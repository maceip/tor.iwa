// ────────────────────────────────────────────
// WebMCP Tool Registration for Tor Hidden Service
// Production implementations: real SOCKS5 holepunch,
// TOFU cert validation, HS auth enforcement, .onion fetch
// ────────────────────────────────────────────

import {
  fetchOnion as rawFetchOnion,
  fetchLog,
  getServerStatus,
  socks5Connect,
  setTrustedClientsRef,
  setCertCaptureCallback,
  getLocalOnionAddress,
  startRelayVolunteer,
  stopRelayVolunteer,
  addRelayPeer,
  removeRelayPeer,
  getRelayPeers,
  getRelayStats,
  isRelayVolunteering,
  setMCPJsonRpcHandler,
  isMCPServerEnabled,
} from './tor-fetch.mjs';

// ── Internal state stores ──
const onionCertStore = new Map();   // .onion -> { fingerprint, firstSeen, lastSeen, hitCount, headers }
const trustedClients = new Map();   // clientId -> { name, pubkey, addedAt, lastSeen, lastAuth, requestCount }
const holepunchSessions = new Map(); // sessionId -> { target, status, connection, createdAt, ... }

// ── Wire trusted clients to the HS handler ──
// This ref is shared with tor-fetch.mjs so the HS can enforce access control
setTrustedClientsRef(trustedClients);

// ── TOFU cert capture callback ──
// Called by fetchOnion in tor-fetch.mjs after every successful fetch
setCertCaptureCallback((hostname, fingerprint, headers) => {
  const existing = onionCertStore.get(hostname);
  if (!existing) {
    // First contact — trust on first use
    onionCertStore.set(hostname, {
      fingerprint,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      hitCount: 1,
      trusted: true,
      headers: {
        server: headers['server'] || null,
        poweredBy: headers['x-powered-by'] || null,
      },
    });
    window.dispatchEvent(new CustomEvent('webmcp:cert-tofu', {
      detail: { hostname, fingerprint, action: 'first-use-stored' },
    }));
  } else {
    existing.hitCount++;
    existing.lastSeen = new Date().toISOString();
    if (existing.fingerprint !== fingerprint) {
      // Fingerprint changed — possible service compromise
      existing.previousFingerprint = existing.fingerprint;
      existing.fingerprint = fingerprint;
      existing.trusted = false;
      existing.mismatchAt = new Date().toISOString();
      window.dispatchEvent(new CustomEvent('webmcp:cert-mismatch', {
        detail: {
          hostname,
          expected: existing.previousFingerprint,
          received: fingerprint,
        },
      }));
    }
    onionCertStore.set(hostname, existing);
  }
});

// ── Holepunch tool ──
// Real implementation: connects via SOCKS5 to target .onion, establishing
// a bidirectional TCP channel over Tor for peer-to-peer communication.
// Supports actions: connect, send, receive, close
async function holepunch({ targetOnion, port, action, sessionId, message, relayHint, timeout }) {
  const act = action || 'connect';

  // ── CONNECT: establish a new SOCKS5 session to target .onion ──
  if (act === 'connect') {
    if (!targetOnion || !targetOnion.endsWith('.onion')) {
      return { success: false, error: 'Invalid target: must be a .onion address' };
    }

    const sid = crypto.randomUUID();
    const targetPort = port || 80;
    const timeoutMs = (timeout || 30) * 1000;
    const session = {
      id: sid,
      target: targetOnion,
      port: targetPort,
      relay: relayHint || null,
      status: 'initiating',
      createdAt: new Date().toISOString(),
      messagesSent: 0,
      messagesReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
    };
    holepunchSessions.set(sid, session);

    try {
      // Real SOCKS5 connection through Tor to the target .onion
      const conn = await Promise.race([
        socks5Connect(targetOnion, targetPort),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Connection timeout')), timeoutMs)
        ),
      ]);

      // Send holepunch handshake identifying this node
      const localAddr = getLocalOnionAddress();
      const handshake = JSON.stringify({
        protocol: 'tor-iwa-holepunch',
        version: 1,
        sessionId: sid,
        from: localAddr || 'unknown',
        relay: relayHint || null,
        ts: new Date().toISOString(),
      }) + '\n';

      const handshakeBytes = new TextEncoder().encode(handshake);
      await conn.writer.write(handshakeBytes);
      session.bytesSent += handshakeBytes.length;

      // Try to read a response (peer may or may not respond with a handshake)
      let responseBuf = new Uint8Array(conn.readBuf || []);
      let peerResponse = null;
      try {
        const readResult = await Promise.race([
          conn.reader.read(),
          new Promise((resolve) =>
            setTimeout(() => resolve({ value: null, done: false }), 5000)
          ),
        ]);
        if (readResult.value) {
          const merged = new Uint8Array(responseBuf.length + readResult.value.length);
          merged.set(responseBuf);
          merged.set(readResult.value, responseBuf.length);
          responseBuf = merged;
          session.bytesReceived += readResult.value.length;
        }
        const responseText = new TextDecoder().decode(responseBuf).trim();
        if (responseText) {
          try { peerResponse = JSON.parse(responseText); } catch (e) {
            peerResponse = { raw: responseText };
          }
          session.messagesReceived++;
        }
      } catch (e) {
        // No response from peer — connection is still valid for sending
      }

      session.status = 'connected';
      session.connectedAt = new Date().toISOString();
      session._connection = conn; // keep live connection (not serialized)
      session.peerResponse = peerResponse;
      holepunchSessions.set(sid, session);

      window.dispatchEvent(new CustomEvent('webmcp:holepunch:connected', {
        detail: { sessionId: sid, target: targetOnion, port: targetPort },
      }));

      return {
        success: true,
        sessionId: sid,
        status: 'connected',
        target: targetOnion,
        port: targetPort,
        peerResponse,
        createdAt: session.createdAt,
        connectedAt: session.connectedAt,
      };
    } catch (e) {
      session.status = 'failed';
      session.error = e.message;
      session.failedAt = new Date().toISOString();
      holepunchSessions.set(sid, session);

      window.dispatchEvent(new CustomEvent('webmcp:holepunch:failed', {
        detail: { sessionId: sid, target: targetOnion, error: e.message },
      }));

      return {
        success: false,
        sessionId: sid,
        status: 'failed',
        target: targetOnion,
        error: e.message,
      };
    }
  }

  // ── SEND: write data to an open holepunch session ──
  if (act === 'send') {
    if (!sessionId) return { success: false, error: 'sessionId is required for send' };
    const session = holepunchSessions.get(sessionId);
    if (!session) return { success: false, error: 'Session not found: ' + sessionId };
    if (session.status !== 'connected' || !session._connection) {
      return { success: false, error: 'Session is not connected (status: ' + session.status + ')' };
    }
    if (!message) return { success: false, error: 'message is required for send' };

    try {
      const payload = (typeof message === 'string' ? message : JSON.stringify(message)) + '\n';
      const payloadBytes = new TextEncoder().encode(payload);
      await session._connection.writer.write(payloadBytes);
      session.messagesSent++;
      session.bytesSent += payloadBytes.length;
      session.lastSentAt = new Date().toISOString();
      holepunchSessions.set(sessionId, session);

      return {
        success: true,
        sessionId,
        action: 'send',
        bytesSent: payloadBytes.length,
        totalMessagesSent: session.messagesSent,
      };
    } catch (e) {
      session.status = 'error';
      session.error = e.message;
      holepunchSessions.set(sessionId, session);
      return { success: false, sessionId, error: 'Send failed: ' + e.message };
    }
  }

  // ── RECEIVE: read data from an open holepunch session ──
  if (act === 'receive') {
    if (!sessionId) return { success: false, error: 'sessionId is required for receive' };
    const session = holepunchSessions.get(sessionId);
    if (!session) return { success: false, error: 'Session not found: ' + sessionId };
    if (session.status !== 'connected' || !session._connection) {
      return { success: false, error: 'Session is not connected (status: ' + session.status + ')' };
    }

    const recvTimeout = (timeout || 10) * 1000;
    try {
      const readResult = await Promise.race([
        session._connection.reader.read(),
        new Promise((resolve) =>
          setTimeout(() => resolve({ value: null, done: true, timedOut: true }), recvTimeout)
        ),
      ]);

      if (readResult.timedOut) {
        return { success: true, sessionId, action: 'receive', data: null, timedOut: true };
      }
      if (readResult.done) {
        session.status = 'closed';
        session.closedAt = new Date().toISOString();
        holepunchSessions.set(sessionId, session);
        return { success: true, sessionId, action: 'receive', data: null, connectionClosed: true };
      }

      const data = new TextDecoder().decode(readResult.value);
      session.messagesReceived++;
      session.bytesReceived += readResult.value.length;
      session.lastReceivedAt = new Date().toISOString();
      holepunchSessions.set(sessionId, session);

      // Try to parse as JSON
      let parsed = null;
      try { parsed = JSON.parse(data.trim()); } catch (e) { /* raw text */ }

      return {
        success: true,
        sessionId,
        action: 'receive',
        data: parsed || data,
        bytesReceived: readResult.value.length,
        totalMessagesReceived: session.messagesReceived,
      };
    } catch (e) {
      return { success: false, sessionId, error: 'Receive failed: ' + e.message };
    }
  }

  // ── CLOSE: tear down a holepunch session ──
  if (act === 'close') {
    if (!sessionId) return { success: false, error: 'sessionId is required for close' };
    const session = holepunchSessions.get(sessionId);
    if (!session) return { success: false, error: 'Session not found: ' + sessionId };

    if (session._connection) {
      try { await session._connection.writer.close(); } catch (e) { /* ignore */ }
      try { await session._connection.socket.close(); } catch (e) { /* ignore */ }
      session._connection = null;
    }
    session.status = 'closed';
    session.closedAt = new Date().toISOString();
    holepunchSessions.set(sessionId, session);

    window.dispatchEvent(new CustomEvent('webmcp:holepunch:closed', {
      detail: { sessionId, target: session.target },
    }));

    return {
      success: true,
      sessionId,
      status: 'closed',
      target: session.target,
      totalMessagesSent: session.messagesSent,
      totalMessagesReceived: session.messagesReceived,
      totalBytesSent: session.bytesSent,
      totalBytesReceived: session.bytesReceived,
    };
  }

  return { success: false, error: 'Unknown action: ' + act + '. Use: connect, send, receive, close' };
}

// ── Validate Onion Cert tool ──
// TOFU-based certificate/fingerprint management for .onion services.
// Fingerprints are auto-captured by fetchOnion (see setCertCaptureCallback above).
// This tool lets agents check, store, list, remove, and verify certs.
async function validateOnionCert({ onionAddress, fingerprint, action }) {
  if (!onionAddress && action !== 'list') {
    return { valid: false, error: 'onionAddress is required (except for action=list)' };
  }
  if (onionAddress && !onionAddress.endsWith('.onion')) {
    return { valid: false, error: 'Invalid .onion address' };
  }

  const act = action || 'check';

  if (act === 'store') {
    if (!fingerprint) {
      return { valid: false, error: 'fingerprint is required for store action' };
    }
    const existing = onionCertStore.get(onionAddress);
    onionCertStore.set(onionAddress, {
      fingerprint,
      firstSeen: existing ? existing.firstSeen : new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      hitCount: existing ? existing.hitCount : 0,
      trusted: true,
      storedBy: 'agent',
      headers: existing ? existing.headers : {},
    });

    window.dispatchEvent(new CustomEvent('webmcp:cert-stored', {
      detail: { onionAddress, fingerprint },
    }));

    return {
      valid: true,
      onionAddress,
      fingerprint,
      action: 'stored',
      previousFingerprint: existing ? existing.fingerprint : null,
    };
  }

  if (act === 'check') {
    const stored = onionCertStore.get(onionAddress);
    if (!stored) {
      return {
        valid: false,
        onionAddress,
        action: 'check',
        error: 'No certificate on record — fetch this .onion first to auto-capture, or store manually',
        knownOnions: Array.from(onionCertStore.keys()),
      };
    }

    if (fingerprint && fingerprint !== stored.fingerprint) {
      return {
        valid: false,
        onionAddress,
        action: 'check',
        error: 'FINGERPRINT MISMATCH — possible MITM or service change',
        expected: stored.fingerprint,
        received: fingerprint,
        firstSeen: stored.firstSeen,
        lastSeen: stored.lastSeen,
        hitCount: stored.hitCount,
        trusted: false,
      };
    }

    return {
      valid: true,
      trusted: stored.trusted,
      onionAddress,
      fingerprint: stored.fingerprint,
      firstSeen: stored.firstSeen,
      lastSeen: stored.lastSeen,
      hitCount: stored.hitCount,
      action: 'check',
    };
  }

  if (act === 'list') {
    const entries = [];
    for (const [addr, cert] of onionCertStore) {
      entries.push({
        onionAddress: addr,
        fingerprint: cert.fingerprint,
        firstSeen: cert.firstSeen,
        lastSeen: cert.lastSeen,
        hitCount: cert.hitCount,
        trusted: cert.trusted,
      });
    }
    return { action: 'list', count: entries.length, certs: entries };
  }

  if (act === 'remove') {
    const existing = onionCertStore.get(onionAddress);
    const removed = onionCertStore.delete(onionAddress);
    window.dispatchEvent(new CustomEvent('webmcp:cert-removed', {
      detail: { onionAddress },
    }));
    return {
      action: 'remove',
      onionAddress,
      removed,
      fingerprint: existing ? existing.fingerprint : null,
    };
  }

  if (act === 'trust') {
    const stored = onionCertStore.get(onionAddress);
    if (!stored) {
      return { valid: false, error: 'No cert on record for this .onion — cannot trust unknown service' };
    }
    stored.trusted = true;
    stored.trustedAt = new Date().toISOString();
    stored.trustedBy = 'agent';
    onionCertStore.set(onionAddress, stored);
    return {
      action: 'trust',
      onionAddress,
      fingerprint: stored.fingerprint,
      trusted: true,
    };
  }

  if (act === 'untrust') {
    const stored = onionCertStore.get(onionAddress);
    if (!stored) {
      return { valid: false, error: 'No cert on record for this .onion' };
    }
    stored.trusted = false;
    onionCertStore.set(onionAddress, stored);
    return {
      action: 'untrust',
      onionAddress,
      fingerprint: stored.fingerprint,
      trusted: false,
    };
  }

  return { valid: false, error: 'Unknown action: ' + act };
}

// ── Manage Trusted Clients tool ──
// Controls which clients can access this hidden service.
// When the trusted list is non-empty, the HS handler (in tor-fetch.mjs)
// rejects requests without a valid X-Client-ID header.
async function manageTrustedClients({ action, clientId, name, pubkey }) {
  const act = action || 'list';

  if (act === 'add') {
    if (!clientId) {
      return { success: false, error: 'clientId is required' };
    }
    const existing = trustedClients.get(clientId);
    const client = {
      clientId,
      name: name || clientId,
      pubkey: pubkey || null,
      addedAt: existing ? existing.addedAt : new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastSeen: existing ? existing.lastSeen : null,
      requestCount: existing ? existing.requestCount : 0,
    };

    // If pubkey provided, compute a verification fingerprint
    if (pubkey) {
      try {
        const keyBuf = await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(pubkey),
        );
        client.pubkeyFingerprint = Array.from(new Uint8Array(keyBuf))
          .map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        client.pubkeyFingerprint = null;
      }
    }

    trustedClients.set(clientId, client);

    window.dispatchEvent(new CustomEvent('webmcp:client-added', {
      detail: { clientId, name: client.name },
    }));

    const totalClients = trustedClients.size;
    return {
      success: true,
      action: 'add',
      client,
      totalTrustedClients: totalClients,
      note: totalClients === 1
        ? 'Access control is now ACTIVE — only trusted clients can reach the hidden service'
        : null,
    };
  }

  if (act === 'remove') {
    if (!clientId) {
      return { success: false, error: 'clientId is required' };
    }
    const client = trustedClients.get(clientId);
    const removed = trustedClients.delete(clientId);

    window.dispatchEvent(new CustomEvent('webmcp:client-removed', {
      detail: { clientId },
    }));

    const totalClients = trustedClients.size;
    return {
      success: removed,
      action: 'remove',
      clientId,
      removedName: client ? client.name : null,
      totalTrustedClients: totalClients,
      note: totalClients === 0
        ? 'Access control is now DISABLED — all clients can reach the hidden service'
        : null,
    };
  }

  if (act === 'list') {
    const clients = [];
    for (const [, client] of trustedClients) {
      clients.push({
        clientId: client.clientId,
        name: client.name,
        pubkey: client.pubkey ? '***' + client.pubkey.slice(-8) : null,
        pubkeyFingerprint: client.pubkeyFingerprint || null,
        addedAt: client.addedAt,
        lastSeen: client.lastSeen,
        requestCount: client.requestCount || 0,
      });
    }
    return {
      action: 'list',
      count: clients.length,
      accessControlActive: clients.length > 0,
      clients,
    };
  }

  if (act === 'verify') {
    if (!clientId) {
      return { success: false, error: 'clientId is required' };
    }
    const client = trustedClients.get(clientId);
    if (!client) {
      return {
        trusted: false,
        clientId,
        error: 'Client not in trust store',
        totalTrustedClients: trustedClients.size,
      };
    }
    client.lastSeen = new Date().toISOString();
    trustedClients.set(clientId, client);
    return {
      trusted: true,
      clientId,
      name: client.name,
      pubkeyFingerprint: client.pubkeyFingerprint || null,
      lastSeen: client.lastSeen,
      addedAt: client.addedAt,
    };
  }

  if (act === 'clear') {
    const count = trustedClients.size;
    trustedClients.clear();
    window.dispatchEvent(new CustomEvent('webmcp:clients-cleared', { detail: {} }));
    return {
      success: true,
      action: 'clear',
      removedCount: count,
      note: 'Access control is now DISABLED — all clients can reach the hidden service',
    };
  }

  return { success: false, error: 'Unknown action: ' + act + '. Use: add, remove, list, verify, clear' };
}

// ── List holepunch sessions ──
async function listHolepunchSessions() {
  const sessions = [];
  for (const [, session] of holepunchSessions) {
    sessions.push({
      id: session.id,
      target: session.target,
      port: session.port,
      status: session.status,
      createdAt: session.createdAt,
      connectedAt: session.connectedAt || null,
      closedAt: session.closedAt || null,
      messagesSent: session.messagesSent || 0,
      messagesReceived: session.messagesReceived || 0,
      bytesSent: session.bytesSent || 0,
      bytesReceived: session.bytesReceived || 0,
      error: session.error || null,
    });
  }
  const active = sessions.filter(s => s.status === 'connected').length;
  return { count: sessions.length, active, sessions };
}

// ── Get hidden service status ──
// Aggregates real data from the HS listener, cert store, trusted clients, and sessions
async function getServiceStatus() {
  const hs = getServerStatus();
  const localAddr = getLocalOnionAddress();

  const activeSessions = [];
  for (const [, s] of holepunchSessions) {
    if (s.status === 'connected') activeSessions.push(s.target);
  }

  return {
    hiddenService: {
      running: hs.running,
      onionAddress: localAddr || null,
      uptimeMs: hs.uptimeMs,
      requestCount: hs.requestCount,
      bytesServed: hs.bytesServed,
      activeConnections: hs.connections,
      recentConnections: hs.recentConnections,
    },
    security: {
      accessControlActive: trustedClients.size > 0,
      trustedClientCount: trustedClients.size,
      knownCertCount: onionCertStore.size,
      untrustedCerts: Array.from(onionCertStore.values()).filter(c => !c.trusted).length,
    },
    network: {
      activeHolepunchSessions: activeSessions.length,
      holepunchTargets: activeSessions,
      totalSessions: holepunchSessions.size,
    },
    ohttpRelay: {
      volunteering: isRelayVolunteering(),
      peerCount: getRelayPeers().size,
      ...getRelayStats(),
    },
    fetchLog: {
      totalEntries: fetchLog.length,
      recentErrors: fetchLog.filter(e => e.type === 'error').slice(-5),
    },
  };
}

// ── OHTTP Relay Management tool ──
// Lets agents volunteer this instance as a relay, add/remove peers, check status
async function manageOHTTPRelay({ action, peerOnion, peerPubkey }) {
  const act = action || 'status';

  if (act === 'volunteer') {
    const result = await startRelayVolunteer();
    const localAddr = getLocalOnionAddress();
    window.dispatchEvent(new CustomEvent('webmcp:relay-started', {
      detail: { pubkey: result.pubkey, onion: localAddr },
    }));
    return {
      success: true,
      action: 'volunteer',
      volunteering: true,
      pubkey: result.pubkey,
      localOnion: localAddr,
      note: 'This instance is now accepting OHTTP relay requests at /.well-known/ohttp-relay. Share your .onion address and pubkey with peers.',
    };
  }

  if (act === 'stop') {
    await stopRelayVolunteer();
    window.dispatchEvent(new CustomEvent('webmcp:relay-stopped', { detail: {} }));
    return { success: true, action: 'stop', volunteering: false };
  }

  if (act === 'addPeer') {
    if (!peerOnion || !peerOnion.endsWith('.onion')) {
      return { success: false, error: 'peerOnion must be a valid .onion address' };
    }
    if (!peerPubkey) {
      return { success: false, error: 'peerPubkey (base64 ECDH public key) is required' };
    }
    addRelayPeer(peerOnion, peerPubkey);
    window.dispatchEvent(new CustomEvent('webmcp:relay-peer-added', {
      detail: { peerOnion, peerPubkey: peerPubkey.slice(0, 16) + '...' },
    }));
    return {
      success: true,
      action: 'addPeer',
      peerOnion,
      totalPeers: getRelayPeers().size,
      note: 'Peer added. fetchOnion with useOHTTP=true will now route through available peers.',
    };
  }

  if (act === 'removePeer') {
    if (!peerOnion) return { success: false, error: 'peerOnion is required' };
    const removed = removeRelayPeer(peerOnion);
    window.dispatchEvent(new CustomEvent('webmcp:relay-peer-removed', {
      detail: { peerOnion },
    }));
    return { success: removed, action: 'removePeer', peerOnion, totalPeers: getRelayPeers().size };
  }

  if (act === 'listPeers') {
    const peers = [];
    for (const [addr, peer] of getRelayPeers()) {
      peers.push({
        onion: addr,
        pubkey: peer.pubkey ? peer.pubkey.slice(0, 16) + '...' : null,
        addedAt: peer.addedAt,
        lastSeen: peer.lastSeen,
        relayCount: peer.relayCount,
        available: peer.available,
      });
    }
    return { action: 'listPeers', count: peers.length, peers };
  }

  if (act === 'status') {
    const stats = getRelayStats();
    const peers = [];
    for (const [addr, peer] of getRelayPeers()) {
      peers.push({ onion: addr.slice(0, 16) + '...', relayCount: peer.relayCount });
    }
    return {
      action: 'status',
      volunteering: stats.volunteering,
      peerCount: stats.peerCount,
      requestsRelayed: stats.requestsRelayed,
      bytesRelayed: stats.bytesRelayed,
      lastRelayedAt: stats.lastRelayedAt,
      peers,
      note: stats.peerCount === 0
        ? 'No peers available. fetchOnion with useOHTTP=true will use circuit isolation (SOCKS5 auth-based circuit separation) as fallback.'
        : 'Peer relay active. fetchOnion with useOHTTP=true will route through a random available peer.',
    };
  }

  return { success: false, error: 'Unknown action: ' + act + '. Use: volunteer, stop, addPeer, removePeer, listPeers, status' };
}

// ── Enhanced fetchOnion wrapper ──
// Wraps the raw fetchOnion from tor-fetch.mjs to add cert verification status
async function fetchOnionWithCertCheck(params) {
  const result = await rawFetchOnion(params);
  if (!result.success) return result;

  // Add TOFU verification status
  let parsed;
  try {
    const normalized = params.url.startsWith('http') ? params.url : 'http://' + params.url;
    parsed = new URL(normalized);
  } catch (e) {
    return result;
  }

  const hostname = parsed.hostname;
  const certEntry = onionCertStore.get(hostname);

  result.certVerification = certEntry ? {
    known: true,
    trusted: certEntry.trusted,
    fingerprint: certEntry.fingerprint,
    firstSeen: certEntry.firstSeen,
    hitCount: certEntry.hitCount,
    mismatch: certEntry.previousFingerprint ? true : false,
  } : {
    known: false,
    note: 'First contact — fingerprint auto-stored via TOFU',
  };

  return result;
}

// ── Registration tracking ──
let _coreToolsRegistered = false;

export function registerWebMCPTools() {
  if (!navigator.modelContext) {
    console.log('[WebMCP] navigator.modelContext not available');
    return false;
  }

  if (_coreToolsRegistered) return true;
  _coreToolsRegistered = true;

  // Tool 1: holepunch — real SOCKS5 peer connections over Tor
  navigator.modelContext.registerTool(
    'holepunch',
    {
      description: 'Establish direct peer-to-peer connections to other .onion hidden services through Tor using SOCKS5 Direct Sockets. Supports actions: "connect" (open a new session), "send" (write data), "receive" (read data), "close" (tear down session). Enables AI-to-AI anonymous communication.',
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['connect', 'send', 'receive', 'close'],
            description: 'Action to perform (default: "connect")',
          },
          targetOnion: {
            type: 'string',
            description: 'The target .onion address to connect to (required for "connect")',
          },
          port: {
            type: 'number',
            description: 'Target port (default: 80)',
          },
          sessionId: {
            type: 'string',
            description: 'Session ID for send/receive/close actions',
          },
          message: {
            type: 'string',
            description: 'Message to send (for "send" action)',
          },
          relayHint: {
            type: 'string',
            description: 'Optional relay node hint for optimizing the connection path',
          },
          timeout: {
            type: 'number',
            description: 'Timeout in seconds (default: 30 for connect, 10 for receive)',
          },
        },
        required: [],
      },
    },
    holepunch,
  );

  // Tool 2: validateOnionCert — TOFU cert management with auto-capture
  navigator.modelContext.registerTool(
    'validateOnionCert',
    {
      description: 'Trust-on-first-use (TOFU) certificate management for .onion services. Fingerprints are auto-captured when using fetchOnion. Actions: "check" (verify a cert), "store" (manually save), "list" (show all), "remove" (delete), "trust"/"untrust" (set trust status). Detects service identity changes that may indicate compromise.',
      parameters: {
        type: 'object',
        properties: {
          onionAddress: {
            type: 'string',
            description: 'The .onion address (required except for action=list)',
          },
          fingerprint: {
            type: 'string',
            description: 'SHA-256 fingerprint to store or verify against',
          },
          action: {
            type: 'string',
            enum: ['check', 'store', 'list', 'remove', 'trust', 'untrust'],
            description: 'Action to perform (default: "check")',
          },
        },
        required: [],
      },
    },
    validateOnionCert,
  );

  // Tool 3: manageTrustedClients — HS access control with real enforcement
  navigator.modelContext.registerTool(
    'manageTrustedClients',
    {
      description: 'Control access to this Tor hidden service. When trusted clients exist, the HS rejects requests without a valid X-Client-ID header. Actions: "add" (authorize a client), "remove" (revoke), "list" (show all), "verify" (check trust), "clear" (disable access control). Adding the first client activates enforcement; removing the last deactivates it.',
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['add', 'remove', 'list', 'verify', 'clear'],
            description: 'Action to perform (default: "list")',
          },
          clientId: {
            type: 'string',
            description: 'Unique client identifier (required for add/remove/verify)',
          },
          name: {
            type: 'string',
            description: 'Human-readable name (optional, for "add")',
          },
          pubkey: {
            type: 'string',
            description: 'Client public key for cryptographic verification (optional, for "add")',
          },
        },
        required: ['action'],
      },
    },
    manageTrustedClients,
  );

  // Tool 4: listHolepunchSessions
  navigator.modelContext.registerTool(
    'listHolepunchSessions',
    {
      description: 'List all holepunch sessions with connection status, message/byte counts, and timestamps. Shows active peer-to-peer connections over Tor.',
      parameters: {
        type: 'object',
        properties: {},
      },
    },
    listHolepunchSessions,
  );

  // Tool 5: getServiceStatus — real aggregated data
  navigator.modelContext.registerTool(
    'getServiceStatus',
    {
      description: 'Get comprehensive status of this Tor hidden service: HS uptime/stats, access control state, cert store health, active holepunch sessions, and recent fetch errors.',
      parameters: {
        type: 'object',
        properties: {},
      },
    },
    getServiceStatus,
  );

  // Tool 6: fetchOnion — with TOFU cert verification
  navigator.modelContext.registerTool(
    'fetchOnion',
    {
      description: 'Fetch a .onion URL through Tor. When useOHTTP=true, routes through a peer OHTTP relay (another tor.iwa instance) for application-layer unlinkability. If no peers are available, automatically falls back to Tor circuit isolation (unique SOCKS5 credentials force a separate circuit). Returns HTTP response + TOFU cert verification + OHTTP mode used.',
      parameters: {
        type: 'object',
        properties: {
          url: {
            type: 'string',
            description: 'The .onion URL to fetch (e.g. "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")',
          },
          method: {
            type: 'string',
            enum: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'],
            description: 'HTTP method (default: GET)',
          },
          headers: {
            type: 'object',
            description: 'Additional HTTP headers to send',
          },
          body: {
            type: 'string',
            description: 'Request body (for POST/PUT)',
          },
          useOHTTP: {
            type: 'boolean',
            description: 'Enable OHTTP privacy: peer relay (default) or circuit isolation (fallback)',
          },
          relayOnion: {
            type: 'string',
            description: 'Specific peer .onion to use as OHTTP relay (optional, random peer chosen if omitted)',
          },
        },
        required: ['url'],
      },
    },
    fetchOnionWithCertCheck,
  );

  // Tool 7: manageOHTTPRelay — OHTTP relay volunteering and peer management
  navigator.modelContext.registerTool(
    'manageOHTTPRelay',
    {
      description: 'Manage OHTTP relay infrastructure. "volunteer" makes this instance accept relay requests from peers. "addPeer" registers another tor.iwa instance as an available relay. "status" shows relay stats and peer list. When peers are available, fetchOnion with useOHTTP=true routes through them for real application-layer privacy.',
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['volunteer', 'stop', 'addPeer', 'removePeer', 'listPeers', 'status'],
            description: 'Action to perform (default: "status")',
          },
          peerOnion: {
            type: 'string',
            description: 'Peer .onion address (for addPeer/removePeer)',
          },
          peerPubkey: {
            type: 'string',
            description: 'Peer ECDH public key in base64 (for addPeer)',
          },
        },
        required: [],
      },
    },
    manageOHTTPRelay,
  );

  console.log('[WebMCP] Registered 7 Tor hidden service tools (incl. OHTTP relay)');
  return true;
}

export function unregisterWebMCPTools() {
  if (!navigator.modelContext || !_coreToolsRegistered) return;
  _coreToolsRegistered = false;

  navigator.modelContext.unregisterTool('holepunch');
  navigator.modelContext.unregisterTool('validateOnionCert');
  navigator.modelContext.unregisterTool('manageTrustedClients');
  navigator.modelContext.unregisterTool('listHolepunchSessions');
  navigator.modelContext.unregisterTool('getServiceStatus');
  navigator.modelContext.unregisterTool('fetchOnion');
  navigator.modelContext.unregisterTool('manageOHTTPRelay');

  console.log('[WebMCP] Unregistered Tor hidden service tools');
}

// ────────────────────────────────────────────
// Path 2: MCP JSON-RPC Server over Hidden Service
// Serves standard MCP protocol at /.well-known/mcp on the .onion address.
// Any MCP client on Tor can discover and call tools via JSON-RPC.
// ────────────────────────────────────────────

// Tool dispatch table — maps tool names to handler functions
const _toolHandlers = {
  holepunch,
  validateOnionCert,
  manageTrustedClients,
  listHolepunchSessions,
  getServiceStatus,
  fetchOnion: fetchOnionWithCertCheck,
  manageOHTTPRelay,
};

// JSON-RPC handler called by the HS request handler in tor-fetch.mjs
async function mcpJsonRpcHandler(bodyText) {
  let req;
  try {
    req = JSON.parse(bodyText);
  } catch (e) {
    return JSON.stringify({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: 'Parse error' },
    });
  }

  const { method, params, id } = req;

  // tools/list — return all available tools
  if (method === 'tools/list') {
    const tools = [
      { name: 'holepunch', description: 'Peer-to-peer connections to .onion services via SOCKS5 Direct Sockets' },
      { name: 'validateOnionCert', description: 'TOFU certificate management for .onion services' },
      { name: 'manageTrustedClients', description: 'Access control for this hidden service' },
      { name: 'listHolepunchSessions', description: 'List all holepunch sessions' },
      { name: 'getServiceStatus', description: 'Comprehensive hidden service status' },
      { name: 'fetchOnion', description: 'Fetch .onion URLs through Tor with OHTTP privacy' },
      { name: 'manageOHTTPRelay', description: 'OHTTP relay volunteering and peer management' },
    ];
    return JSON.stringify({ jsonrpc: '2.0', id, result: { tools } });
  }

  // tools/call — execute a tool
  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};
    const handler = _toolHandlers[toolName];
    if (!handler) {
      return JSON.stringify({
        jsonrpc: '2.0', id,
        error: { code: -32601, message: 'Unknown tool: ' + toolName },
      });
    }
    try {
      const result = await handler(toolArgs);
      return JSON.stringify({ jsonrpc: '2.0', id, result });
    } catch (e) {
      return JSON.stringify({
        jsonrpc: '2.0', id,
        error: { code: -32000, message: e.message },
      });
    }
  }

  return JSON.stringify({
    jsonrpc: '2.0', id,
    error: { code: -32601, message: 'Unknown method: ' + method },
  });
}

let _mcpServerActive = false;

export function enableMCPServer() {
  setMCPJsonRpcHandler(mcpJsonRpcHandler);
  _mcpServerActive = true;
  window.dispatchEvent(new CustomEvent('webmcp:mcp-server-started', { detail: {} }));
  console.log('[MCP Server] JSON-RPC endpoint active at /.well-known/mcp');
  return true;
}

export function disableMCPServer() {
  setMCPJsonRpcHandler(null);
  _mcpServerActive = false;
  window.dispatchEvent(new CustomEvent('webmcp:mcp-server-stopped', { detail: {} }));
  console.log('[MCP Server] JSON-RPC endpoint disabled');
  return true;
}

export function isMCPServerActive() { return _mcpServerActive; }

// ────────────────────────────────────────────
// Path 3: BroadcastChannel / postMessage Bridge
// Attempts cross-origin communication between the IWA and
// extensions or other pages. BroadcastChannel is same-origin only
// so this uses a window.postMessage listener as fallback for
// any window that can get a reference to the IWA window.
// ────────────────────────────────────────────

let _bridgeChannel = null;
let _bridgeActive = false;
let _bridgeStats = { messagesReceived: 0, toolCallsHandled: 0, lastMessageAt: null };

function handleBridgeMessage(data, reply) {
  _bridgeStats.messagesReceived++;
  _bridgeStats.lastMessageAt = new Date().toISOString();

  // Tool discovery
  if (data.type === 'mcp:tools/list') {
    const tools = Object.keys(_toolHandlers);
    reply({ type: 'mcp:tools/list:result', tools, source: 'tor-iwa' });
    return;
  }

  // Tool call
  if (data.type === 'mcp:tools/call') {
    const handler = _toolHandlers[data.name];
    if (!handler) {
      reply({ type: 'mcp:tools/call:error', name: data.name, error: 'Unknown tool' });
      return;
    }
    _bridgeStats.toolCallsHandled++;
    handler(data.arguments || {}).then(result => {
      reply({ type: 'mcp:tools/call:result', name: data.name, id: data.id, result });
    }).catch(e => {
      reply({ type: 'mcp:tools/call:error', name: data.name, id: data.id, error: e.message });
    });
    return;
  }

  // Ping/discovery
  if (data.type === 'mcp:ping') {
    reply({
      type: 'mcp:pong',
      source: 'tor-iwa',
      tools: Object.keys(_toolHandlers).length,
      onion: getLocalOnionAddress() || null,
    });
    return;
  }
}

export function enableBridge() {
  if (_bridgeActive) return true;

  // BroadcastChannel — same-origin only, works if another IWA page needs to communicate
  try {
    _bridgeChannel = new BroadcastChannel('tor-iwa-mcp');
    _bridgeChannel.onmessage = (e) => {
      handleBridgeMessage(e.data, (resp) => _bridgeChannel.postMessage(resp));
    };
  } catch (e) {
    // BroadcastChannel not available
  }

  // window.postMessage — cross-origin capable if caller has a window reference
  // Extensions with access to chrome.scripting.executeScript could potentially
  // use window.postMessage, or a popup/tab could use window.open + postMessage
  window.addEventListener('message', _postMessageListener);

  _bridgeActive = true;
  _bridgeStats = { messagesReceived: 0, toolCallsHandled: 0, lastMessageAt: null };
  window.dispatchEvent(new CustomEvent('webmcp:bridge-started', { detail: {} }));
  console.log('[MCP Bridge] BroadcastChannel + postMessage bridge active');
  return true;
}

function _postMessageListener(e) {
  // Accept messages with the mcp: prefix from any origin
  if (!e.data || typeof e.data.type !== 'string' || !e.data.type.startsWith('mcp:')) return;
  handleBridgeMessage(e.data, (resp) => {
    if (e.source) {
      e.source.postMessage(resp, e.origin === 'null' ? '*' : e.origin);
    }
  });
}

export function disableBridge() {
  if (_bridgeChannel) {
    _bridgeChannel.close();
    _bridgeChannel = null;
  }
  window.removeEventListener('message', _postMessageListener);
  _bridgeActive = false;
  window.dispatchEvent(new CustomEvent('webmcp:bridge-stopped', { detail: {} }));
  console.log('[MCP Bridge] Bridge disabled');
  return true;
}

export function isBridgeActive() { return _bridgeActive; }
export function getBridgeStats() { return { ..._bridgeStats, active: _bridgeActive }; }

// ── Expose stores for UI consumption ──
export { onionCertStore, trustedClients, holepunchSessions, fetchLog, getServerStatus };
export { getRelayPeers, getRelayStats, isRelayVolunteering } from './tor-fetch.mjs';
export { isMCPServerEnabled } from './tor-fetch.mjs';
