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
    fetchLog: {
      totalEntries: fetchLog.length,
      recentErrors: fetchLog.filter(e => e.type === 'error').slice(-5),
    },
  };
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
      description: 'Fetch a .onion URL through this IWA\'s Tor circuit using Direct Sockets SOCKS5. Returns the HTTP response plus TOFU certificate verification status. Fingerprints are auto-captured on first contact and verified on subsequent fetches. Supports optional OHTTP (Oblivious HTTP) encapsulation.',
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
            description: 'Wrap in Oblivious HTTP (OHTTP) for additional privacy',
          },
        },
        required: ['url'],
      },
    },
    fetchOnionWithCertCheck,
  );

  console.log('[WebMCP] Registered 6 production Tor hidden service tools');
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

  console.log('[WebMCP] Unregistered Tor hidden service tools');
}

// ── Expose stores for UI consumption ──
export { onionCertStore, trustedClients, holepunchSessions, fetchLog, getServerStatus };
