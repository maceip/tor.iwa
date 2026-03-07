// ────────────────────────────────────────────
// WebMCP Tool Registration for Tor Hidden Service
// Exposes holepunch, cert validation, trusted client
// management, and .onion fetch proxy to AI agents
// via navigator.modelContext
// ────────────────────────────────────────────

import { fetchOnion, fetchLog, getServerStatus } from './tor-fetch.mjs';

// ── Internal state stores ──
const onionCertStore = new Map();   // .onion -> { fingerprint, lastSeen, valid }
const trustedClients = new Map();   // clientId -> { name, pubkey, addedAt, lastSeen }
const holepunchSessions = new Map(); // sessionId -> { target, status, createdAt }

// ── Event dispatch helper (mirrors react-flightsearch pattern) ──
let _requestId = 0;
function dispatchAndWait(eventName, detail, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const reqId = ++_requestId;
    const fullDetail = { ...detail, _reqId: reqId };

    const handler = (e) => {
      if (e.detail && e.detail._reqId === reqId) {
        window.removeEventListener(eventName + ':done', handler);
        resolve(e.detail.result);
      }
    };
    window.removeEventListener(eventName + ':done', handler);
    window.addEventListener(eventName + ':done', handler);

    window.dispatchEvent(new CustomEvent(eventName, { detail: fullDetail }));

    setTimeout(() => {
      window.removeEventListener(eventName + ':done', handler);
      resolve({ status: 'timeout' });
    }, timeout);
  });
}

// ── Holepunch tool ──
// Initiates a NAT holepunch connection to a target .onion address
// so a remote client can reach this hidden service through a relay
async function holepunch({ targetOnion, relayHint, timeout }) {
  if (!targetOnion || !targetOnion.endsWith('.onion')) {
    return { success: false, error: 'Invalid target: must be a .onion address' };
  }

  const sessionId = crypto.randomUUID();
  const session = {
    id: sessionId,
    target: targetOnion,
    relay: relayHint || null,
    status: 'initiating',
    createdAt: new Date().toISOString(),
  };
  holepunchSessions.set(sessionId, session);

  const result = await dispatchAndWait('webmcp:holepunch', {
    sessionId,
    targetOnion,
    relayHint: relayHint || null,
    timeout: timeout || 30,
  });

  if (result && result.status !== 'timeout') {
    session.status = result.status || 'connected';
    holepunchSessions.set(sessionId, session);
  } else {
    session.status = 'timeout';
    holepunchSessions.set(sessionId, session);
  }

  return {
    success: session.status === 'connected',
    sessionId,
    status: session.status,
    target: targetOnion,
    createdAt: session.createdAt,
  };
}

// ── Validate Onion Cert tool ──
// Validates/stores the TLS certificate fingerprint for a .onion address
// this server has previously connected to
async function validateOnionCert({ onionAddress, fingerprint, action }) {
  if (!onionAddress || !onionAddress.endsWith('.onion')) {
    return { valid: false, error: 'Invalid .onion address' };
  }

  const act = action || 'check';

  if (act === 'store') {
    if (!fingerprint) {
      return { valid: false, error: 'Fingerprint required for store action' };
    }
    onionCertStore.set(onionAddress, {
      fingerprint,
      lastSeen: new Date().toISOString(),
      valid: true,
      storedBy: 'webmcp',
    });

    await dispatchAndWait('webmcp:cert-stored', { onionAddress, fingerprint });

    return {
      valid: true,
      onionAddress,
      fingerprint,
      action: 'stored',
      lastSeen: new Date().toISOString(),
    };
  }

  if (act === 'check') {
    const stored = onionCertStore.get(onionAddress);
    if (!stored) {
      return {
        valid: false,
        onionAddress,
        action: 'check',
        error: 'No certificate on record for this .onion',
        knownOnions: Array.from(onionCertStore.keys()),
      };
    }

    if (fingerprint && fingerprint !== stored.fingerprint) {
      return {
        valid: false,
        onionAddress,
        action: 'check',
        error: 'Certificate fingerprint mismatch — possible MITM',
        expected: stored.fingerprint,
        received: fingerprint,
        lastSeen: stored.lastSeen,
      };
    }

    return {
      valid: true,
      onionAddress,
      fingerprint: stored.fingerprint,
      lastSeen: stored.lastSeen,
      action: 'check',
    };
  }

  if (act === 'list') {
    const entries = [];
    for (const [addr, cert] of onionCertStore) {
      entries.push({ onionAddress: addr, fingerprint: cert.fingerprint, lastSeen: cert.lastSeen, valid: cert.valid });
    }
    return { action: 'list', count: entries.length, certs: entries };
  }

  if (act === 'remove') {
    const removed = onionCertStore.delete(onionAddress);
    await dispatchAndWait('webmcp:cert-removed', { onionAddress });
    return { action: 'remove', onionAddress, removed };
  }

  return { valid: false, error: 'Unknown action: ' + act };
}

// ── Manage Trusted Clients tool ──
// Add, remove, or list clients this hidden service trusts
async function manageTrustedClients({ action, clientId, name, pubkey }) {
  const act = action || 'list';

  if (act === 'add') {
    if (!clientId) {
      return { success: false, error: 'clientId is required' };
    }
    const client = {
      clientId,
      name: name || clientId,
      pubkey: pubkey || null,
      addedAt: new Date().toISOString(),
      lastSeen: null,
    };
    trustedClients.set(clientId, client);

    await dispatchAndWait('webmcp:client-added', { clientId, name: client.name });

    return { success: true, action: 'add', client };
  }

  if (act === 'remove') {
    if (!clientId) {
      return { success: false, error: 'clientId is required' };
    }
    const removed = trustedClients.delete(clientId);

    await dispatchAndWait('webmcp:client-removed', { clientId });

    return { success: removed, action: 'remove', clientId };
  }

  if (act === 'list') {
    const clients = [];
    for (const [, client] of trustedClients) {
      clients.push(client);
    }
    return { action: 'list', count: clients.length, clients };
  }

  if (act === 'verify') {
    if (!clientId) {
      return { success: false, error: 'clientId is required' };
    }
    const client = trustedClients.get(clientId);
    if (!client) {
      return { trusted: false, clientId, error: 'Client not found in trust store' };
    }
    client.lastSeen = new Date().toISOString();
    trustedClients.set(clientId, client);
    return { trusted: true, clientId, name: client.name, lastSeen: client.lastSeen };
  }

  return { success: false, error: 'Unknown action: ' + act };
}

// ── List active holepunch sessions ──
async function listHolepunchSessions() {
  const sessions = [];
  for (const [, session] of holepunchSessions) {
    sessions.push(session);
  }
  return { count: sessions.length, sessions };
}

// ── Get hidden service status ──
async function getServiceStatus() {
  return await dispatchAndWait('webmcp:get-status', {});
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

  // Tool 1: holepunch
  navigator.modelContext.registerTool(
    'holepunch',
    {
      description: 'Initiate a NAT holepunch to establish a direct connection to a target .onion hidden service through the Tor network. Use this to help a remote client reach this server.',
      parameters: {
        type: 'object',
        properties: {
          targetOnion: {
            type: 'string',
            description: 'The target .onion address to holepunch to (e.g. "abc123...xyz.onion")',
          },
          relayHint: {
            type: 'string',
            description: 'Optional relay node hint for optimizing the connection path',
          },
          timeout: {
            type: 'number',
            description: 'Connection timeout in seconds (default: 30)',
          },
        },
        required: ['targetOnion'],
      },
    },
    holepunch,
  );

  // Tool 2: validateOnionCert
  navigator.modelContext.registerTool(
    'validateOnionCert',
    {
      description: 'Validate, store, list, or remove TLS certificate fingerprints for .onion addresses this server has seen. Helps detect MITM attacks and verify the identity of other hidden services.',
      parameters: {
        type: 'object',
        properties: {
          onionAddress: {
            type: 'string',
            description: 'The .onion address to check/store a cert for',
          },
          fingerprint: {
            type: 'string',
            description: 'SHA-256 fingerprint of the TLS certificate (hex string)',
          },
          action: {
            type: 'string',
            enum: ['check', 'store', 'list', 'remove'],
            description: 'Action to perform: "check" verifies a cert, "store" saves a new cert, "list" shows all stored certs, "remove" deletes a cert entry',
          },
        },
        required: ['onionAddress'],
      },
    },
    validateOnionCert,
  );

  // Tool 3: manageTrustedClients
  navigator.modelContext.registerTool(
    'manageTrustedClients',
    {
      description: 'Manage the list of clients trusted by this Tor hidden service. Add, remove, list, or verify client identities. Trusted clients get preferential access to the hidden service.',
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['add', 'remove', 'list', 'verify'],
            description: 'Action: "add" a new trusted client, "remove" one, "list" all, or "verify" a client\'s trust status',
          },
          clientId: {
            type: 'string',
            description: 'Unique identifier for the client (required for add/remove/verify)',
          },
          name: {
            type: 'string',
            description: 'Human-readable name for the client (optional, used with "add")',
          },
          pubkey: {
            type: 'string',
            description: 'Client\'s public key for cryptographic verification (optional, used with "add")',
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
      description: 'List all active and past holepunch sessions initiated by this hidden service. Shows connection status, targets, and timestamps.',
      parameters: {
        type: 'object',
        properties: {},
      },
    },
    listHolepunchSessions,
  );

  // Tool 5: getServiceStatus
  navigator.modelContext.registerTool(
    'getServiceStatus',
    {
      description: 'Get the current status of this Tor hidden service including .onion address, uptime, connection state, number of trusted clients, and known onion certificates.',
      parameters: {
        type: 'object',
        properties: {},
      },
    },
    getServiceStatus,
  );

  // Tool 6: fetchOnion — proxy fetch .onion sites through this IWA's Tor circuit
  navigator.modelContext.registerTool(
    'fetchOnion',
    {
      description: 'Fetch a .onion URL through this hidden service\'s Tor circuit using Direct Sockets SOCKS5. Pass a .onion URL and get back the HTTP response. Supports optional OHTTP (Oblivious HTTP) encapsulation for additional privacy — the request is wrapped in an encrypted BHTTP envelope before traversing the Tor circuit.',
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
            description: 'Wrap the request in Oblivious HTTP (OHTTP) encapsulation for additional privacy. The request is encrypted in a BHTTP envelope using HPKE before being sent through Tor.',
          },
        },
        required: ['url'],
      },
    },
    fetchOnion,
  );

  console.log('[WebMCP] Registered 6 Tor hidden service tools');
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
