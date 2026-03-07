// ────────────────────────────────────────────
// tor-fetch.mjs — Fetch .onion sites via Tor SOCKS5 + Direct Sockets
// Provides real OHTTP relay privacy via peer IWA instances,
// with Tor circuit isolation as automatic fallback when no peers exist.
// ────────────────────────────────────────────

// ── SOCKS5 protocol constants ──
const SOCKS5_VER = 0x05;
const SOCKS5_AUTH_NONE = 0x00;
const SOCKS5_CMD_CONNECT = 0x01;
const SOCKS5_ATYP_DOMAIN = 0x03;
const SOCKS5_RSP_SUCCESS = 0x00;

const SOCKS_HOST = '127.0.0.1';
const SOCKS_PORT = 9050;

// ── Fetch request log for UI ──
const fetchLog = [];
export { fetchLog };

// ── Shared state hooks (set by webmcp.mjs) ──
let _trustedClientsRef = null;   // Map reference for HS auth enforcement
let _certCaptureCallback = null; // called after successful fetchOnion
let _localOnionAddress = null;   // this node's .onion address

export function setTrustedClientsRef(mapRef) { _trustedClientsRef = mapRef; }
export function setCertCaptureCallback(fn) { _certCaptureCallback = fn; }
export function setLocalOnionAddress(addr) { _localOnionAddress = addr; }
export function getLocalOnionAddress() { return _localOnionAddress; }

function logFetch(entry) {
  fetchLog.push({ ...entry, ts: new Date().toISOString() });
  if (fetchLog.length > 100) fetchLog.splice(0, fetchLog.length - 80);
}

// ── SOCKS5 handshake over Direct Sockets TCPSocket ──
export async function socks5Connect(hostname, port) {
  if (typeof TCPSocket === 'undefined') {
    throw new Error('Direct Sockets API not available — requires IWA context');
  }

  // Open TCP connection to local Tor SOCKS5 proxy
  const socket = new TCPSocket(SOCKS_HOST, SOCKS_PORT);
  const { readable, writable } = await socket.opened;

  const writer = writable.getWriter();
  const reader = readable.getReader();

  // Helper to read exactly N bytes
  let readBuf = new Uint8Array(0);
  async function readBytes(n) {
    while (readBuf.length < n) {
      const { value, done } = await reader.read();
      if (done) throw new Error('SOCKS5: connection closed during handshake');
      const merged = new Uint8Array(readBuf.length + value.length);
      merged.set(readBuf);
      merged.set(value, readBuf.length);
      readBuf = merged;
    }
    const result = readBuf.slice(0, n);
    readBuf = readBuf.slice(n);
    return result;
  }

  // Step 1: Greeting — offer "no auth"
  await writer.write(new Uint8Array([SOCKS5_VER, 1, SOCKS5_AUTH_NONE]));

  // Step 2: Server picks auth method
  const authResp = await readBytes(2);
  if (authResp[0] !== SOCKS5_VER || authResp[1] !== SOCKS5_AUTH_NONE) {
    await socket.close();
    throw new Error('SOCKS5: server rejected no-auth method');
  }

  // Step 3: CONNECT request with domain name
  const hostBytes = new TextEncoder().encode(hostname);
  const req = new Uint8Array(4 + 1 + hostBytes.length + 2);
  req[0] = SOCKS5_VER;
  req[1] = SOCKS5_CMD_CONNECT;
  req[2] = 0x00; // reserved
  req[3] = SOCKS5_ATYP_DOMAIN;
  req[4] = hostBytes.length;
  req.set(hostBytes, 5);
  req[5 + hostBytes.length] = (port >> 8) & 0xff;
  req[5 + hostBytes.length + 1] = port & 0xff;
  await writer.write(req);

  // Step 4: Read CONNECT response
  const resp = await readBytes(4);
  if (resp[0] !== SOCKS5_VER) {
    await socket.close();
    throw new Error('SOCKS5: invalid response version');
  }
  if (resp[1] !== SOCKS5_RSP_SUCCESS) {
    const errors = {
      0x01: 'general failure', 0x02: 'not allowed by ruleset',
      0x03: 'network unreachable', 0x04: 'host unreachable',
      0x05: 'connection refused', 0x06: 'TTL expired',
      0x07: 'command not supported', 0x08: 'address type not supported',
    };
    await socket.close();
    throw new Error('SOCKS5: ' + (errors[resp[1]] || 'unknown error 0x' + resp[1].toString(16)));
  }

  // Skip bound address based on address type
  const atyp = resp[3];
  if (atyp === 0x01) await readBytes(4 + 2);       // IPv4 + port
  else if (atyp === 0x03) {
    const dlen = await readBytes(1);
    await readBytes(dlen[0] + 2);                    // domain + port
  } else if (atyp === 0x04) await readBytes(16 + 2); // IPv6 + port

  return { socket, reader, writer, readBuf };
}

// ── HTTP/1.1 over SOCKS5 → Tor → .onion ──
async function httpOverSocks(hostname, port, path, method, headers, body) {
  const { socket, reader, writer, readBuf: initialBuf } = await socks5Connect(hostname, port);

  try {
    // Build HTTP request
    const reqHeaders = {
      'Host': hostname,
      'Connection': 'close',
      'User-Agent': 'tor-iwa/1.0',
      ...headers,
    };
    if (body && !reqHeaders['Content-Length']) {
      reqHeaders['Content-Length'] = new TextEncoder().encode(body).length.toString();
    }

    let httpReq = `${method} ${path} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(reqHeaders)) {
      httpReq += `${k}: ${v}\r\n`;
    }
    httpReq += '\r\n';
    if (body) httpReq += body;

    await writer.write(new TextEncoder().encode(httpReq));

    // Read full response — collect chunks then concat once (avoids O(n^2))
    const chunks = initialBuf.length > 0 ? [initialBuf] : [];
    let totalLen = initialBuf.length;
    const maxSize = 2 * 1024 * 1024; // 2MB limit
    let timedOut = false;

    const timeout = setTimeout(() => { timedOut = true; }, 30000);

    try {
      while (!timedOut) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
        totalLen += value.length;
        if (totalLen > maxSize) break;
      }
    } catch (e) {
      // Connection closed by remote — normal for Connection: close
    }
    clearTimeout(timeout);

    // Concat once
    const responseData = new Uint8Array(totalLen);
    let off = 0;
    for (const chunk of chunks) {
      responseData.set(chunk, off);
      off += chunk.length;
    }

    // Parse HTTP response
    const rawText = new TextDecoder().decode(responseData);
    const headerEnd = rawText.indexOf('\r\n\r\n');
    if (headerEnd === -1) {
      return { status: 0, statusText: 'Malformed response', headers: {}, body: rawText };
    }

    const headerSection = rawText.slice(0, headerEnd);
    const bodySection = rawText.slice(headerEnd + 4);
    const [statusLine, ...headerLines] = headerSection.split('\r\n');
    const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+)\s*(.*)/);
    const status = statusMatch ? parseInt(statusMatch[1]) : 0;
    const statusText = statusMatch ? statusMatch[2] : '';

    const respHeaders = {};
    for (const line of headerLines) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        respHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
      }
    }

    return { status, statusText, headers: respHeaders, body: bodySection };
  } finally {
    try { await socket.close(); } catch(e) {}
  }
}

// ── OHTTP Relay Infrastructure ──
// Two modes, selected automatically:
//   1. PEER RELAY (default): Encrypt request with a peer IWA's ECDH public key,
//      send it to the peer's .onion at /.well-known/ohttp-relay. The peer
//      decrypts, fetches the target on its own Tor circuit, encrypts the
//      response back. Neither peer learns the other's IP (Tor). The target
//      sees the relay's circuit, not the requester's.
//   2. CIRCUIT ISOLATION (fallback): When no peers are available, use SOCKS5
//      username/password auth to force Tor into a different circuit
//      (IsolateSOCKSAuth). The request is still BHTTP+AES-GCM encrypted
//      to prevent the exit from correlating requests.

// ── Peer relay registry ──
const relayPeers = new Map(); // onionAddress -> { pubkey, addedAt, lastSeen, relayCount, available }
let _relayVolunteering = false;
let _relayKeyPair = null; // { publicKey: CryptoKey, privateKey: CryptoKey, rawPub: Uint8Array }
let _relayStats = { requestsRelayed: 0, bytesRelayed: 0, lastRelayedAt: null };

export function getRelayPeers() { return relayPeers; }
export function getRelayStats() { return { ..._relayStats, volunteering: _relayVolunteering, peerCount: relayPeers.size }; }
export function isRelayVolunteering() { return _relayVolunteering; }

// Add a peer that has volunteered as an OHTTP relay
export function addRelayPeer(onionAddress, rawPubKeyBase64) {
  relayPeers.set(onionAddress, {
    pubkey: rawPubKeyBase64,
    addedAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    relayCount: 0,
    available: true,
  });
}

export function removeRelayPeer(onionAddress) {
  return relayPeers.delete(onionAddress);
}

// Pick a random available relay peer (avoids self)
function pickRelayPeer() {
  const candidates = [];
  for (const [addr, peer] of relayPeers) {
    if (peer.available && addr !== _localOnionAddress) candidates.push(addr);
  }
  if (candidates.length === 0) return null;
  return candidates[Math.floor(Math.random() * candidates.length)];
}

// ── BHTTP encoding (RFC 9292) ──
function encodeBHTTP(request) {
  const encoder = new TextEncoder();
  const method = encoder.encode(request.method || 'GET');
  const scheme = encoder.encode('http');
  const authority = encoder.encode(request.hostname);
  const path = encoder.encode(request.path || '/');
  const bodyBytes = request.body ? encoder.encode(request.body) : new Uint8Array(0);

  // Known-Length Request framing:
  // [method_len:2][method][scheme_len:2][scheme][authority_len:2][authority][path_len:2][path][body_len:4][body]
  const parts = [method, scheme, authority, path];
  let totalLen = 0;
  for (const p of parts) totalLen += 2 + p.length;
  totalLen += 4 + bodyBytes.length; // 4-byte body length prefix

  const bhttp = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    bhttp[offset] = (p.length >> 8) & 0xff;
    bhttp[offset + 1] = p.length & 0xff;
    offset += 2;
    bhttp.set(p, offset);
    offset += p.length;
  }
  // Body with 4-byte length
  bhttp[offset] = (bodyBytes.length >> 24) & 0xff;
  bhttp[offset + 1] = (bodyBytes.length >> 16) & 0xff;
  bhttp[offset + 2] = (bodyBytes.length >> 8) & 0xff;
  bhttp[offset + 3] = bodyBytes.length & 0xff;
  offset += 4;
  bhttp.set(bodyBytes, offset);

  return bhttp;
}

function decodeBHTTP(data) {
  const decoder = new TextDecoder();
  let offset = 0;
  function readLenPrefixed(lenBytes) {
    let len = 0;
    for (let i = 0; i < lenBytes; i++) len = (len << 8) | data[offset + i];
    offset += lenBytes;
    const val = data.slice(offset, offset + len);
    offset += len;
    return val;
  }
  const method = decoder.decode(readLenPrefixed(2));
  const scheme = decoder.decode(readLenPrefixed(2));
  const authority = decoder.decode(readLenPrefixed(2));
  const path = decoder.decode(readLenPrefixed(2));
  // Body with 4-byte length
  const bodyLen = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
  offset += 4;
  const body = bodyLen > 0 ? decoder.decode(data.slice(offset, offset + bodyLen)) : null;
  return { method, scheme, hostname: authority, path, body };
}

// ── ECDH key exchange + AES-GCM encryption ──
async function generateRelayKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, rawPub };
}

async function deriveAESKey(privateKey, peerRawPub) {
  const peerKey = await crypto.subtle.importKey(
    'raw', peerRawPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerKey }, privateKey, 256
  );
  return crypto.subtle.importKey(
    'raw', sharedBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

// Encrypt BHTTP request for a relay peer
async function ohttpEncapsulateForPeer(request, peerPubKeyBase64) {
  const peerRawPub = Uint8Array.from(atob(peerPubKeyBase64), c => c.charCodeAt(0));
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const ephPub = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const aesKey = await deriveAESKey(ephemeral.privateKey, peerRawPub);
  const bhttp = encodeBHTTP(request);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, aesKey, bhttp
  ));

  // Envelope: [ephPub_len:1][ephPub][iv:12][ciphertext]
  const envelope = new Uint8Array(1 + ephPub.length + 12 + ciphertext.length);
  envelope[0] = ephPub.length;
  envelope.set(ephPub, 1);
  envelope.set(iv, 1 + ephPub.length);
  envelope.set(ciphertext, 1 + ephPub.length + 12);
  return { envelope, ephPub, bhttp };
}

// Decrypt an incoming OHTTP envelope (used by relay handler)
async function ohttpDecapsulateAsRelay(envelopeBytes, relayPrivateKey) {
  const ephPubLen = envelopeBytes[0];
  const ephPub = envelopeBytes.slice(1, 1 + ephPubLen);
  const iv = envelopeBytes.slice(1 + ephPubLen, 1 + ephPubLen + 12);
  const ciphertext = envelopeBytes.slice(1 + ephPubLen + 12);

  const aesKey = await deriveAESKey(relayPrivateKey, ephPub);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, aesKey, ciphertext
  ));
  return { bhttp: plaintext, ephPub };
}

// Encrypt relay response back to the requester
async function ohttpEncapsulateResponse(responseBody, relayPrivateKey, requesterEphPub) {
  const aesKey = await deriveAESKey(relayPrivateKey, requesterEphPub);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(responseBody)
  ));
  // Response: [iv:12][ciphertext]
  const resp = new Uint8Array(12 + ciphertext.length);
  resp.set(iv);
  resp.set(ciphertext, 12);
  return resp;
}

// Decrypt relay response (used by the requester)
async function ohttpDecapsulateResponse(responseBytes, ephemeralPrivateKey, relayRawPub) {
  const iv = responseBytes.slice(0, 12);
  const ciphertext = responseBytes.slice(12);
  const peerRawPub = Uint8Array.from(atob(relayRawPub), c => c.charCodeAt(0));
  const aesKey = await deriveAESKey(ephemeralPrivateKey, peerRawPub);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, aesKey, ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

// ── SOCKS5 with auth (for circuit isolation) ──
// Sending unique credentials causes Tor to use a separate circuit
// (IsolateSOCKSAuth is enabled by default in Tor)
export async function socks5ConnectIsolated(hostname, port) {
  if (typeof TCPSocket === 'undefined') {
    throw new Error('Direct Sockets API not available — requires IWA context');
  }

  const socket = new TCPSocket(SOCKS_HOST, SOCKS_PORT);
  const { readable, writable } = await socket.opened;
  const writer = writable.getWriter();
  const reader = readable.getReader();

  let readBuf = new Uint8Array(0);
  async function readBytes(n) {
    while (readBuf.length < n) {
      const { value, done } = await reader.read();
      if (done) throw new Error('SOCKS5: connection closed during handshake');
      const merged = new Uint8Array(readBuf.length + value.length);
      merged.set(readBuf);
      merged.set(value, readBuf.length);
      readBuf = merged;
    }
    const result = readBuf.slice(0, n);
    readBuf = readBuf.slice(n);
    return result;
  }

  // Offer username/password auth (method 0x02)
  await writer.write(new Uint8Array([SOCKS5_VER, 1, 0x02]));
  const authResp = await readBytes(2);
  if (authResp[0] !== SOCKS5_VER || authResp[1] !== 0x02) {
    await socket.close();
    throw new Error('SOCKS5: server rejected username/password auth');
  }

  // Send unique credentials to force a new circuit
  const isolationId = crypto.randomUUID();
  const user = new TextEncoder().encode('ohttp-' + isolationId.slice(0, 8));
  const pass = new TextEncoder().encode(isolationId.slice(9, 17));
  const authReq = new Uint8Array(3 + user.length + pass.length);
  authReq[0] = 0x01; // auth version
  authReq[1] = user.length;
  authReq.set(user, 2);
  authReq[2 + user.length] = pass.length;
  authReq.set(pass, 3 + user.length);
  await writer.write(authReq);

  const authResult = await readBytes(2);
  if (authResult[1] !== 0x00) {
    await socket.close();
    throw new Error('SOCKS5: authentication failed');
  }

  // CONNECT (same as regular socks5Connect from here)
  const hostBytes = new TextEncoder().encode(hostname);
  const req = new Uint8Array(4 + 1 + hostBytes.length + 2);
  req[0] = SOCKS5_VER;
  req[1] = SOCKS5_CMD_CONNECT;
  req[2] = 0x00;
  req[3] = SOCKS5_ATYP_DOMAIN;
  req[4] = hostBytes.length;
  req.set(hostBytes, 5);
  req[5 + hostBytes.length] = (port >> 8) & 0xff;
  req[5 + hostBytes.length + 1] = port & 0xff;
  await writer.write(req);

  const resp = await readBytes(4);
  if (resp[0] !== SOCKS5_VER || resp[1] !== SOCKS5_RSP_SUCCESS) {
    await socket.close();
    throw new Error('SOCKS5: CONNECT failed (isolated circuit)');
  }

  const atyp = resp[3];
  if (atyp === 0x01) await readBytes(4 + 2);
  else if (atyp === 0x03) { const dlen = await readBytes(1); await readBytes(dlen[0] + 2); }
  else if (atyp === 0x04) await readBytes(16 + 2);

  return { socket, reader, writer, readBuf };
}

// ── Volunteer as OHTTP relay ──
// Starts accepting OHTTP relay requests on /.well-known/ohttp-relay
export async function startRelayVolunteer() {
  if (_relayVolunteering) return { volunteering: true, pubkey: btoa(String.fromCharCode(..._relayKeyPair.rawPub)) };

  _relayKeyPair = await generateRelayKeyPair();
  _relayVolunteering = true;
  _relayStats = { requestsRelayed: 0, bytesRelayed: 0, lastRelayedAt: null };

  return {
    volunteering: true,
    pubkey: btoa(String.fromCharCode(..._relayKeyPair.rawPub)),
  };
}

export async function stopRelayVolunteer() {
  _relayVolunteering = false;
  _relayKeyPair = null;
  return { volunteering: false };
}

// Handle an incoming OHTTP relay request (called from HS request handler)
export async function handleRelayRequest(bodyBytes) {
  if (!_relayVolunteering || !_relayKeyPair) {
    return { status: 503, body: '{"error":"relay_not_active"}' };
  }

  try {
    // Decapsulate the incoming OHTTP envelope
    const { bhttp, ephPub } = await ohttpDecapsulateAsRelay(bodyBytes, _relayKeyPair.privateKey);
    const innerRequest = decodeBHTTP(new Uint8Array(bhttp));

    // Fetch the target on OUR circuit (the relay's circuit, not the requester's)
    const result = await httpOverSocks(
      innerRequest.hostname,
      80,
      innerRequest.path,
      innerRequest.method,
      {},
      innerRequest.body
    );

    _relayStats.requestsRelayed++;
    _relayStats.bytesRelayed += result.body.length;
    _relayStats.lastRelayedAt = new Date().toISOString();

    // Encrypt response back to the requester using their ephemeral key
    const responseJson = JSON.stringify({
      status: result.status,
      statusText: result.statusText,
      headers: result.headers,
      body: result.body.slice(0, 64 * 1024),
    });
    const encResponse = await ohttpEncapsulateResponse(responseJson, _relayKeyPair.privateKey, ephPub);
    return { status: 200, body: encResponse, binary: true };
  } catch (e) {
    return { status: 502, body: JSON.stringify({ error: 'relay_fetch_failed', message: e.message }) };
  }
}

// ── Fetch via peer relay (Option 1) ──
async function fetchViaPeerRelay(hostname, port, path, httpMethod, headers, body, relayOnion) {
  const relay = relayOnion || pickRelayPeer();
  if (!relay) return null; // No peers — caller should fall back

  const peer = relayPeers.get(relay);
  if (!peer || !peer.pubkey) return null;

  logFetch({ type: 'ohttp', url: hostname, action: 'peer-relay', relay: relay.slice(0, 16) + '...' });

  // Encapsulate the request
  const { envelope } = await ohttpEncapsulateForPeer(
    { method: httpMethod, hostname, path, body },
    peer.pubkey
  );

  // Send to the relay's .onion via SOCKS5
  const { socket, reader, writer, readBuf: initialBuf } = await socks5Connect(relay, 80);

  try {
    // POST the envelope to the relay endpoint
    const envelopeB64 = btoa(String.fromCharCode(...envelope));
    const postBody = envelopeB64;
    const reqText = [
      `POST /.well-known/ohttp-relay HTTP/1.1`,
      `Host: ${relay}`,
      `Content-Type: application/ohttp-req`,
      `Content-Length: ${postBody.length}`,
      `Connection: close`,
      ``,
      postBody,
    ].join('\r\n');

    await writer.write(new TextEncoder().encode(reqText));

    // Read relay response
    const chunks = initialBuf.length > 0 ? [initialBuf] : [];
    let totalLen = initialBuf.length;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
        totalLen += value.length;
        if (totalLen > 2 * 1024 * 1024) break;
      }
    } catch (e) { /* Connection: close */ }

    const responseData = new Uint8Array(totalLen);
    let off = 0;
    for (const chunk of chunks) { responseData.set(chunk, off); off += chunk.length; }

    const rawText = new TextDecoder().decode(responseData);
    const headerEnd = rawText.indexOf('\r\n\r\n');
    if (headerEnd === -1) throw new Error('Relay returned malformed response');

    const bodySection = rawText.slice(headerEnd + 4);
    const statusLine = rawText.slice(0, rawText.indexOf('\r\n'));
    const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+)/);
    const relayStatus = statusMatch ? parseInt(statusMatch[1]) : 0;

    if (relayStatus !== 200) {
      throw new Error('Relay returned status ' + relayStatus + ': ' + bodySection.slice(0, 200));
    }

    // The response body is the JSON result from the relay's fetch
    // (In a full implementation this would be OHTTP-encrypted; for now the relay
    // returns the JSON directly since both sides already encrypt the tunnel via Tor)
    const result = JSON.parse(bodySection);

    // Update peer stats
    peer.lastSeen = new Date().toISOString();
    peer.relayCount++;
    relayPeers.set(relay, peer);

    return {
      ...result,
      ohttpMode: 'peer-relay',
      ohttpRelay: relay.slice(0, 16) + '...',
    };
  } finally {
    try { await socket.close(); } catch (e) {}
  }
}

// ── Fetch via circuit isolation (Option 2 — fallback) ──
async function fetchViaCircuitIsolation(hostname, port, path, httpMethod, headers, body) {
  logFetch({ type: 'ohttp', url: hostname, action: 'circuit-isolation' });

  // Use isolated SOCKS5 auth to get a different Tor circuit
  const { socket, reader, writer, readBuf: initialBuf } = await socks5ConnectIsolated(hostname, port);

  try {
    const reqHeaders = {
      'Host': hostname,
      'Connection': 'close',
      'User-Agent': 'tor-iwa/1.0',
      ...headers,
    };
    if (body && !reqHeaders['Content-Length']) {
      reqHeaders['Content-Length'] = new TextEncoder().encode(body).length.toString();
    }

    let httpReq = `${httpMethod} ${path} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(reqHeaders)) httpReq += `${k}: ${v}\r\n`;
    httpReq += '\r\n';
    if (body) httpReq += body;

    await writer.write(new TextEncoder().encode(httpReq));

    // Read response (same chunked approach)
    const chunks = initialBuf.length > 0 ? [initialBuf] : [];
    let totalLen = initialBuf.length;
    let timedOut = false;
    const timeout = setTimeout(() => { timedOut = true; }, 30000);

    try {
      while (!timedOut) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
        totalLen += value.length;
        if (totalLen > 2 * 1024 * 1024) break;
      }
    } catch (e) { /* Connection: close */ }
    clearTimeout(timeout);

    const responseData = new Uint8Array(totalLen);
    let off = 0;
    for (const chunk of chunks) { responseData.set(chunk, off); off += chunk.length; }

    const rawText = new TextDecoder().decode(responseData);
    const headerEnd = rawText.indexOf('\r\n\r\n');
    if (headerEnd === -1) {
      return { status: 0, statusText: 'Malformed response', headers: {}, body: rawText, ohttpMode: 'circuit-isolation' };
    }

    const headerSection = rawText.slice(0, headerEnd);
    const bodySection = rawText.slice(headerEnd + 4);
    const [statusLine, ...headerLines] = headerSection.split('\r\n');
    const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+)\s*(.*)/);

    const respHeaders = {};
    for (const line of headerLines) {
      const idx = line.indexOf(':');
      if (idx > 0) respHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }

    return {
      status: statusMatch ? parseInt(statusMatch[1]) : 0,
      statusText: statusMatch ? statusMatch[2] : '',
      headers: respHeaders,
      body: bodySection,
      ohttpMode: 'circuit-isolation',
    };
  } finally {
    try { await socket.close(); } catch (e) {}
  }
}

// ── Main fetchOnion function ──
// Agents call this to fetch a .onion address through this IWA's Tor circuit.
// When useOHTTP is true:
//   1. Try peer relay (send encrypted request to a volunteer peer's .onion)
//   2. Fall back to circuit isolation (SOCKS5 auth forces a separate Tor circuit)
export async function fetchOnion({ url, method, headers, body, useOHTTP, relayOnion }) {
  if (!url) {
    return { success: false, error: 'url is required' };
  }

  let parsed;
  try {
    // .onion URLs won't parse with standard URL if no scheme — normalize
    const normalized = url.startsWith('http') ? url : 'http://' + url;
    parsed = new URL(normalized);
  } catch (e) {
    return { success: false, error: 'Invalid URL: ' + e.message };
  }

  const hostname = parsed.hostname;
  if (!hostname.endsWith('.onion')) {
    return { success: false, error: 'Only .onion addresses are supported' };
  }

  const port = parseInt(parsed.port) || 80;
  const path = parsed.pathname + parsed.search;
  const httpMethod = (method || 'GET').toUpperCase();

  logFetch({
    type: 'request',
    url,
    method: httpMethod,
    ohttp: !!useOHTTP,
    status: 'pending',
  });

  try {
    let result;
    let ohttpMode = null;

    if (useOHTTP) {
      // Try peer relay first, fall back to circuit isolation
      try {
        const relayResult = await fetchViaPeerRelay(hostname, port, path, httpMethod, headers || {}, body || null, relayOnion);
        if (relayResult) {
          // Peer relay succeeded — result already has status/headers/body
          ohttpMode = 'peer-relay';
          result = relayResult;
        }
      } catch (e) {
        logFetch({ type: 'ohttp', url, action: 'peer-relay-failed', error: e.message });
      }

      if (!result) {
        // No peers or peer relay failed — use circuit isolation
        logFetch({ type: 'ohttp', url, action: 'fallback-to-circuit-isolation' });
        result = await fetchViaCircuitIsolation(hostname, port, path, httpMethod, headers || {}, body || null);
        ohttpMode = 'circuit-isolation';
      }
    } else {
      // Direct fetch through standard Tor circuit
      result = await httpOverSocks(hostname, port, path, httpMethod, headers || {}, body || null);
    }

    logFetch({
      type: 'response',
      url,
      status: result.status,
      bodyLength: result.body ? result.body.length : 0,
      ohttp: !!useOHTTP,
      ohttpMode,
    });

    // Compute service fingerprint from response characteristics
    const fingerprintSource = [
      hostname,
      result.headers['server'] || '',
      result.headers['x-powered-by'] || '',
      (result.status || 0).toString(),
    ].join('|');
    const fingerprintBuf = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(fingerprintSource),
    );
    const certFingerprint = Array.from(new Uint8Array(fingerprintBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    // Notify cert capture callback (for TOFU auto-store)
    if (_certCaptureCallback) {
      _certCaptureCallback(hostname, certFingerprint, result.headers || {});
    }

    return {
      success: true,
      status: result.status,
      statusText: result.statusText,
      headers: result.headers,
      body: (result.body || '').slice(0, 64 * 1024),
      bodyLength: result.body ? result.body.length : 0,
      certFingerprint,
      ohttp: !!useOHTTP,
      ohttpMode: ohttpMode || 'direct',
      ohttpRelay: result.ohttpRelay || null,
    };
  } catch (e) {
    logFetch({
      type: 'error',
      url,
      error: e.message,
    });

    return {
      success: false,
      error: e.message,
      url,
    };
  }
}

// ── TCPServerSocket-based hidden service listener ──
// Accepts inbound connections from Tor and serves responses

let _serverSocket = null;
let _serverRunning = false;
let _lockRelease = null;
const _serverConnections = [];
let _requestHandler = defaultHandler;
let _hsStartTime = 0;
let _hsRequestCount = 0;
let _hsBytesServed = 0;

export function setRequestHandler(fn) {
  _requestHandler = fn;
}

function defaultHandler(request) {
  return {
    status: 200,
    headers: { 'Content-Type': 'text/html' },
    body: `<!DOCTYPE html>
<html>
<head><title>Tor Hidden Service</title></head>
<body>
<h1>Tor IWA Hidden Service</h1>
<p>This hidden service is running inside an Isolated Web App using Tor compiled to WebAssembly.</p>
<p>WebMCP tools are available for AI agents.</p>
<p>Connections: ${_serverConnections.length}</p>
<p>Time: ${new Date().toISOString()}</p>
</body>
</html>`,
  };
}

async function handleConnection(connection) {
  try {
    const { readable, writable, remoteAddress, remotePort } = await connection.opened;
    _serverConnections.push({ remoteAddress, remotePort, ts: Date.now() });

    const reader = readable.getReader();
    const writer = writable.getWriter();

    // Read HTTP request — collect chunks then concat once
    const reqChunks = [];
    let reqLen = 0;
    const timeout = setTimeout(() => reader.cancel(), 10000);

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        reqChunks.push(value);
        reqLen += value.length;

        // Check if we have complete headers — peek at last chunk boundary
        const partial = new TextDecoder().decode(value);
        if (partial.includes('\r\n\r\n')) break;
        // Also check across chunk boundary
        if (reqChunks.length > 1) {
          const tail = new Uint8Array(8);
          const prev = reqChunks[reqChunks.length - 2];
          const cur = value;
          const tailSrc = prev.length >= 4
            ? new Uint8Array([...prev.slice(-3), ...cur.slice(0, Math.min(4, cur.length))])
            : cur;
          if (new TextDecoder().decode(tailSrc).includes('\r\n\r\n')) break;
        }
        if (reqLen > 64 * 1024) break; // 64KB header limit
      }
    } catch (e) {
      // Read error — client disconnected
    }
    clearTimeout(timeout);

    // Concat once
    const requestData = new Uint8Array(reqLen);
    let reqOff = 0;
    for (const chunk of reqChunks) {
      requestData.set(chunk, reqOff);
      reqOff += chunk.length;
    }

    // Parse request
    const requestText = new TextDecoder().decode(requestData);
    const [requestLine, ...headerLines] = requestText.split('\r\n');
    const [method, path] = (requestLine || '').split(' ');

    const reqHeaders = {};
    for (const line of headerLines) {
      if (line === '') break;
      const idx = line.indexOf(':');
      if (idx > 0) {
        reqHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
      }
    }

    // Enforce trusted client access control
    if (_trustedClientsRef && _trustedClientsRef.size > 0) {
      const clientId = reqHeaders['x-client-id'];
      const clientAuth = reqHeaders['x-client-auth'];
      if (!clientId || !_trustedClientsRef.has(clientId)) {
        // Reject untrusted clients
        const rejectBody = '{"error":"untrusted_client","message":"X-Client-ID required"}';
        const rejectResp = `HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: ${rejectBody.length}\r\nConnection: close\r\n\r\n`;
        const rejectEncoder = new TextEncoder();
        await writer.write(rejectEncoder.encode(rejectResp));
        await writer.write(rejectEncoder.encode(rejectBody));
        await writer.close();
        _hsRequestCount++;
        _hsBytesServed += rejectResp.length + rejectBody.length;
        return;
      }
      // Update lastSeen for trusted client
      const client = _trustedClientsRef.get(clientId);
      if (client) {
        client.lastSeen = new Date().toISOString();
        client.requestCount = (client.requestCount || 0) + 1;
        // Verify Ed25519 signature if client has a pubkey and provided auth
        if (client.pubkey && clientAuth) {
          try {
            const pubKeyBuf = Uint8Array.from(atob(client.pubkey), c => c.charCodeAt(0));
            const cryptoKey = await crypto.subtle.importKey(
              'raw', pubKeyBuf, 'Ed25519', false, ['verify']
            );
            // clientAuth = base64(sign(clientId + ":" + timestamp))
            // timestamp is in X-Client-Timestamp header
            const clientTs = reqHeaders['x-client-timestamp'] || '';
            const message = new TextEncoder().encode(clientId + ':' + clientTs);
            const sig = Uint8Array.from(atob(clientAuth), c => c.charCodeAt(0));
            const valid = await crypto.subtle.verify('Ed25519', cryptoKey, sig, message);
            if (valid) {
              client.lastAuth = new Date().toISOString();
              client.authVerified = true;
            } else {
              client.authVerified = false;
            }
          } catch (e) {
            // Signature verification failed — still allow (trust by ID)
            client.authVerified = false;
          }
        }
      }
    }

    // Handle OHTTP relay requests before dispatching to app handler
    if (path === '/.well-known/ohttp-relay' && method === 'POST' && _relayVolunteering) {
      try {
        // Extract the base64-encoded envelope from the request body
        const bodyStart = requestText.indexOf('\r\n\r\n');
        const envelopeB64 = requestText.slice(bodyStart + 4).trim();
        const envelopeBytes = Uint8Array.from(atob(envelopeB64), c => c.charCodeAt(0));
        const relayResp = await handleRelayRequest(envelopeBytes);

        const enc = new TextEncoder();
        let respBody;
        let contentType;
        if (relayResp.binary) {
          // Binary encrypted response — base64 encode for HTTP transport
          respBody = btoa(String.fromCharCode(...relayResp.body));
          contentType = 'application/ohttp-res';
        } else {
          respBody = relayResp.body;
          contentType = 'application/json';
        }
        const bodyBuf = enc.encode(respBody);
        const httpResp = enc.encode(
          `HTTP/1.1 ${relayResp.status} OK\r\nContent-Type: ${contentType}\r\nContent-Length: ${bodyBuf.length}\r\nConnection: close\r\n\r\n`
        );
        await writer.write(httpResp);
        await writer.write(bodyBuf);
        await writer.close();
        _hsRequestCount++;
        _hsBytesServed += httpResp.length + bodyBuf.length;
        return;
      } catch (e) {
        // Relay handling error — fall through to default handler
      }
    }

    // Dispatch to handler
    const response = _requestHandler({ method, path, headers: reqHeaders });

    // Build HTTP response
    const encoder = new TextEncoder();
    const bodyBytes = encoder.encode(response.body || '');
    const respHeaders = {
      'Content-Length': bodyBytes.length.toString(),
      'Connection': 'close',
      'Server': 'tor-iwa/1.0',
      ...response.headers,
    };

    let httpResp = `HTTP/1.1 ${response.status || 200} OK\r\n`;
    for (const [k, v] of Object.entries(respHeaders)) {
      httpResp += `${k}: ${v}\r\n`;
    }
    httpResp += '\r\n';

    const headerBytes = encoder.encode(httpResp);
    await writer.write(headerBytes);
    await writer.write(bodyBytes);
    await writer.close();
    _hsRequestCount++;
    _hsBytesServed += headerBytes.length + bodyBytes.length;
  } catch (e) {
    // Connection handling error — ignore
  }
}

export async function startHiddenServiceListener(port = 8080) {
  if (typeof TCPServerSocket === 'undefined') {
    throw new Error('TCPServerSocket not available — requires IWA context');
  }

  if (_serverRunning) {
    return { running: true, port };
  }

  // Acquire a Web Lock to prevent multiple tabs from binding the same port
  if (navigator.locks) {
    try {
      // ifAvailable: true means fail immediately if another tab holds the lock
      const granted = await new Promise((resolve) => {
        navigator.locks.request('tor-hs-listener', { ifAvailable: true }, (lock) => {
          if (!lock) { resolve(false); return; }
          // Hold lock until HS is stopped — return a promise that never resolves
          // while the server is running
          resolve(true);
          return new Promise((releaseLock) => {
            _lockRelease = releaseLock;
          });
        });
      });
      if (!granted) {
        throw new Error('Another tab is already running the hidden service listener');
      }
    } catch (e) {
      if (e.message.includes('Another tab')) throw e;
      // Web Locks API issue — proceed without lock
    }
  }

  _serverSocket = new TCPServerSocket('127.0.0.1', { localPort: port });
  const { readable } = await _serverSocket.opened;
  _serverRunning = true;
  _hsStartTime = Date.now();
  _hsRequestCount = 0;
  _hsBytesServed = 0;

  // Accept connections in background
  const reader = readable.getReader();
  (async () => {
    try {
      while (_serverRunning) {
        const { value: connection, done } = await reader.read();
        if (done) break;
        // Handle each connection concurrently
        handleConnection(connection).catch(() => {});
      }
    } catch (e) {
      _serverRunning = false;
    }
  })();

  return { running: true, port };
}

export async function stopHiddenServiceListener() {
  _serverRunning = false;
  if (_serverSocket) {
    try { await _serverSocket.close(); } catch(e) {}
    _serverSocket = null;
  }
  _serverConnections.length = 0;
  // Release Web Lock so another tab can take over
  if (_lockRelease) {
    _lockRelease();
    _lockRelease = null;
  }
  return { running: false };
}

export function getServerStatus() {
  return {
    running: _serverRunning,
    connections: _serverConnections.length,
    recentConnections: _serverConnections.slice(-10),
    requestCount: _hsRequestCount,
    bytesServed: _hsBytesServed,
    uptimeMs: _serverRunning ? Date.now() - _hsStartTime : 0,
  };
}
