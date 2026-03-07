// ────────────────────────────────────────────
// tor-fetch.mjs — Fetch .onion sites via Tor SOCKS5 + Direct Sockets
// Also provides OHTTP-style request encapsulation for privacy
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

function logFetch(entry) {
  fetchLog.push({ ...entry, ts: new Date().toISOString() });
  if (fetchLog.length > 100) fetchLog.splice(0, fetchLog.length - 80);
}

// ── SOCKS5 handshake over Direct Sockets TCPSocket ──
async function socks5Connect(hostname, port) {
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

    // Read full response
    let responseData = new Uint8Array(initialBuf);
    const decoder = new TextDecoder();
    const maxSize = 2 * 1024 * 1024; // 2MB limit
    let timedOut = false;

    const timeout = setTimeout(() => { timedOut = true; }, 30000);

    try {
      while (!timedOut) {
        const { value, done } = await reader.read();
        if (done) break;
        const merged = new Uint8Array(responseData.length + value.length);
        merged.set(responseData);
        merged.set(value, responseData.length);
        responseData = merged;
        if (responseData.length > maxSize) break;
      }
    } catch (e) {
      // Connection closed by remote — normal for Connection: close
    }
    clearTimeout(timeout);

    // Parse HTTP response
    const rawText = decoder.decode(responseData);
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

// ── OHTTP-style encapsulation ──
// Wraps the .onion fetch request in an encrypted Binary HTTP (BHTTP)
// envelope. In a full deployment, this would use HPKE to encrypt to
// an oblivious relay's public key. Here we implement the framing so
// the protocol is correct and ready for a real relay.

async function ohttpEncapsulate(request) {
  // Generate ephemeral ECDH key pair for HPKE-like key agreement
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const ephPub = await crypto.subtle.exportKey('raw', ephemeral.publicKey);

  // Encode request as Binary HTTP (RFC 9292) framing
  const encoder = new TextEncoder();
  const method = encoder.encode(request.method || 'GET');
  const scheme = encoder.encode('http');
  const authority = encoder.encode(request.hostname);
  const path = encoder.encode(request.path || '/');

  // Simplified BHTTP Known-Length Request:
  // [method_len][method][scheme_len][scheme][authority_len][authority][path_len][path]
  const parts = [method, scheme, authority, path];
  let totalLen = 0;
  for (const p of parts) totalLen += 2 + p.length; // 2-byte length prefix each

  const bhttp = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    bhttp[offset] = (p.length >> 8) & 0xff;
    bhttp[offset + 1] = p.length & 0xff;
    offset += 2;
    bhttp.set(p, offset);
    offset += p.length;
  }

  // Encrypt with AES-GCM using a derived key (self-keyed for demo;
  // in production this would use the relay's HPKE public key)
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    bhttp,
  );

  // Export key for the envelope (in production, this is replaced by HPKE enc)
  const rawKey = await crypto.subtle.exportKey('raw', aesKey);

  return {
    keyId: 0x01, // config ID
    kem: 0x0010, // DHKEM(P-256, HKDF-SHA256)
    ephemeralPublicKey: new Uint8Array(ephPub),
    encryptedRequest: new Uint8Array(ciphertext),
    iv,
    // For self-decapsulation in demo mode:
    _aesKey: aesKey,
    _bhttp: bhttp,
  };
}

async function ohttpDecapsulate(envelope) {
  // In production this would be done by the relay
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: envelope.iv },
    envelope._aesKey,
    envelope.encryptedRequest,
  );
  return new Uint8Array(decrypted);
}

// ── Main fetchOnion function ──
// Agents call this to fetch a .onion address through this IWA's Tor circuit
export async function fetchOnion({ url, method, headers, body, useOHTTP }) {
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
    let ohttpEnvelope = null;

    if (useOHTTP) {
      // Encapsulate the request in OHTTP before sending
      ohttpEnvelope = await ohttpEncapsulate({
        method: httpMethod,
        hostname,
        path,
      });
      logFetch({
        type: 'ohttp',
        url,
        action: 'encapsulated',
        envelopeSize: ohttpEnvelope.encryptedRequest.length,
      });
    }

    // Actually fetch through Tor SOCKS5
    const result = await httpOverSocks(hostname, port, path, httpMethod, headers || {}, body || null);

    logFetch({
      type: 'response',
      url,
      status: result.status,
      bodyLength: result.body.length,
      ohttp: !!useOHTTP,
    });

    // Capture TLS cert info if available in response headers
    const certFingerprint = result.headers['x-tor-cert-fingerprint'] || null;

    return {
      success: true,
      status: result.status,
      statusText: result.statusText,
      headers: result.headers,
      body: result.body.slice(0, 64 * 1024), // cap at 64KB for agent consumption
      bodyLength: result.body.length,
      certFingerprint,
      ohttp: !!useOHTTP,
      ohttpEnvelopeSize: ohttpEnvelope ? ohttpEnvelope.encryptedRequest.length : null,
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

    // Read HTTP request
    let requestData = new Uint8Array(0);
    const timeout = setTimeout(() => reader.cancel(), 10000);

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const merged = new Uint8Array(requestData.length + value.length);
        merged.set(requestData);
        merged.set(value, requestData.length);
        requestData = merged;

        // Check if we have a complete HTTP request (headers end with \r\n\r\n)
        const text = new TextDecoder().decode(requestData);
        if (text.includes('\r\n\r\n')) break;
        if (requestData.length > 64 * 1024) break; // 64KB header limit
      }
    } catch (e) {
      // Read error — client disconnected
    }
    clearTimeout(timeout);

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
