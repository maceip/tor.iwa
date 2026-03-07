# Tor IWA — Tor Hidden Service in Your Browser

A fully functional Tor hidden service running inside a Chrome Isolated Web App (IWA). Tor is compiled to WebAssembly. The hidden service listens on a real TCP socket via the Direct Sockets API. Seven WebMCP tools let AI agents operate the hidden service — fetch .onion sites, relay requests through peers for real privacy, open peer connections, manage access control, and verify service identities.

![Screenshot](iwa/public/og-image.png)

## What It Does

1. **Runs Tor in your browser** — The Tor binary is compiled to WASM and boots inside the IWA. It connects to the real Tor network, builds circuits, and bootstraps to 100%.

2. **Serves a hidden service** — A `TCPServerSocket` listens on `127.0.0.1:8080`. Tor advertises a `.onion` address. Anyone on the Tor network can reach your hidden service.

3. **OHTTP relay mesh** — Any instance can volunteer as an Oblivious HTTP relay. When you fetch with `useOHTTP=true`, your request is encrypted with a peer's ECDH public key, sent to their `.onion`, and the peer fetches the target on its own Tor circuit. Neither peer learns the other's IP (Tor handles that), and the target sees the relay's circuit, not yours. If no peers are available, the app automatically falls back to Tor circuit isolation (unique SOCKS5 credentials force a separate circuit via `IsolateSOCKSAuth`).

4. **AI agents can operate it** — Seven tools are registered via `navigator.modelContext` (WebMCP). An AI agent can fetch .onion URLs, manage the relay mesh, open peer-to-peer connections, manage who can access your service, and verify service identities with TOFU certificates.

## How to Set Up Chrome (Step by Step)

### Step 1: Get Chrome

You need regular **Google Chrome** (stable channel works). Download it from [google.com/chrome](https://www.google.com/chrome/) if you don't already have it. IWAs work in GA Chrome with flags — you do not need Canary.

### Step 2: Turn on the Flags

Open Chrome. In the address bar at the top, type each of these one at a time, press Enter, and flip the switch to **Enabled**:

```
chrome://flags/#enable-isolated-web-apps
```
This lets Chrome load Isolated Web Apps.

```
chrome://flags/#enable-isolated-web-app-dev-mode
```
This lets you load IWAs from your own computer during development.

```
chrome://flags/#direct-sockets
```
This lets the app open real TCP connections (needed for Tor).

```
chrome://flags/#enable-web-mcp
```
This lets AI agents use the tools the app registers.

After enabling all four flags, Chrome will ask you to **Relaunch**. Click the button.

### Step 3: Build the WASM Binary

You need the Tor WASM binary (`tor.js` and `tor.wasm`). If you have the Emscripten toolchain:

```bash
# From the repo root (adjust paths to your Tor source)
emcc tor-src/src/or/main.c ... -o iwa/public/tor.js \
  -s WASM=1 -s MODULARIZE=0 -s EXPORT_ES6=0 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_FUNCTIONS='["_main"]'
```

Or download a prebuilt `tor.js` + `tor.wasm` and place them in `iwa/public/`.

### Step 4: Load the IWA

1. Open Chrome
2. First, serve the files. Open a terminal and run:
   ```bash
   cd iwa/public
   python3 -m http.server 8080
   ```
   (Or use any static file server — `npx serve`, `php -S localhost:8080`, etc.)
3. Go to `chrome://web-app-internals`
4. Under **Install IWA from Dev Mode Proxy**, type:
   ```
   http://localhost:8080
   ```
5. Click **Install**
6. The IWA will open in its own window with a purple title bar

### Step 5: Use It

1. Click **Start Tor** — wait for bootstrap to reach 100%
2. Click **Start Service** — a `.onion` address appears (persisted across reloads via OPFS)
3. Click **Register 7 Tools** — WebMCP tools become available to AI agents
4. Click **Volunteer as Relay** — your instance now accepts OHTTP relay requests from peers

That's it. You're running a Tor hidden service with OHTTP relay capabilities inside your browser.

## OHTTP Privacy: How It Works

When an AI agent calls `fetchOnion({ url: "...", useOHTTP: true })`:

```
┌──────────┐    ECDH-encrypted    ┌──────────────┐    Separate     ┌──────────┐
│ Your IWA │ ────────────────────→ │ Peer Relay   │ ──────────────→ │  Target  │
│          │    via Tor circuit A  │ (.onion IWA) │  Tor circuit B  │  .onion  │
└──────────┘                      └──────────────┘                 └──────────┘
```

1. **Your IWA** encodes the request as Binary HTTP (RFC 9292), encrypts it with the peer's ECDH public key via AES-GCM
2. Sends the encrypted envelope to `peer.onion/.well-known/ohttp-relay` through Tor circuit A
3. **Peer relay** decrypts the envelope using its ECDH private key, extracts the BHTTP request
4. Fetches the target on **its own Tor circuit B** (different guard/middle/exit nodes)
5. Encrypts the response back and returns it

**Privacy properties:**
- Tor hides your IP from the relay (circuit A)
- The target sees circuit B, not circuit A — can't link the request to you
- The relay sees the request content but not who sent it
- AES-GCM encryption prevents Tor exit nodes from reading the envelope

**Fallback — no peers available:**
Uses SOCKS5 username/password auth with a unique random credential per request. Tor's `IsolateSOCKSAuth` forces a fresh circuit, so each OHTTP request goes through different guard/middle/exit nodes than your regular traffic.

## The 7 WebMCP Tools

| Tool | What It Does |
|------|-------------|
| `fetchOnion` | Fetches a `.onion` URL through Tor. With `useOHTTP=true`, routes through a peer relay (or circuit isolation fallback). Returns HTTP response + TOFU cert status + OHTTP mode used. |
| `manageOHTTPRelay` | Manage the OHTTP relay mesh. `volunteer` to accept relay requests, `addPeer` / `removePeer` to manage known relays, `status` to check relay stats. |
| `holepunch` | Opens a direct TCP connection to another `.onion` service via SOCKS5. Supports `connect` / `send` / `receive` / `close` for bidirectional peer-to-peer messaging over Tor. |
| `validateOnionCert` | Trust-on-first-use certificate management. Auto-captures service fingerprints on every fetch. Detects identity changes that may indicate compromise. |
| `manageTrustedClients` | Controls who can access your hidden service. When active, the HS rejects requests without a valid `X-Client-ID` header. Supports Ed25519 signature verification. |
| `listHolepunchSessions` | Lists all peer connections with status, message counts, and byte statistics. |
| `getServiceStatus` | Returns comprehensive status: HS uptime/stats, OHTTP relay state, access control, cert store health, active peer sessions. |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Chrome IWA Window                                  │
│                                                     │
│  ┌──────────┐  ┌────────────┐  ┌────────────────┐  │
│  │ Tor WASM │  │ UI (Preact)│  │ OHTTP Relay    │  │
│  │ (tor.js) │  │ (app.mjs)  │  │ (ECDH+AES-GCM) │  │
│  └────┬─────┘  └─────┬──────┘  └───────┬────────┘  │
│       │               │                │            │
│  ┌────▼─────┐  ┌──────▼──────┐  ┌──────▼───────┐   │
│  │ SOCKS5   │  │  WebMCP     │  │ Circuit      │   │
│  │ :9050    │  │  7 tools    │  │ Isolation    │   │
│  └────┬─────┘  └──────┬──────┘  └──────┬───────┘   │
│       │               │               │            │
│  ┌────▼───────────────▼───────────────▼────┐       │
│  │          Direct Sockets API             │       │
│  │  TCPSocket (SOCKS5) + TCPServer (HS)    │       │
│  └────┬────────────────────────────────────┘       │
│       │                                            │
│  ┌────▼─────┐  ┌──────────────────────────┐        │
│  │ HS :8080 │  │ /.well-known/ohttp-relay │        │
│  └──────────┘  └──────────────────────────┘        │
└─────────────────────────────────────────────────────┘
```

**Key connections:**
- `tor-fetch.mjs` — SOCKS5 client, circuit isolation (`socks5ConnectIsolated`), OHTTP relay handler, BHTTP codec, ECDH key exchange
- `webmcp.mjs` — Registers 7 tools with `navigator.modelContext`, manages relay peer registry, cert store, trusted clients
- `app.mjs` — Preact UI with OHTTP relay card, live dashboards, canvas visualizations

## Browser APIs Used

- **Direct Sockets** (`TCPSocket`, `TCPServerSocket`) — Real TCP connections for Tor SOCKS5 and HS listener
- **WebMCP** (`navigator.modelContext.registerTool`) — Exposes 7 tools to AI agents
- **Web Crypto** (Ed25519, ECDH P-256, AES-GCM, SHA-256) — Key generation, .onion derivation, OHTTP encryption, client auth
- **OPFS** (`navigator.storage.getDirectory`) — Persists HS keypair so .onion address survives reloads
- **Web Locks** (`navigator.locks`) — Prevents multiple tabs from binding the same HS port
- **File System Access** (`showDirectoryPicker`) — Optional persistent storage for Tor data
- **Service Worker** — Offline caching of app assets
- **View Transitions** — Smooth UI state changes
- **Share Target** — Receive URLs from the OS share sheet
- **Protocol Handler** — Register `web+tor://` URL scheme
- **Trusted Types** — CSP compliance required by IWA context

## Files

```
iwa/public/
  index.html              — Shell HTML with meta/OG tags
  app.mjs                 — UI (Preact + htm, no build step)
  app.css                 — Styles
  tor-fetch.mjs           — SOCKS5 client, HS listener, OHTTP relay, circuit isolation
  webmcp.mjs              — 7 WebMCP tool implementations
  sw.js                   — Service worker
  icon-192.png            — App icon
  icon-512.png            — App icon (large)
  og-image.png            — Social sharing image
  .well-known/manifest.webmanifest — IWA manifest with webmcp.tools
  lib/                    — Preact, preact-hooks, htm (vendored)
```

## License

MIT
