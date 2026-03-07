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

## The MCP Boundary Problem (and 3 Paths We're Building)

This is the hard part. IWAs and extensions live in different worlds, and Chrome's security model makes connecting them non-trivial. Here's exactly where the boundaries are and what we're doing about it.

### The Problem

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Chrome Browser                              │
│                                                                    │
│  ┌───────────────────────┐          ┌──────────────────────────┐   │
│  │    Extension          │          │    IWA (tor.iwa)          │   │
│  │    (MCP client)       │          │    (MCP tools live here)  │   │
│  │                       │    ✗     │                           │   │
│  │  Wants to call        │◄──┼────►│  Has 7 tools registered   │   │
│  │  fetchOnion, etc.     │    ✗     │  via navigator.modelContext│  │
│  │                       │          │                           │   │
│  └───────────────────────┘          └──────────────────────────┘   │
│                                                                    │
│  WHY THE ✗?                                                        │
│  • IWAs have isolated-app:// origins — not https://                │
│  • Chrome blocks content script injection into IWAs                │
│  • externally_connectable doesn't work with isolated-app://        │
│  • chrome.tabs.sendMessage can't reach IWA windows                 │
│  • BroadcastChannel is same-origin only                            │
│  • No shared DOM, no shared workers across these origins            │
└─────────────────────────────────────────────────────────────────────┘
```

Extensions are the primary way people use WebMCP today. But extensions **cannot inject content scripts into IWAs**, cannot use `externally_connectable` with `isolated-app://` origins, and cannot use `chrome.tabs.sendMessage` to reach IWA windows. This is by design — IWAs are security-hardened contexts.

We don't know which approach Chrome will eventually support for IWA-extension communication, so **we're building all three paths** and asking the community to evaluate them:

### Path 1: Native WebMCP (already works)

```js
// Inside the IWA — this works today with chrome://flags/#enable-web-mcp
navigator.modelContext.registerTool('fetchOnion', { ... }, handler);
```

The IWA calls `navigator.modelContext.registerTool()` directly. Chrome's built-in MCP infrastructure handles discovery and dispatch. **This is the cleanest path** — no bridge code, no relay, no workarounds. The catch: the `#enable-web-mcp` flag must be enabled, and it's Chrome-only.

**Status:** Implemented. 7 tools registered. Works today.

### Path 2: MCP JSON-RPC Server over the Hidden Service

```
┌──────────────┐     Tor circuit      ┌───────────────────────────┐
│ Any MCP      │ ───────────────────→ │ tor.iwa Hidden Service    │
│ client       │  POST /.well-known/  │                           │
│ (extension,  │       mcp            │ JSON-RPC handler          │
│  CLI, agent) │ ←─────────────────── │ dispatches to same 7 tools│
└──────────────┘                      └───────────────────────────┘
```

The hidden service already listens on a `TCPServerSocket`. We add a standard MCP JSON-RPC endpoint at `/.well-known/mcp`. **Any MCP client that can reach the `.onion` address** — an extension routing through Tor, a CLI tool, another agent — can discover and call tools via standard JSON-RPC over HTTP.

This completely sidesteps the IWA isolation problem. The communication doesn't go through Chrome's extension APIs at all — it goes through the Tor network to the hidden service's TCP socket.

```
GET  /.well-known/mcp              → Server info + capabilities
POST /.well-known/mcp              → JSON-RPC (tools/list, tools/call)
```

Example:
```json
// Request
{"jsonrpc":"2.0","id":1,"method":"tools/list"}

// Response
{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"fetchOnion",...},...]}}

// Tool call
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetchOnion","arguments":{"url":"http://...onion/"}}}
```

**Status:** Implemented. Enable with "Start MCP Server" button. Serves JSON-RPC at `your.onion/.well-known/mcp`.

### Path 3: BroadcastChannel / postMessage Bridge

```
┌──────────────────┐   window.postMessage   ┌──────────────────────┐
│ Extension popup  │ ◄───────────────────►  │ IWA window           │
│ or bridge page   │   (if window ref       │ (listens for mcp:*   │
│                  │    can be obtained)     │  prefixed messages)  │
└──────────────────┘                        └──────────────────────┘
```

The IWA opens a `BroadcastChannel('tor-iwa-mcp')` and a `window.postMessage` listener. Any code that can get a reference to the IWA window (e.g., if the IWA was opened via `window.open()`, or through a shared `BroadcastChannel` on the same origin) can send tool calls.

**Honest assessment:** This is the most limited path. `BroadcastChannel` is same-origin only, so it won't work cross-origin between an extension and an IWA. `window.postMessage` requires a window reference, which extensions typically can't get for IWA windows. But we're implementing it because:
1. It works for same-origin IWA-to-IWA communication
2. Chrome may add cross-origin IWA messaging in the future
3. It demonstrates the communication pattern the community wants

Message protocol:
```js
// Discovery
postMessage({ type: 'mcp:ping' })
// → { type: 'mcp:pong', source: 'tor-iwa', tools: 7 }

// List tools
postMessage({ type: 'mcp:tools/list' })
// → { type: 'mcp:tools/list:result', tools: [...] }

// Call a tool
postMessage({ type: 'mcp:tools/call', name: 'fetchOnion', arguments: { url: '...' }, id: '123' })
// → { type: 'mcp:tools/call:result', name: 'fetchOnion', id: '123', result: { ... } }
```

**Status:** Implemented. Enable with "Start Bridge" button. Listening on BroadcastChannel + postMessage.

### Which Path Should Chrome Support?

We think **Path 1 (native WebMCP) is the right answer** — it's clean, secure, and doesn't require workarounds. But until `navigator.modelContext` is widely available and extensions can discover IWA-registered tools, we need Paths 2 and 3 as alternatives.

**If you're from the Chrome team:** We'd love guidance on the intended IWA-extension communication model. Should IWAs be able to register as `externally_connectable`? Should there be a cross-origin messaging API for isolated apps? We're building this to help figure out the right answer.

**If you're a developer:** Try all three paths and tell us which works for your use case. File issues, open PRs, help us convince Chrome to support IWA-extension communication natively.

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
┌────────────────────────────────────────────────────────────────┐
│  Chrome IWA Window (isolated-app:// origin)                    │
│                                                                │
│  ┌──────────┐  ┌────────────┐  ┌──────────────────────────┐   │
│  │ Tor WASM │  │ UI (Preact)│  │ OHTTP Relay (ECDH+AES)  │   │
│  │ (tor.js) │  │ (app.mjs)  │  │ /.well-known/ohttp-relay│   │
│  └────┬─────┘  └─────┬──────┘  └───────────┬─────────────┘   │
│       │               │                     │                  │
│  ┌────▼─────┐  ┌──────▼──────────────┐  ┌──▼──────────────┐  │
│  │ SOCKS5   │  │  3 MCP Paths:       │  │ Circuit         │  │
│  │ :9050    │  │  ① WebMCP (native)  │  │ Isolation       │  │
│  │          │  │  ② JSON-RPC on HS   │  │ (SOCKS5 auth)   │  │
│  │          │  │  ③ postMessage      │  │                 │  │
│  └────┬─────┘  └──────┬──────────────┘  └──┬──────────────┘  │
│       │               │                     │                  │
│  ┌────▼───────────────▼─────────────────────▼──────┐          │
│  │             Direct Sockets API                  │          │
│  │   TCPSocket (SOCKS5) + TCPServerSocket (HS)     │          │
│  └────┬────────────────────────────────────────────┘          │
│       │                                                        │
│  ┌────▼────────────────────────────────────────────┐          │
│  │  Hidden Service :8080                           │          │
│  │  /.well-known/ohttp-relay  (OHTTP relay)        │          │
│  │  /.well-known/mcp          (MCP JSON-RPC)       │          │
│  └─────────────────────────────────────────────────┘          │
└────────────────────────────────────────────────────────────────┘
```

**Key modules:**
- `tor-fetch.mjs` — SOCKS5 client, circuit isolation, OHTTP relay handler, MCP JSON-RPC endpoint, BHTTP codec, ECDH key exchange
- `webmcp.mjs` — 7 tool implementations, MCP JSON-RPC dispatch, BroadcastChannel/postMessage bridge, relay peer registry, cert store, trusted clients
- `app.mjs` — Preact UI with OHTTP relay card, MCP path status, live dashboards, canvas visualizations

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
  tor-fetch.mjs           — SOCKS5 client, HS listener, OHTTP relay, MCP JSON-RPC endpoint, circuit isolation
  webmcp.mjs              — 7 tool implementations + MCP JSON-RPC handler + BroadcastChannel bridge
  sw.js                   — Service worker
  icon-192.png            — App icon
  icon-512.png            — App icon (large)
  og-image.png            — Social sharing image
  .well-known/manifest.webmanifest — IWA manifest with 7 webmcp.tools
  lib/                    — Preact, preact-hooks, htm (vendored)
```

## License

MIT
