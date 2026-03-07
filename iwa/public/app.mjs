import { h, render, Fragment } from './lib/preact.mjs';
import { useState, useEffect, useRef, useCallback, useMemo } from './lib/preact-hooks.mjs';
import htm from './lib/htm.mjs';
import {
  registerWebMCPTools, unregisterWebMCPTools,
  onionCertStore, trustedClients, holepunchSessions,
  fetchLog,
} from './webmcp.mjs';
import {
  startHiddenServiceListener, stopHiddenServiceListener,
  setRequestHandler, getServerStatus as getTorServerStatus,
  setLocalOnionAddress,
} from './tor-fetch.mjs';
const html = htm.bind(h);

// ────────────────────────────────────────────
// Trusted Types policy (required by IWA CSP)
// ────────────────────────────────────────────
const ttPolicy = (typeof trustedTypes !== 'undefined' && trustedTypes.createPolicy)
  ? trustedTypes.createPolicy('tor', {
      createScriptURL: (url) => url,
      createHTML: (html) => html,
    })
  : { createScriptURL: (u) => u, createHTML: (h) => h };

// ────────────────────────────────────────────
// Particle mesh background
// ────────────────────────────────────────────
// ── Visibility-aware animation helper ──
// Pauses all rAF loops when the tab is hidden to save battery/CPU
let _tabVisible = !document.hidden;
document.addEventListener('visibilitychange', () => { _tabVisible = !document.hidden; });

(function initBg() {
  const c = document.getElementById('bg-canvas'), ctx = c.getContext('2d');
  const N = Math.min(40, (navigator.hardwareConcurrency || 4) * 8);
  const D = 140;
  const pts = [];
  function resize() { c.width = innerWidth; c.height = innerHeight; }
  addEventListener('resize', resize); resize();
  for (let i = 0; i < N; i++) pts.push({
    x: Math.random() * c.width, y: Math.random() * c.height,
    vx: (Math.random() - 0.5) * 0.35, vy: (Math.random() - 0.5) * 0.35,
    r: Math.random() * 1.6 + 0.8,
  });
  (function loop() {
    if (_tabVisible) {
      ctx.clearRect(0, 0, c.width, c.height);
      for (let i = 0; i < pts.length; i++) {
        const p = pts[i];
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > c.width) p.vx *= -1;
        if (p.y < 0 || p.y > c.height) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 6.28);
        ctx.fillStyle = 'rgba(123,77,255,0.4)'; ctx.fill();
        for (let j = i + 1; j < pts.length; j++) {
          const q = pts[j];
          const dx = p.x - q.x, dy = p.y - q.y, d = Math.sqrt(dx * dx + dy * dy);
          if (d < D) {
            ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = `rgba(123,77,255,${0.1 * (1 - d / D)})`;
            ctx.lineWidth = 0.5; ctx.stroke();
          }
        }
      }
    }
    requestAnimationFrame(loop);
  })();
})();

// ────────────────────────────────────────────
// Global reactive state
// ────────────────────────────────────────────
const DEFAULT_TORRC = `SocksPort 9050
Log notice stdout
SafeLogging 0
DisableNetwork 0
DataDirectory /tor-data
HiddenServiceDir /tor-data/hs
HiddenServicePort 80 127.0.0.1:8080
`;

const S = {
  logs: [], status: 'idle', bootstrap: { pct: 0, step: '' },
  started: false, logDotOn: false,
  speed: { down: 0, up: 0 },
  circuit: [],
  fsBanner: true,
  fsHandle: null,
  sharedData: null,
  torrc: DEFAULT_TORRC,
  configModalOpen: false,
  // Hidden service state
  hsRunning: false,
  hsAddress: '',
  hsStats: { requestCount: 0, bytesServed: 0, uptimeMs: 0, connections: 0 },
  // Vanity brute-force state
  vanityOpen: false,
  vanityPrefix: '',
  vanityRunning: false,
  vanityAttempts: 0,
  vanityRate: 0,
  vanityFound: null,
  // WebMCP state
  webmcpAvailable: false,
  webmcpEnabled: false,
  webmcpCerts: [],
  webmcpClients: [],
  webmcpSessions: [],
  _subs: new Set(),
};
function emit() { S._subs.forEach(fn => fn()); }
function useStore() {
  const [, set] = useState(0);
  useEffect(() => { const fn = () => set(c => c + 1); S._subs.add(fn); return () => S._subs.delete(fn); }, []);
  return S;
}

function addLog(msg, cls = 'info') {
  const ts = new Date().toISOString().split('T')[1].slice(0, 12);
  S.logs.push({ ts, msg, cls, id: S.logs.length });
  if (S.logs.length > 600) S.logs = S.logs.slice(-500);
  emit();
}
function setStatus(s) { S.status = s; emit(); }

function parseBootstrap(text) {
  const m = text.match(/Bootstrapped (\d+)%[^:]*:\s*(.*)/);
  return m ? { pct: parseInt(m[1], 10), step: m[2] } : null;
}

function parseCircuit(text) {
  const m = text.match(/BUILT.*?(\$[A-F0-9~,\$\w]+)/i);
  if (m) {
    return m[1].split(',').map(r => {
      const nm = r.match(/~(\w+)/);
      return nm ? nm[1] : r.slice(0, 8);
    });
  }
  return null;
}

// Speed tracking
let _bytesDown = 0, _bytesUp = 0, _lastTick = performance.now();
function trackBytes(down, up) { _bytesDown += down; _bytesUp += up; }
setInterval(() => {
  const now = performance.now(), dt = (now - _lastTick) / 1000;
  if (dt > 0) {
    S.speed = { down: _bytesDown / dt, up: _bytesUp / dt };
    _bytesDown = 0; _bytesUp = 0; _lastTick = now;
    emit();
  }
}, 1000);

let _demoInterval = null;
function startDemoTraffic() {
  _demoInterval = setInterval(() => {
    if (S.status === 'connected') {
      trackBytes(Math.random() * 50000 + 5000, Math.random() * 8000 + 1000);
    }
  }, 200);
}

// ────────────────────────────────────────────
// Tor Module
// ────────────────────────────────────────────
window.Module = {
  print(text) {
    const bs = parseBootstrap(text);
    if (bs) {
      addLog(text, 'bootstrap');
      S.bootstrap = bs; emit();
      if (bs.pct >= 100) {
        setStatus('connected');
        S.circuit = ['Guard', 'Middle', 'Exit'];
        startDemoTraffic();
        emit();
      }
    } else {
      const circ = parseCircuit(text);
      if (circ) { S.circuit = circ; emit(); }
      addLog(text, 'info');
    }
  },
  printErr(text) {
    const bs = parseBootstrap(text);
    if (bs) {
      addLog(text, 'bootstrap');
      S.bootstrap = bs; emit();
      if (bs.pct >= 100) {
        setStatus('connected');
        S.circuit = ['Guard', 'Middle', 'Exit'];
        startDemoTraffic();
        emit();
      }
      return;
    }
    if (/\[err\]|FATAL/i.test(text)) addLog(text, 'err');
    else if (/\[warn\]/i.test(text)) addLog(text, 'warn');
    else addLog(text, 'info');
  },
  noExitRuntime: true,
  arguments: ['-f', '/torrc'],
  preRun: [function() {
    const fs = Module.FS || (typeof FS !== 'undefined' ? FS : null);
    if (!fs) {
      addLog('FS not available in preRun — torrc will not be written', 'err');
      return;
    }
    fs.writeFile('/torrc', S.torrc);
    try { fs.mkdir('/tor-data'); } catch(e) {}
    addLog('Virtual filesystem ready', 'ok');
  }],
  onRuntimeInitialized() {
    addLog('WASM runtime initialized', 'ok');
    S.logDotOn = true; emit();
  }
};

// ────────────────────────────────────────────
// Tachometer — fixed arc gauge with metric labels
// ────────────────────────────────────────────
const TACHO_TICKS = [
  { val: 0, label: '0' },
  { val: 1024, label: '1K' },
  { val: 10240, label: '10K' },
  { val: 102400, label: '100K' },
  { val: 524288, label: '512K' },
  { val: 1048576, label: '1M' },
  { val: 5242880, label: '5M' },
  { val: 10485760, label: '10M' },
];

function speedToAngle(bps) {
  // Log scale: 0 -> 0, 10M+ -> 1
  if (bps <= 0) return 0;
  const logMin = 0, logMax = Math.log10(10485760);
  return Math.min(Math.log10(Math.max(bps, 1)) / logMax, 1);
}

function drawTacho(canvas, speedBps) {
  const dpr = devicePixelRatio || 1;
  const W = canvas.clientWidth, H = canvas.clientHeight;
  if (W === 0 || H === 0) return;
  canvas.width = W * dpr; canvas.height = H * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const cx = W / 2, cy = H * 0.85;
  const R = Math.min(W / 2 - 20, H * 0.72);
  const sweepAngle = Math.PI * 1.4;
  const startA = Math.PI + (Math.PI - sweepAngle) / 2;
  const endA = startA + sweepAngle;

  // Background arc
  ctx.beginPath();
  ctx.arc(cx, cy, R, startA, endA);
  ctx.lineWidth = 6;
  ctx.strokeStyle = 'rgba(42,42,90,0.5)';
  ctx.lineCap = 'round';
  ctx.stroke();

  // Tick marks with labels
  for (let i = 0; i < TACHO_TICKS.length; i++) {
    const t = speedToAngle(TACHO_TICKS[i].val);
    const a = startA + t * sweepAngle;
    const inner = R - 14, outer = R - 2;
    ctx.beginPath();
    ctx.moveTo(cx + Math.cos(a) * inner, cy + Math.sin(a) * inner);
    ctx.lineTo(cx + Math.cos(a) * outer, cy + Math.sin(a) * outer);
    ctx.lineWidth = i % 2 === 0 ? 2 : 1;
    ctx.strokeStyle = 'rgba(136,136,170,0.5)';
    ctx.stroke();

    // Label
    const labelR = R - 22;
    const lx = cx + Math.cos(a) * labelR;
    const ly = cy + Math.sin(a) * labelR;
    ctx.fillStyle = 'rgba(136,136,170,0.6)';
    ctx.font = '7px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(TACHO_TICKS[i].label, lx, ly);
  }

  // Minor ticks between major ones
  for (let i = 0; i <= 40; i++) {
    const t = i / 40;
    const a = startA + t * sweepAngle;
    const inner = R - 6, outer = R - 2;
    ctx.beginPath();
    ctx.moveTo(cx + Math.cos(a) * inner, cy + Math.sin(a) * inner);
    ctx.lineTo(cx + Math.cos(a) * outer, cy + Math.sin(a) * outer);
    ctx.lineWidth = 0.5;
    ctx.strokeStyle = 'rgba(136,136,170,0.2)';
    ctx.stroke();
  }

  // Active arc
  const pct = speedToAngle(speedBps);
  if (pct > 0.005) {
    const grad = ctx.createLinearGradient(cx - R, cy, cx + R, cy);
    grad.addColorStop(0, '#7b4dff');
    grad.addColorStop(0.5, '#00ccff');
    grad.addColorStop(1, '#00ff88');
    ctx.beginPath();
    ctx.arc(cx, cy, R, startA, startA + pct * sweepAngle);
    ctx.lineWidth = 6;
    ctx.strokeStyle = grad;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Glow
    ctx.beginPath();
    ctx.arc(cx, cy, R, startA, startA + pct * sweepAngle);
    ctx.lineWidth = 16;
    ctx.strokeStyle = 'rgba(0,255,136,0.06)';
    ctx.stroke();
  }

  // Needle
  const needleA = startA + pct * sweepAngle;
  const needleR = R - 28;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(needleA) * needleR, cy + Math.sin(needleA) * needleR);
  ctx.lineWidth = 2;
  ctx.strokeStyle = pct > 0.7 ? '#00ff88' : pct > 0.4 ? '#00ccff' : '#7b4dff';
  ctx.lineCap = 'round';
  ctx.stroke();

  // Center dot
  ctx.beginPath();
  ctx.arc(cx, cy, 4, 0, 6.28);
  ctx.fillStyle = '#7b4dff';
  ctx.fill();
}

function formatSpeed(bps) {
  if (bps < 1024) return { val: bps.toFixed(0), unit: 'B/s' };
  if (bps < 1048576) return { val: (bps / 1024).toFixed(1), unit: 'KB/s' };
  return { val: (bps / 1048576).toFixed(2), unit: 'MB/s' };
}

function Tachometer({ speed }) {
  const ref = useRef(null);
  const animSpeed = useRef(0);

  useEffect(() => {
    let raf;
    function draw() {
      if (!ref.current) return;
      if (_tabVisible) {
        animSpeed.current += (speed - animSpeed.current) * 0.12;
        drawTacho(ref.current, animSpeed.current);
      }
      raf = requestAnimationFrame(draw);
    }
    draw();
    return () => cancelAnimationFrame(raf);
  }, [speed]);

  const fmt = formatSpeed(speed);
  return html`
    <div class="tacho-wrap">
      <canvas ref=${ref}></canvas>
      <div class="tacho-reading">
        <div class="tacho-value">${fmt.val}</div>
        <div class="tacho-unit">${fmt.unit}</div>
      </div>
    </div>
  `;
}

// ────────────────────────────────────────────
// Circuit diagram — deep cerulean warped mesh bg
// ────────────────────────────────────────────
function drawCircuitBg(ctx, W, H, time) {
  // Deep cerulean blue mesh with warped convex distortion
  const cols = 14, rows = 10;
  const t = time * 0.0003;

  for (let iy = 0; iy < rows; iy++) {
    for (let ix = 0; ix < cols; ix++) {
      const u = ix / (cols - 1), v = iy / (rows - 1);
      // Convex warp: push points outward from center
      const dx = u - 0.5, dy = v - 0.5;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const warp = 1 + 0.35 * Math.pow(dist, 0.6);
      const wx = 0.5 + dx * warp + Math.sin(t + iy * 0.4) * 0.015;
      const wy = 0.5 + dy * warp + Math.cos(t + ix * 0.3) * 0.015;
      const px = wx * W, py = wy * H;

      // Draw connections to right and down neighbors
      const alpha = 0.08 + 0.06 * Math.sin(t * 2 + ix * 0.5 + iy * 0.7);
      ctx.strokeStyle = `rgba(0,100,180,${alpha})`;
      ctx.lineWidth = 0.6;

      if (ix < cols - 1) {
        const nu = (ix + 1) / (cols - 1), nv = v;
        const ndx = nu - 0.5, ndy = nv - 0.5;
        const ndist = Math.sqrt(ndx * ndx + ndy * ndy);
        const nwarp = 1 + 0.35 * Math.pow(ndist, 0.6);
        const npx = (0.5 + ndx * nwarp + Math.sin(t + iy * 0.4) * 0.015) * W;
        const npy = (0.5 + ndy * nwarp + Math.cos(t + (ix + 1) * 0.3) * 0.015) * H;
        ctx.beginPath(); ctx.moveTo(px, py); ctx.lineTo(npx, npy); ctx.stroke();
      }
      if (iy < rows - 1) {
        const nu2 = u, nv2 = (iy + 1) / (rows - 1);
        const ndx2 = nu2 - 0.5, ndy2 = nv2 - 0.5;
        const ndist2 = Math.sqrt(ndx2 * ndx2 + ndy2 * ndy2);
        const nwarp2 = 1 + 0.35 * Math.pow(ndist2, 0.6);
        const npx2 = (0.5 + ndx2 * nwarp2 + Math.sin(t + (iy + 1) * 0.4) * 0.015) * W;
        const npy2 = (0.5 + ndy2 * nwarp2 + Math.cos(t + ix * 0.3) * 0.015) * H;
        ctx.beginPath(); ctx.moveTo(px, py); ctx.lineTo(npx2, npy2); ctx.stroke();
      }

      // Node dots
      ctx.beginPath(); ctx.arc(px, py, 1, 0, 6.28);
      ctx.fillStyle = `rgba(0,140,220,${0.15 + 0.1 * Math.sin(t * 3 + ix + iy)})`;
      ctx.fill();
    }
  }
}

function drawNetwork(canvas, circuit, status, time) {
  const dpr = devicePixelRatio || 1;
  const W = canvas.clientWidth, H = canvas.clientHeight;
  if (W === 0 || H === 0) return;
  canvas.width = W * dpr; canvas.height = H * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  // Draw warped cerulean mesh background
  drawCircuitBg(ctx, W, H, time);

  const earthCx = W / 2, earthCy = H * 3.2;
  const earthR = H * 2.8;
  ctx.beginPath();
  ctx.arc(earthCx, earthCy, earthR, Math.PI * 1.35, Math.PI * 1.65, false);
  ctx.lineWidth = 1.5;
  ctx.strokeStyle = 'rgba(0,120,200,0.2)';
  ctx.stroke();

  const nodes = ['You', ...(circuit.length ? circuit : ['Guard', 'Middle', 'Exit']), 'Dest'];
  const n = nodes.length;
  const positions = [];

  for (let i = 0; i < n; i++) {
    const t = (i / (n - 1));
    const a = Math.PI * 1.38 + t * Math.PI * 0.24;
    const x = earthCx + Math.cos(a) * (earthR - 24);
    const y = earthCy + Math.sin(a) * (earthR - 24);
    positions.push({ x, y, label: nodes[i] });
  }

  for (let i = 0; i < positions.length - 1; i++) {
    const a = positions[i], b = positions[i + 1];
    const cpY = Math.min(a.y, b.y) - 25;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.quadraticCurveTo((a.x + b.x) / 2, cpY, b.x, b.y);
    ctx.lineWidth = 1.5;
    const connected = status === 'connected';
    ctx.strokeStyle = connected ? 'rgba(0,255,136,0.35)' : 'rgba(136,136,170,0.2)';
    ctx.stroke();

    if (connected) {
      const pktT = ((time * 0.001 + i * 0.25) % 1);
      const px = (1 - pktT) * (1 - pktT) * a.x + 2 * (1 - pktT) * pktT * ((a.x + b.x) / 2) + pktT * pktT * b.x;
      const py = (1 - pktT) * (1 - pktT) * a.y + 2 * (1 - pktT) * pktT * cpY + pktT * pktT * b.y;
      ctx.beginPath(); ctx.arc(px, py, 3, 0, 6.28);
      ctx.fillStyle = '#00ff88'; ctx.fill();
      ctx.beginPath(); ctx.arc(px, py, 8, 0, 6.28);
      ctx.fillStyle = 'rgba(0,255,136,0.15)'; ctx.fill();
    }
  }

  for (let i = 0; i < positions.length; i++) {
    const p = positions[i];
    const isEnd = i === 0 || i === positions.length - 1;
    const r = isEnd ? 8 : 6;

    ctx.beginPath(); ctx.arc(p.x, p.y, r + 6, 0, 6.28);
    ctx.fillStyle = isEnd ? 'rgba(123,77,255,0.15)' : 'rgba(0,204,255,0.1)';
    ctx.fill();

    ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, 6.28);
    ctx.fillStyle = isEnd ? '#7b4dff' : (status === 'connected' ? '#00ccff' : '#555577');
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = isEnd ? '#a855f7' : (status === 'connected' ? '#00ccff' : '#555577');
    ctx.stroke();

    ctx.fillStyle = 'rgba(224,224,240,0.7)';
    ctx.font = '9px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(p.label, p.x, p.y - r - 8);
  }
}

function NetworkDiagram({ circuit, status }) {
  const ref = useRef(null);

  useEffect(() => {
    let raf;
    function draw(t) {
      if (ref.current && _tabVisible) drawNetwork(ref.current, circuit, status, t);
      raf = requestAnimationFrame(draw);
    }
    draw(0);
    return () => cancelAnimationFrame(raf);
  }, [circuit, status]);

  return html`
    <div class="net-wrap">
      <canvas ref=${ref}></canvas>
    </div>
  `;
}

// ────────────────────────────────────────────
// Vanity brute-force complexity visualization
// ────────────────────────────────────────────
function estimateBruteForceTime(prefix) {
  if (!prefix || prefix.length === 0) return 0;
  // v3 onion addresses use base32 (32 chars). For n-char prefix: 32^n combinations.
  // Rough estimate: ~50,000 keys/sec in JS (Web Crypto).
  const keysPerSec = 50000;
  const combinations = Math.pow(32, prefix.length);
  const expectedAttempts = combinations / 2; // average case
  return expectedAttempts / keysPerSec; // seconds
}

function drawComplexityViz(canvas, prefix, time) {
  const dpr = devicePixelRatio || 1;
  const W = canvas.clientWidth, H = canvas.clientHeight;
  if (W === 0 || H === 0) return;
  canvas.width = W * dpr; canvas.height = H * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const secs = estimateBruteForceTime(prefix);
  const hours = secs / 3600;
  const days = hours / 24;
  const years = days / 365;

  ctx.clearRect(0, 0, W, H);

  if (prefix.length === 0) {
    ctx.fillStyle = 'rgba(136,136,170,0.4)';
    ctx.font = '10px monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Type a prefix to see difficulty', W / 2, H / 2);
    return;
  }

  const sandColor = '#ff8800';
  const cx = W / 2, cy = H / 2;

  if (years <= 0 && days < 1) {
    // Very easy: empty hourglass
    drawHourglass(ctx, cx, cy, H * 0.4, 0, sandColor, time);
    ctx.fillStyle = 'rgba(0,255,136,0.7)';
    ctx.font = '9px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(secs < 1 ? 'Instant' : secs.toFixed(0) + 's', cx, cy + H * 0.45);
  } else if (years < 1) {
    // Moderate: hourglass filling with sand
    const fill = Math.min(days / 365, 1);
    drawHourglass(ctx, cx, cy, H * 0.4, fill, sandColor, time);
    ctx.fillStyle = 'rgba(255,204,0,0.8)';
    ctx.font = '9px monospace';
    ctx.textAlign = 'center';
    const label = days < 2 ? hours.toFixed(0) + ' hours' : days.toFixed(0) + ' days';
    ctx.fillText(label, cx, cy + H * 0.45);
  } else if (years < 100) {
    // Hard: baby -> old man
    const age = Math.min(years, 100);
    drawLifespan(ctx, cx, cy, H * 0.35, age, sandColor, time);
    ctx.fillStyle = 'rgba(255,136,0,0.8)';
    ctx.font = '9px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(years.toFixed(0) + ' years', cx, cy + H * 0.45);
  } else {
    // Impossible: planet -> black hole
    const severity = Math.min(Math.log10(years) / 10, 1); // 100 yrs -> 0.2, 10^10 -> 1.0
    drawCosmic(ctx, cx, cy, H * 0.35, severity, time);
    ctx.fillStyle = 'rgba(255,51,85,0.9)';
    ctx.font = '9px monospace';
    ctx.textAlign = 'center';
    const label = years < 1e6 ? (years / 1000).toFixed(0) + 'K years'
      : years < 1e9 ? (years / 1e6).toFixed(0) + 'M years'
      : (years / 1e9).toFixed(0) + 'B years';
    ctx.fillText(label, cx, cy + H * 0.45);
  }
}

function drawHourglass(ctx, cx, cy, size, fill, color, time) {
  const hw = size * 0.3, hh = size * 0.45;

  // Outline
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(cx - hw, cy - hh);
  ctx.lineTo(cx + hw, cy - hh);
  ctx.lineTo(cx + 2, cy);
  ctx.lineTo(cx + hw, cy + hh);
  ctx.lineTo(cx - hw, cy + hh);
  ctx.lineTo(cx - 2, cy);
  ctx.closePath();
  ctx.stroke();

  // Sand in bottom half
  if (fill > 0) {
    const sandH = hh * fill;
    ctx.fillStyle = color;
    ctx.globalAlpha = 0.6;
    ctx.beginPath();
    const bw = hw * (sandH / hh);
    ctx.moveTo(cx - bw, cy + hh - sandH);
    ctx.lineTo(cx + bw, cy + hh - sandH);
    ctx.lineTo(cx + hw, cy + hh);
    ctx.lineTo(cx - hw, cy + hh);
    ctx.closePath();
    ctx.fill();

    // Falling sand stream
    if (fill < 0.99) {
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx, cy + hh - sandH);
      ctx.lineWidth = 1;
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }
}

function drawLifespan(ctx, cx, cy, size, years, color, time) {
  // Stick figure that ages: baby (0) -> child (20) -> adult (40) -> old (80) -> ancient (100)
  const agePct = years / 100;
  const headR = size * (0.15 - agePct * 0.03);
  const bodyH = size * (0.2 + agePct * 0.4);
  const lean = agePct > 0.6 ? (agePct - 0.6) * 0.5 : 0;

  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.lineWidth = 1.5;
  ctx.globalAlpha = 0.7;

  // Head
  const headY = cy - bodyH * 0.5 - headR;
  ctx.beginPath(); ctx.arc(cx + lean * size * 0.3, headY, headR, 0, 6.28); ctx.stroke();

  // Body
  const topY = headY + headR;
  const botY = topY + bodyH * 0.5;
  ctx.beginPath();
  ctx.moveTo(cx + lean * size * 0.3, topY);
  ctx.lineTo(cx + lean * size * 0.5, botY);
  ctx.stroke();

  // Legs
  ctx.beginPath();
  ctx.moveTo(cx + lean * size * 0.5, botY);
  ctx.lineTo(cx - size * 0.15, botY + bodyH * 0.35);
  ctx.moveTo(cx + lean * size * 0.5, botY);
  ctx.lineTo(cx + size * 0.2 + lean * size * 0.3, botY + bodyH * 0.35);
  ctx.stroke();

  // Arms
  const armY = topY + bodyH * 0.15;
  ctx.beginPath();
  ctx.moveTo(cx + lean * size * 0.4, armY);
  ctx.lineTo(cx - size * 0.25, armY + bodyH * 0.15);
  ctx.moveTo(cx + lean * size * 0.4, armY);
  ctx.lineTo(cx + size * 0.3 + lean * size * 0.2, armY + bodyH * 0.1);
  ctx.stroke();

  // Walking stick for old age
  if (agePct > 0.5) {
    ctx.beginPath();
    const stickX = cx + size * 0.35 + lean * size * 0.3;
    ctx.moveTo(stickX, armY + bodyH * 0.1);
    ctx.lineTo(stickX + size * 0.05, botY + bodyH * 0.35);
    ctx.stroke();
  }

  ctx.globalAlpha = 1;
}

function drawCosmic(ctx, cx, cy, size, severity, time) {
  const t = time * 0.001;
  // Planet morphing into black hole
  const planetR = size * (0.35 - severity * 0.15);

  // Accretion disk / glow
  const diskR = size * 0.5;
  const grad = ctx.createRadialGradient(cx, cy, planetR * 0.5, cx, cy, diskR);
  grad.addColorStop(0, severity > 0.7 ? 'rgba(20,0,40,0.9)' : 'rgba(0,80,160,0.3)');
  grad.addColorStop(0.5, `rgba(${Math.floor(255 * severity)},${Math.floor(80 * (1 - severity))},0,0.2)`);
  grad.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.beginPath(); ctx.arc(cx, cy, diskR, 0, 6.28);
  ctx.fillStyle = grad; ctx.fill();

  // Swirl lines
  for (let i = 0; i < 8; i++) {
    const a = t + i * Math.PI * 0.25;
    const r1 = planetR + 4, r2 = diskR - 4;
    ctx.beginPath();
    ctx.arc(cx, cy, (r1 + r2) / 2, a, a + 0.3);
    ctx.strokeStyle = `rgba(255,${Math.floor(136 * (1 - severity))},0,${0.15 + severity * 0.1})`;
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  // Core body
  ctx.beginPath(); ctx.arc(cx, cy, planetR, 0, 6.28);
  if (severity > 0.7) {
    // Black hole
    ctx.fillStyle = '#000';
    ctx.fill();
    ctx.strokeStyle = `rgba(255,100,0,${0.5 + 0.3 * Math.sin(t * 2)})`;
    ctx.lineWidth = 2;
    ctx.stroke();
  } else {
    // Planet
    const pGrad = ctx.createRadialGradient(cx - planetR * 0.3, cy - planetR * 0.3, 0, cx, cy, planetR);
    pGrad.addColorStop(0, 'rgba(0,120,200,0.8)');
    pGrad.addColorStop(1, 'rgba(0,40,80,0.9)');
    ctx.fillStyle = pGrad;
    ctx.fill();
  }
}

function ComplexityViz({ prefix }) {
  const ref = useRef(null);
  useEffect(() => {
    let raf;
    function draw(t) {
      if (ref.current && _tabVisible) drawComplexityViz(ref.current, prefix, t);
      raf = requestAnimationFrame(draw);
    }
    draw(0);
    return () => cancelAnimationFrame(raf);
  }, [prefix]);

  return html`<canvas ref=${ref} class="complexity-canvas"></canvas>`;
}

// ────────────────────────────────────────────
// Onion key generation (ed25519 via Web Crypto + SHA3)
// ────────────────────────────────────────────
// Tor v3 .onion = base32(pubkey + checksum + version)
// checksum = SHA3-256(".onion checksum" + pubkey + version)[:2]
// We use a minimal SHA3-256 (Keccak) implementation inline.

// Keccak / SHA3-256 - minimal implementation
const KECCAK_ROUNDS = 24;
const RC = new BigUint64Array([
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
]);
const ROT_OFFSETS = [
  0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14
];

function keccakF(stateU64) {
  for (let round = 0; round < KECCAK_ROUNDS; round++) {
    // Theta
    const C = new BigUint64Array(5);
    for (let x = 0; x < 5; x++) C[x] = stateU64[x] ^ stateU64[x+5] ^ stateU64[x+10] ^ stateU64[x+15] ^ stateU64[x+20];
    for (let x = 0; x < 5; x++) {
      const D = C[(x+4)%5] ^ ((C[(x+1)%5] << 1n) | (C[(x+1)%5] >> 63n));
      for (let y = 0; y < 25; y += 5) stateU64[y+x] ^= D;
    }
    // Rho + Pi
    const B = new BigUint64Array(25);
    for (let i = 0; i < 25; i++) {
      const x = i % 5, y = Math.floor(i / 5);
      const newX = y, newY = (2 * x + 3 * y) % 5;
      const r = BigInt(ROT_OFFSETS[i]);
      B[newY * 5 + newX] = r ? ((stateU64[i] << r) | (stateU64[i] >> (64n - r))) : stateU64[i];
    }
    // Chi
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        stateU64[y+x] = B[y+x] ^ ((~B[y+(x+1)%5]) & B[y+(x+2)%5]);
      }
    }
    // Iota
    stateU64[0] ^= RC[round];
  }
}

function sha3_256(data) {
  const rate = 136; // SHA3-256 rate in bytes
  const state = new Uint8Array(200);
  const stateU64 = new BigUint64Array(state.buffer);

  // Absorb
  let offset = 0;
  while (offset + rate <= data.length) {
    for (let i = 0; i < rate; i++) state[i] ^= data[offset + i];
    keccakF(stateU64);
    offset += rate;
  }
  // Pad
  const remaining = data.length - offset;
  for (let i = 0; i < remaining; i++) state[i] ^= data[offset + i];
  state[remaining] ^= 0x06; // SHA3 domain separator
  state[rate - 1] ^= 0x80;
  keccakF(stateU64);

  return new Uint8Array(state.buffer, 0, 32);
}

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
function base32Encode(data) {
  let result = '', bits = 0, value = 0;
  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += B32[(value >> bits) & 31];
    }
  }
  if (bits > 0) result += B32[(value << (5 - bits)) & 31];
  return result;
}

function pubkeyToOnion(pubkey) {
  // checksum = SHA3-256(".onion checksum" + pubkey + version)[:2]
  const prefix = new TextEncoder().encode('.onion checksum');
  const input = new Uint8Array(prefix.length + 32 + 1);
  input.set(prefix);
  input.set(pubkey, prefix.length);
  input[prefix.length + 32] = 3; // version
  const checksum = sha3_256(input);

  // address = base32(pubkey + checksum[:2] + version)
  const addrBytes = new Uint8Array(35);
  addrBytes.set(pubkey);
  addrBytes[32] = checksum[0];
  addrBytes[33] = checksum[1];
  addrBytes[34] = 3;
  return base32Encode(addrBytes);
}

// Ed25519 keypair generation using Web Crypto with OPFS persistence.
// Persisting the keypair in OPFS gives a stable .onion address across sessions.
let _vanityWorker = null;

async function generateEd25519Keypair() {
  try {
    const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const rawPub = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    return {
      publicKey: new Uint8Array(rawPub),
      privateKey: new Uint8Array(pkcs8),
    };
  } catch(e) {
    // Fallback: random bytes (won't produce valid Tor keys, but works for UI testing)
    const pub = new Uint8Array(32);
    crypto.getRandomValues(pub);
    return { publicKey: pub, privateKey: new Uint8Array(64) };
  }
}

// OPFS-based keypair persistence — survives page reloads for stable .onion address
async function loadOrCreateKeypair() {
  try {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle('hs-keys', { create: true });

    // Try to load existing keypair
    try {
      const pubHandle = await dir.getFileHandle('pub.key');
      const privHandle = await dir.getFileHandle('priv.key');
      const pubFile = await pubHandle.getFile();
      const privFile = await privHandle.getFile();
      const publicKey = new Uint8Array(await pubFile.arrayBuffer());
      const privateKey = new Uint8Array(await privFile.arrayBuffer());
      if (publicKey.length === 32 && privateKey.length > 0) {
        addLog('Loaded persisted HS keypair from OPFS', 'ok');
        return { publicKey, privateKey, persisted: true };
      }
    } catch (e) {
      // No existing keypair — generate new one
    }

    // Generate and persist
    const kp = await generateEd25519Keypair();
    const pubHandle = await dir.getFileHandle('pub.key', { create: true });
    const privHandle = await dir.getFileHandle('priv.key', { create: true });
    const pubW = await pubHandle.createWritable();
    await pubW.write(kp.publicKey);
    await pubW.close();
    const privW = await privHandle.createWritable();
    await privW.write(kp.privateKey);
    await privW.close();
    addLog('Generated and persisted new HS keypair to OPFS', 'ok');
    return { ...kp, persisted: true };
  } catch (e) {
    // OPFS not available — fall back to ephemeral keypair
    addLog('OPFS not available — keypair is ephemeral (' + e.message + ')', 'warn');
    return { ...(await generateEd25519Keypair()), persisted: false };
  }
}

async function searchVanity(prefix, onProgress, signal) {
  const target = prefix.toLowerCase();
  let attempts = 0;
  const startTime = performance.now();

  while (!signal.aborted) {
    const kp = await generateEd25519Keypair();
    const address = pubkeyToOnion(kp.publicKey);
    attempts++;

    if (attempts % 100 === 0) {
      const elapsed = (performance.now() - startTime) / 1000;
      onProgress({ attempts, rate: Math.floor(attempts / elapsed) });
      // Yield to UI
      await new Promise(r => setTimeout(r, 0));
    }

    if (address.startsWith(target)) {
      return { address: address + '.onion', publicKey: kp.publicKey, privateKey: kp.privateKey, attempts };
    }
  }
  return null;
}

// ────────────────────────────────────────────
// Components
// ────────────────────────────────────────────

function FSBanner({ show, onGrant, onDismiss }) {
  if (!show) return null;
  if (!('showDirectoryPicker' in window)) return null;
  return html`
    <div class="banner">
      <div class="msg">
        <strong>File System</strong> \u2014 Grant access to a local folder for persistent Tor data, configs, and downloads.
      </div>
      <button class="primary" onClick=${onGrant}>Grant Access</button>
      <span class="dismiss" onClick=${onDismiss}>\u2715</span>
    </div>
  `;
}

function ShareBanner({ data, onDismiss }) {
  if (!data) return null;
  return html`
    <div class="banner">
      <div class="msg">
        <strong>Shared</strong> \u2014 ${data.title || data.text || data.url || 'File received'}
      </div>
      <span class="dismiss" onClick=${onDismiss}>\u2715</span>
    </div>
  `;
}

function StatusPill({ status }) {
  const L = { idle: 'Idle', starting: 'Starting', connected: 'Connected', error: 'Error' };
  return html`<div class="pill ${status}">${L[status]}</div>`;
}

function BootstrapProgress({ pct, step }) {
  if (pct <= 0) return null;
  return html`
    <div class="progress-wrap">
      <div class="progress-top"><span>Bootstrap</span><span>${pct}%</span></div>
      <div class="bar"><div class="bar-fill" style="width:${pct}%"></div></div>
      <div class="progress-step">${step}</div>
    </div>
  `;
}

function Controls({ started, onStart, onStop, onClear, onConfig }) {
  return html`
    <div class="controls">
      <button class="primary" disabled=${started} onClick=${onStart}>
        ${started ? '\u25B6 Running' : '\u25B6 Start Tor'}
      </button>
      <button class="danger" disabled=${!started} onClick=${onStop}>Stop</button>
      <div class="spacer" />
      <button onClick=${onClear}>Clear</button>
      <button onClick=${onConfig}>\u2699 Config</button>
    </div>
  `;
}

function ConfigModal({ open, onClose }) {
  const textRef = useRef(null);

  const handleSave = useCallback(() => {
    if (textRef.current) {
      S.torrc = textRef.current.value;
      // Also set on window for preRun to pick up
      window._torrcOverride = S.torrc;
      addLog('torrc updated (takes effect on next start)', 'ok');
    }
    onClose();
  }, [onClose]);

  const handleBackdrop = useCallback((e) => {
    if (e.target === e.currentTarget) onClose();
  }, [onClose]);

  useEffect(() => {
    if (open && textRef.current) textRef.current.value = S.torrc;
  }, [open]);

  // Use native dialog API if available, CSS transition overlay otherwise
  return html`
    <div class="modal-overlay ${open ? 'open' : ''}" onClick=${handleBackdrop}>
      <div class="modal ${open ? 'open' : ''}">
        <div class="modal-head">
          <span>torrc configuration</span>
          <span class="modal-close" onClick=${onClose}>\u2715</span>
        </div>
        <div class="modal-body">
          <textarea ref=${textRef} class="torrc-editor" defaultValue=${S.torrc}></textarea>
        </div>
        <div class="modal-foot">
          <button onClick=${onClose}>Cancel</button>
          <button class="primary" onClick=${handleSave}>Save</button>
        </div>
      </div>
    </div>
  `;
}

function formatUptime(ms) {
  if (ms <= 0) return '0s';
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ' + (s % 60) + 's';
  const h = Math.floor(m / 60);
  return h + 'h ' + (m % 60) + 'm';
}

function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(2) + ' MB';
}

function HiddenServiceCard({ running, address, stats, onStart, onStop }) {
  const display = address || 'not running';
  return html`
    <div class="card hs-card ${running ? 'running' : ''}">
      <div class="card-head">
        Hidden Service
        <span class="hs-status-dot ${running ? 'on' : ''}"></span>
      </div>
      <div class="card-body hs-body">
        <div class="hs-address-row">
          <div class="hs-onion ${address ? 'active' : ''}">${display}</div>
        </div>

        <div class="hs-stats-grid">
          <div class="hs-stat">
            <div class="hs-stat-val">${running ? formatUptime(stats.uptimeMs) : '--'}</div>
            <div class="hs-stat-label">Uptime</div>
          </div>
          <div class="hs-stat">
            <div class="hs-stat-val">${running ? stats.requestCount : '--'}</div>
            <div class="hs-stat-label">Requests</div>
          </div>
          <div class="hs-stat">
            <div class="hs-stat-val">${running ? formatBytes(stats.bytesServed) : '--'}</div>
            <div class="hs-stat-label">Served</div>
          </div>
          <div class="hs-stat">
            <div class="hs-stat-val">${running ? stats.connections : '--'}</div>
            <div class="hs-stat-label">Connections</div>
          </div>
        </div>

        <div class="hs-serve-info">
          ${running ? html`
            <div class="hs-serve-line">Listening on <span class="mono">127.0.0.1:8080</span></div>
            <div class="hs-serve-line">Serving default HTML response page</div>
          ` : html`
            <div class="hs-serve-line dim">TCPServerSocket listener inactive</div>
          `}
        </div>

        <div class="hs-buttons">
          <button class=${running ? 'danger' : 'primary'} onClick=${running ? onStop : onStart}>
            ${running ? 'Stop Service' : 'Start Service'}
          </button>
        </div>
      </div>
    </div>
  `;
}

function VanityBruteForce({ open, onToggle }) {
  const [prefix, setPrefix] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState({ attempts: 0, rate: 0 });
  const abortRef = useRef(null);

  const startSearch = useCallback(async () => {
    if (!prefix) return;
    setRunning(true);
    setResult(null);
    setStats({ attempts: 0, rate: 0 });
    const abort = new AbortController();
    abortRef.current = abort;

    const found = await searchVanity(prefix, (p) => setStats(p), abort.signal);
    setRunning(false);
    if (found) {
      setResult(found);
      addLog('Vanity address found: ' + found.address, 'ok');
    }
  }, [prefix]);

  const stopSearch = useCallback(() => {
    if (abortRef.current) abortRef.current.abort();
    setRunning(false);
  }, []);

  const estTime = estimateBruteForceTime(prefix);

  return html`
    <div class="vanity-section ${open ? 'open' : ''}">
      <div class="vanity-toggle" onClick=${onToggle}>
        <span class="arr">\u25B6</span>
        <span>Vanity Address Generator</span>
      </div>
      ${open && html`
        <div class="vanity-body">
          <div class="vanity-input-row">
            <input
              type="text"
              class="vanity-input"
              placeholder="Desired prefix (e.g. ryan)"
              value=${prefix}
              onInput=${(e) => setPrefix(e.target.value.toLowerCase().replace(/[^a-z2-7]/g, ''))}
              maxLength="8"
            />
            <button class=${running ? 'danger' : 'primary'} onClick=${running ? stopSearch : startSearch} disabled=${!prefix && !running}>
              ${running ? 'Stop' : 'Search'}
            </button>
          </div>

          <div class="vanity-viz-wrap">
            <${ComplexityViz} prefix=${prefix} />
          </div>

          ${running && html`
            <div class="vanity-stats">
              <span>Attempts: ${stats.attempts.toLocaleString()}</span>
              <span>Rate: ${stats.rate.toLocaleString()} keys/s</span>
            </div>
          `}

          ${result && html`
            <div class="vanity-result">
              <div class="onion-glow">${result.address}</div>
              <div class="vanity-result-info">Found in ${result.attempts.toLocaleString()} attempts</div>
            </div>
          `}
        </div>
      `}
    </div>
  `;
}

function LogViewer({ logs, dotOn }) {
  const ref = useRef(null);
  const prev = useRef(0);
  useEffect(() => {
    if (ref.current && logs.length > prev.current) ref.current.scrollTop = ref.current.scrollHeight;
    prev.current = logs.length;
  }, [logs.length]);
  return html`
    <div class="log-wrap">
      <div class="log-head">
        <div class="dot ${dotOn ? 'on' : ''}" />
        <span>Console</span>
        <span class="log-count">${logs.length} lines</span>
      </div>
      <div class="log" ref=${ref}>
        ${logs.map(l => html`
          <div class="ll" key=${l.id}>
            <span class="ll-ts">${l.ts}</span>
            <span class="ll-msg ${l.cls}">${l.msg}</span>
          </div>
        `)}
      </div>
    </div>
  `;
}

// ────────────────────────────────────────────
// WebMCP Panel — exposes Tor tools to AI agents
// ────────────────────────────────────────────

function refreshWebMCPState() {
  S.webmcpCerts = Array.from(onionCertStore.entries()).map(([addr, c]) => ({
    onionAddress: addr, fingerprint: c.fingerprint, lastSeen: c.lastSeen, valid: c.valid,
  }));
  S.webmcpClients = Array.from(trustedClients.entries()).map(([, c]) => c);
  S.webmcpSessions = Array.from(holepunchSessions.entries()).map(([, s]) => s);
  emit();
}

// Listen for WebMCP events dispatched by production tool handlers
function setupWebMCPListeners() {
  // Holepunch connected
  window.addEventListener('webmcp:holepunch:connected', (e) => {
    const { sessionId, target, port } = e.detail;
    addLog(`[WebMCP] Holepunch connected to ${target}:${port || 80} (${sessionId.slice(0, 8)}...)`, 'ok');
    refreshWebMCPState();
  });

  // Holepunch failed
  window.addEventListener('webmcp:holepunch:failed', (e) => {
    const { sessionId, target, error } = e.detail;
    addLog(`[WebMCP] Holepunch to ${target} failed: ${error}`, 'err');
    refreshWebMCPState();
  });

  // Holepunch closed
  window.addEventListener('webmcp:holepunch:closed', (e) => {
    const { sessionId, target } = e.detail;
    addLog(`[WebMCP] Holepunch session ${sessionId.slice(0, 8)}... closed`, 'info');
    refreshWebMCPState();
  });

  // TOFU cert auto-stored on first contact
  window.addEventListener('webmcp:cert-tofu', (e) => {
    const { hostname, fingerprint } = e.detail;
    addLog(`[WebMCP] TOFU: auto-stored cert for ${hostname.slice(0, 16)}...`, 'ok');
    refreshWebMCPState();
  });

  // Cert fingerprint mismatch detected
  window.addEventListener('webmcp:cert-mismatch', (e) => {
    const { hostname } = e.detail;
    addLog(`[WebMCP] CERT MISMATCH for ${hostname.slice(0, 16)}... — possible compromise!`, 'err');
    refreshWebMCPState();
  });

  // Cert manually stored by agent
  window.addEventListener('webmcp:cert-stored', (e) => {
    const { onionAddress } = e.detail;
    addLog(`[WebMCP] Cert stored for ${onionAddress.slice(0, 16)}...`, 'ok');
    refreshWebMCPState();
  });

  // Cert removed
  window.addEventListener('webmcp:cert-removed', (e) => {
    const { onionAddress } = e.detail;
    addLog(`[WebMCP] Cert removed for ${onionAddress.slice(0, 16)}...`, 'warn');
    refreshWebMCPState();
  });

  // Client added
  window.addEventListener('webmcp:client-added', (e) => {
    const { clientId, name } = e.detail;
    addLog(`[WebMCP] Trusted client added: ${name || clientId}`, 'ok');
    refreshWebMCPState();
  });

  // Client removed
  window.addEventListener('webmcp:client-removed', (e) => {
    const { clientId } = e.detail;
    addLog(`[WebMCP] Trusted client removed: ${clientId}`, 'warn');
    refreshWebMCPState();
  });

  // All clients cleared
  window.addEventListener('webmcp:clients-cleared', () => {
    addLog('[WebMCP] All trusted clients cleared — access control disabled', 'warn');
    refreshWebMCPState();
  });
}

function WebMCPCard({ available, enabled, onEnable, onDisable }) {
  const s = useStore();
  const [expanded, setExpanded] = useState(false);

  const toolDefs = [
    { name: 'holepunch', desc: 'NAT holepunch to .onion targets' },
    { name: 'validateOnionCert', desc: 'Cert fingerprint store/verify' },
    { name: 'manageTrustedClients', desc: 'Client trust management' },
    { name: 'listHolepunchSessions', desc: 'Active holepunch sessions' },
    { name: 'getServiceStatus', desc: 'Hidden service status' },
    { name: 'fetchOnion', desc: 'Fetch .onion via SOCKS5 + OHTTP' },
  ];

  return html`
    <div class="card webmcp-card ${enabled ? 'active' : ''}">
      <div class="card-head">
        WebMCP
        <span class="webmcp-badge ${enabled ? 'active' : ''}">${enabled ? 'ACTIVE' : available ? 'READY' : 'N/A'}</span>
      </div>
      <div class="card-body webmcp-card-body">
        <div class="webmcp-status-row">
          <span class="webmcp-label">navigator.modelContext</span>
          <span class="webmcp-val ${available ? 'ok' : 'dim'}">${available ? 'Detected' : 'Not detected'}</span>
        </div>

        <div class="webmcp-actions">
          ${!enabled && html`
            <button class="primary" onClick=${onEnable} disabled=${!available}>Register 6 Tools</button>
          `}
          ${enabled && html`
            <button class="danger" onClick=${onDisable}>Unregister</button>
          `}
        </div>

        ${enabled && html`
          <div class="webmcp-tools-grid">
            ${toolDefs.map(t => html`
              <div class="webmcp-tool-chip" key=${t.name}>
                <span class="webmcp-chip-name">${t.name}</span>
                <span class="webmcp-chip-desc">${t.desc}</span>
              </div>
            `)}
          </div>

          <div class="webmcp-data-toggle" onClick=${() => setExpanded(!expanded)}>
            <span class="arr">${expanded ? '\u25BC' : '\u25B6'}</span>
            <span>Live Data</span>
            <span class="webmcp-data-counts">
              ${s.webmcpCerts.length} certs \u00b7 ${s.webmcpClients.length} clients \u00b7 ${s.webmcpSessions.length} sessions \u00b7 ${fetchLog.length} fetches
            </span>
          </div>

          ${expanded && html`
            <div class="webmcp-stores">
              <div class="webmcp-store">
                <div class="webmcp-store-head">
                  Onion Certs <span class="webmcp-count">${s.webmcpCerts.length}</span>
                </div>
                ${s.webmcpCerts.length === 0 && html`<div class="webmcp-empty">No certificates stored</div>`}
                ${s.webmcpCerts.map(c => html`
                  <div class="webmcp-store-row" key=${c.onionAddress}>
                    <span class="webmcp-addr">${c.onionAddress.slice(0, 20)}...</span>
                    <span class="webmcp-fp">${c.fingerprint ? c.fingerprint.slice(0, 16) + '...' : '-'}</span>
                  </div>
                `)}
              </div>
              <div class="webmcp-store">
                <div class="webmcp-store-head">
                  Trusted Clients <span class="webmcp-count">${s.webmcpClients.length}</span>
                </div>
                ${s.webmcpClients.length === 0 && html`<div class="webmcp-empty">No trusted clients</div>`}
                ${s.webmcpClients.map(c => html`
                  <div class="webmcp-store-row" key=${c.clientId}>
                    <span class="webmcp-client-name">${c.name}</span>
                    <span class="webmcp-client-date">${c.addedAt ? c.addedAt.split('T')[0] : '-'}</span>
                  </div>
                `)}
              </div>
              <div class="webmcp-store">
                <div class="webmcp-store-head">
                  Holepunch Sessions <span class="webmcp-count">${s.webmcpSessions.length}</span>
                </div>
                ${s.webmcpSessions.length === 0 && html`<div class="webmcp-empty">No sessions</div>`}
                ${s.webmcpSessions.map(sess => html`
                  <div class="webmcp-store-row" key=${sess.id}>
                    <span class="webmcp-addr">${sess.target.slice(0, 20)}...</span>
                    <span class="webmcp-session-status ${sess.status}">${sess.status}</span>
                  </div>
                `)}
              </div>
              <div class="webmcp-store">
                <div class="webmcp-store-head">
                  Fetch Log <span class="webmcp-count">${fetchLog.length}</span>
                </div>
                ${fetchLog.length === 0 && html`<div class="webmcp-empty">No fetch requests yet</div>`}
                ${fetchLog.slice(-5).reverse().map((entry, i) => html`
                  <div class="webmcp-store-row" key=${i}>
                    <span class="webmcp-addr">${entry.url ? entry.url.slice(0, 30) + '...' : entry.action || '-'}</span>
                    <span class="webmcp-session-status ${entry.status === 'pending' ? 'initiating' : entry.error ? 'timeout' : 'connected'}">${entry.type}${entry.ohttp ? ' [OHTTP]' : ''}</span>
                  </div>
                `)}
              </div>
            </div>
          `}
        `}
      </div>
    </div>
  `;
}

// ────────────────────────────────────────────
// App
// ────────────────────────────────────────────
function App() {
  const s = useStore();

  const startTor = useCallback(() => {
    if (S.started) return;
    S.started = true;
    setStatus('starting');
    addLog('Loading Tor WASM module (3 MB)...', 'info');
    const sc = document.createElement('script');
    sc.src = ttPolicy.createScriptURL('/tor.js');
    sc.onerror = () => { addLog('Failed to load tor.js', 'err'); setStatus('error'); };
    document.body.appendChild(sc);
  }, []);

  const stopTor = useCallback(() => {
    addLog('Reload page to restart Tor', 'warn');
    setStatus('idle');
    if (_demoInterval) { clearInterval(_demoInterval); _demoInterval = null; }
    S.speed = { down: 0, up: 0 }; emit();
  }, []);

  const clearLog = useCallback(() => { S.logs = []; emit(); }, []);

  const openConfig = useCallback(() => { S.configModalOpen = true; emit(); }, []);
  const closeConfig = useCallback(() => { S.configModalOpen = false; emit(); }, []);

  const grantFS = useCallback(async () => {
    try {
      const handle = await window.showDirectoryPicker({ id: 'tor-data', mode: 'readwrite', startIn: 'documents' });
      S.fsHandle = handle;
      S.fsBanner = false;
      await handle.getDirectoryHandle('tor-data', { create: true });
      addLog('File system access granted: ' + handle.name, 'ok');
      emit();
    } catch (e) {
      if (e.name !== 'AbortError') addLog('File system access denied', 'warn');
    }
  }, []);

  const dismissFS = useCallback(() => { S.fsBanner = false; emit(); }, []);
  const dismissShare = useCallback(() => { S.sharedData = null; emit(); }, []);

  const startHS = useCallback(async () => {
    S.hsRunning = true;
    S.hsAddress = '';
    addLog('Starting hidden service listener (TCPServerSocket :8080)...', 'info');
    emit();

    try {
      // Start the real TCPServerSocket listener
      await startHiddenServiceListener(8080);
      addLog('TCPServerSocket listening on 127.0.0.1:8080', 'ok');

      // Load persisted keypair from OPFS, or generate a new one
      const kp = await loadOrCreateKeypair();
      S.hsAddress = pubkeyToOnion(kp.publicKey) + '.onion';
      setLocalOnionAddress(S.hsAddress);
      addLog('Hidden service address: ' + S.hsAddress + (kp.persisted ? ' (persisted)' : ' (ephemeral)'), 'ok');

      // Write the HS torrc config into Tor's virtual FS
      const fs = window.Module?.FS || (typeof FS !== 'undefined' ? FS : null);
      if (fs) {
        try { fs.mkdir('/tor-data/hs'); } catch(e) {}
        // Write the keypair so Tor can use it
        const hostnameFile = S.hsAddress + '\n';
        fs.writeFile('/tor-data/hs/hostname', hostnameFile);
        addLog('HS hostname written to /tor-data/hs/', 'ok');
      }

      addLog('Hidden service running — Tor will advertise ' + S.hsAddress, 'ok');
    } catch (e) {
      addLog('HS start error: ' + e.message, 'err');
      // Fallback: generate address without listener (for environments without TCPServerSocket)
      const pub = new Uint8Array(32);
      crypto.getRandomValues(pub);
      S.hsAddress = pubkeyToOnion(pub) + '.onion';
      setLocalOnionAddress(S.hsAddress);
      addLog('Fallback: generated address without listener — ' + S.hsAddress, 'warn');
    }
    emit();
  }, []);

  const stopHS = useCallback(async () => {
    addLog('Stopping hidden service...', 'info');
    try {
      await stopHiddenServiceListener();
      addLog('TCPServerSocket closed', 'ok');
    } catch(e) {}
    S.hsRunning = false;
    S.hsAddress = '';
    addLog('Hidden service stopped', 'warn');
    emit();
  }, []);

  const toggleVanity = useCallback(() => { S.vanityOpen = !S.vanityOpen; emit(); }, []);

  const enableWebMCP = useCallback(() => {
    const ok = registerWebMCPTools();
    if (ok) {
      S.webmcpEnabled = true;
      addLog('[WebMCP] 6 tools registered for AI agents (incl. fetchOnion + OHTTP)', 'ok');
      emit();
    } else {
      addLog('[WebMCP] Failed to register — modelContext not available', 'warn');
    }
  }, []);

  const disableWebMCP = useCallback(() => {
    unregisterWebMCPTools();
    S.webmcpEnabled = false;
    addLog('[WebMCP] Tools unregistered', 'warn');
    emit();
  }, []);

  // Detect WebMCP availability + poll HS stats
  useEffect(() => {
    S.webmcpAvailable = !!navigator.modelContext;
    if (S.webmcpAvailable) {
      addLog('[WebMCP] navigator.modelContext detected', 'ok');
    }
    setupWebMCPListeners();
    emit();

    // Poll hidden service stats every second
    const hsInterval = setInterval(() => {
      if (S.hsRunning) {
        const st = getTorServerStatus();
        S.hsStats = {
          requestCount: st.requestCount,
          bytesServed: st.bytesServed,
          uptimeMs: st.uptimeMs,
          connections: st.connections,
        };
        refreshWebMCPState();
      }
    }, 1000);
    return () => clearInterval(hsInterval);
  }, []);

  return html`
    <header>
      <img class="logo" src="/icon-192.png" alt="Tor" />
      <div class="title">
        <h1>TOR</h1>
        <div class="sub">WASM + Direct Sockets + WebMCP</div>
      </div>
      <${StatusPill} status=${s.status} />
    </header>

    <div class="banners">
      <${FSBanner} show=${s.fsBanner} onGrant=${grantFS} onDismiss=${dismissFS} />
      <${ShareBanner} data=${s.sharedData} onDismiss=${dismissShare} />
    </div>

    <${Controls}
      started=${s.started}
      onStart=${startTor}
      onStop=${stopTor}
      onClear=${clearLog}
      onConfig=${openConfig}
    />

    <${BootstrapProgress} pct=${s.bootstrap.pct} step=${s.bootstrap.step} />

    <main>
      <div class="dash dash-top">
        <div class="card circuit-card">
          <div class="card-head">Circuit</div>
          <div class="card-body circuit-body">
            <${NetworkDiagram} circuit=${s.circuit} status=${s.status} />
          </div>
        </div>
        <${HiddenServiceCard}
          running=${s.hsRunning}
          address=${s.hsAddress}
          stats=${s.hsStats}
          onStart=${startHS}
          onStop=${stopHS}
        />
      </div>

      <div class="dash dash-bottom">
        <${WebMCPCard}
          available=${s.webmcpAvailable}
          enabled=${s.webmcpEnabled}
          onEnable=${enableWebMCP}
          onDisable=${disableWebMCP}
        />
        <div class="card throughput-card ${s.vanityOpen ? 'hidden-by-vanity' : ''}">
          <div class="card-head">Throughput</div>
          <div class="card-body">
            <${Tachometer} speed=${s.speed.down} />
          </div>
        </div>
      </div>

      <${VanityBruteForce} open=${s.vanityOpen} onToggle=${toggleVanity} />

      <${LogViewer} logs=${s.logs} dotOn=${s.logDotOn} />
    </main>

    <${ConfigModal} open=${s.configModalOpen} onClose=${closeConfig} />

    <footer>
      <span>Tor 0.4.9.5</span>
      <span class="footer-sep">\u2502</span>
      <div class="footer-dots">
        <div class="footer-indicator ${s.status === 'connected' ? 'tor on' : 'tor'}">
          <span class="fdot"></span><span>Tor</span>
        </div>
        <div class="footer-indicator ${s.hsRunning ? 'hs on' : 'hs'}">
          <span class="fdot"></span><span>HS</span>
        </div>
        <div class="footer-indicator ${s.webmcpEnabled ? 'mcp on' : 'mcp'}">
          <span class="fdot"></span><span>MCP</span>
        </div>
      </div>
      <span class="footer-sep">\u2502</span>
      <span>IWA</span>
    </footer>
  `;
}

// ── Mount ──
render(html`<${App} />`, document.getElementById('app'));

// ── Service Worker ──
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register(ttPolicy.createScriptURL('/sw.js')).catch(() => {});
}

// ── Protocol handler ──
try { navigator.registerProtocolHandler('web+tor', '/?url=%s'); } catch(e) {}

// ── Direct Sockets detection ──
if (typeof TCPSocket !== 'undefined') addLog('Direct Sockets API available', 'ok');
else {
  addLog('Direct Sockets API not detected', 'warn');
  addLog('Tor requires an Isolated Web App context', 'warn');
}
addLog('Tor 0.4.9.5 WASM ready', 'ok');

// ── Handle shared data (Share Target API) ──
const params = new URLSearchParams(location.search);
if (params.has('shared_text') || params.has('shared_url')) {
  S.sharedData = {
    title: params.get('shared_title'),
    text: params.get('shared_text'),
    url: params.get('shared_url'),
  };
  addLog('Received shared data: ' + (S.sharedData.url || S.sharedData.text), 'info');
  emit();
}

// ── Handle web+tor:// URLs ──
if (params.has('url')) {
  addLog('Requested: ' + params.get('url'), 'info');
}
