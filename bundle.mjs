#!/usr/bin/env node
// Bundle the Tor IWA into a Signed Web Bundle (.swbn)
// Uses wbn (via webbundle-webpack-plugin) for bundle building
// and wbn-sign for integrity block signing.
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { createRequire } from 'module';

// wbn-sign is ESM
import { NodeCryptoSigningStrategy, IntegrityBlockSigner, WebBundleId } from 'wbn-sign';

// wbn is CJS (installed as dep of webbundle-webpack-plugin)
const require = createRequire(import.meta.url);
const { BundleBuilder } = require('wbn');

const PUBLIC_DIR = path.resolve('iwa/public');
const OUT_DIR = path.resolve('dist');
const KEY_FILE = path.resolve('iwa-signing-key.pem');

// ── Generate or load Ed25519 key ──
let privateKey;
if (fs.existsSync(KEY_FILE)) {
  console.log('Loading existing signing key...');
  privateKey = crypto.createPrivateKey(fs.readFileSync(KEY_FILE, 'utf8'));
} else {
  console.log('Generating new Ed25519 signing key...');
  const kp = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(KEY_FILE, kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  privateKey = kp.privateKey;
  console.log('Key saved to', KEY_FILE);
}

// ── Derive App ID (as string, not object) ──
const webBundleId = new WebBundleId(privateKey);
const appId = webBundleId.serialize();
const iwaOrigin = webBundleId.serializeWithIsolatedWebAppOrigin();
console.log('');
console.log('App ID:', appId);
console.log('IWA Origin:', iwaOrigin);
console.log('');

// ── Collect files ──
function walkDir(dir, base = '') {
  const entries = [];
  for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = path.join(base, f.name);
    const full = path.join(dir, f.name);
    if (f.isDirectory()) entries.push(...walkDir(full, rel));
    else entries.push({ rel: '/' + rel.replace(/\\/g, '/'), full });
  }
  return entries;
}

const files = walkDir(PUBLIC_DIR);
console.log(`Bundling ${files.length} files from ${PUBLIC_DIR}`);

// ── MIME types ──
const MIME = {
  '.html': 'text/html', '.js': 'application/javascript', '.mjs': 'application/javascript',
  '.wasm': 'application/wasm', '.json': 'application/json', '.png': 'image/png',
  '.svg': 'image/svg+xml', '.css': 'text/css', '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};
const getMime = f => MIME[path.extname(f).toLowerCase()] || 'application/octet-stream';

// ── Build unsigned bundle ──
const baseUrl = iwaOrigin.replace(/\/$/, '');
const builder = new BundleBuilder();
// IWAs must NOT have a primaryURL in the bundle metadata

for (const { rel, full } of files) {
  const body = fs.readFileSync(full);
  builder.addExchange(baseUrl + rel, 200, { 'content-type': getMime(full) }, body);
  console.log('  +', rel, `(${body.length} bytes)`);
}

// '/' → index.html alias
const indexBody = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'));
builder.addExchange(baseUrl + '/', 200, { 'content-type': 'text/html' }, indexBody);
console.log('  + / (alias for /index.html)');

const unsignedBundle = builder.createBundle();
console.log(`\nUnsigned bundle: ${unsignedBundle.length} bytes`);

// ── Sign (pass webBundleId as serialized STRING, not the object) ──
const strategy = new NodeCryptoSigningStrategy(privateKey);
const signer = new IntegrityBlockSigner(
  unsignedBundle,
  appId,           // <-- string, not WebBundleId object
  [strategy]
);

const { signedWebBundle } = await signer.sign();
console.log(`Signed bundle: ${signedWebBundle.length} bytes`);

// ── Write output ──
fs.mkdirSync(OUT_DIR, { recursive: true });
const outPath = path.join(OUT_DIR, 'tor.swbn');
fs.writeFileSync(outPath, signedWebBundle);
fs.writeFileSync(path.join(OUT_DIR, 'app-id.txt'), `App ID: ${appId}\nIWA Origin: ${iwaOrigin}\n`);

console.log(`\nWritten to: ${outPath}`);
console.log(`Size: ${(signedWebBundle.length / 1048576).toFixed(2)} MB`);
console.log('\n=== Install in Chrome ===');
console.log('1. chrome://web-app-internals');
console.log('2. "Install IWA from Signed Web Bundle"');
console.log(`3. Select: ${outPath}`);
