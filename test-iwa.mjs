#!/usr/bin/env node
// Test harness: launches Chrome, installs the IWA, captures console output.
// Usage: node test-iwa.mjs [--timeout 30]
import puppeteer from 'puppeteer';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const args = process.argv.slice(2);
let TIMEOUT = 30;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--timeout' && args[i+1]) TIMEOUT = parseInt(args[++i]);
}

const appIdText = readFileSync(path.join(__dirname, 'dist/app-id.txt'), 'utf8');
const APP_ID = appIdText.match(/App ID: (.+)/)[1].trim();
const SWBN_PATH = path.resolve(__dirname, 'dist/tor.swbn');
const MANIFEST_ID = `isolated-app://${APP_ID}`;
const CHROME_PATH = process.env.CHROME_PATH || '/usr/bin/google-chrome-stable';

console.log(`App ID:  ${APP_ID}`);
console.log(`SWBN:    ${SWBN_PATH}`);
console.log(`Timeout: ${TIMEOUT}s\n`);

const logs = [];
let hasError = false;
let bootstrapPercent = 0;

function onLog(source, text) {
  if (!text || text === 'undefined') return;
  logs.push({ source, text, time: Date.now() });
  console.log(`[${source}] ${text}`);
  const m = text.match(/Bootstrapped (\d+)%/);
  if (m) bootstrapPercent = parseInt(m[1]);
  if (text.includes('assertion_failed') || text.includes('Aborted()')
      || text.includes('Aborted().')) hasError = true;
}

let browser;
try {
  browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: 'new',
    args: [
      '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode',
      '--no-first-run', '--no-default-browser-check',
      '--disable-default-apps', '--disable-extensions',
      '--no-sandbox',
    ],
    pipe: true,
    timeout: 30000,
  });

  const session = await browser.target().createCDPSession();

  // Auto-attach to ALL targets (workers, iframes, etc.) to capture their console
  await session.send('Target.setAutoAttach', {
    autoAttach: true,
    waitForDebuggerOnStart: false,
    flatten: true,
  });

  // Listen for attached targets and enable their Runtime
  session.on('Target.attachedToTarget', async (event) => {
    const { sessionId, targetInfo } = event;
    try {
      // Create a session for this target to capture its console
      const childSession = browser._connection._sessions.get(sessionId);
      if (!childSession) return;

      await childSession.send('Runtime.enable');

      childSession.on('Runtime.consoleAPICalled', (evt) => {
        const text = evt.args.map(a => a.value || a.description || '').join(' ');
        onLog(`worker-${targetInfo.type}`, text);
      });

      childSession.on('Runtime.exceptionThrown', (evt) => {
        const desc = evt.exceptionDetails?.exception?.description ||
                     evt.exceptionDetails?.text || 'unknown';
        onLog(`worker-exception`, desc);
      });
    } catch (e) { /* some targets don't support Runtime */ }
  });

  // Install + launch the IWA
  console.log('Installing IWA...');
  await session.send('PWA.install', {
    manifestId: MANIFEST_ID,
    installUrlOrBundleUrl: `file://${SWBN_PATH}`,
  });

  console.log('Launching IWA...');
  const { targetId } = await session.send('PWA.launch', {
    manifestId: MANIFEST_ID,
  });

  const target = await browser.waitForTarget(
    t => t.url().startsWith('isolated-app://'),
    { timeout: 15000 }
  );
  const page = await target.page();
  console.log(`Page: ${page.url()}\n`);

  // Capture page-level console and errors
  page.on('console', msg => onLog('page', msg.text()));
  page.on('pageerror', err => {
    onLog('pageerror', err.message);
    hasError = true;
  });

  // Also use CDP on the page for Runtime events
  const cdpPage = await page.createCDPSession();
  await cdpPage.send('Runtime.enable');
  await cdpPage.send('Log.enable');

  cdpPage.on('Runtime.consoleAPICalled', (event) => {
    const text = event.args.map(a => a.value || a.description || '').join(' ');
    onLog(`cdp-${event.type}`, text);
  });

  cdpPage.on('Runtime.exceptionThrown', (event) => {
    const desc = event.exceptionDetails?.exception?.description ||
                 event.exceptionDetails?.text || 'unknown';
    onLog('cdp-exception', desc);
  });

  cdpPage.on('Log.entryAdded', (event) => {
    onLog(`log-${event.entry.level}`, event.entry.text || '');
  });

  // Click Start Tor button
  await new Promise(r => setTimeout(r, 2000));
  console.log('Clicking Start Tor...');
  const clicked = await page.evaluate(() => {
    for (const b of document.querySelectorAll('button')) {
      if (b.textContent.includes('Start Tor')) { b.click(); return b.textContent; }
    }
    return null;
  });
  console.log('Clicked:', clicked || 'NONE FOUND');

  // After clicking start, a web worker for Tor will be created.
  // Wait and then try to capture from any new targets (workers).
  await new Promise(r => setTimeout(r, 1000));

  // Enumerate all targets and try to attach to workers
  for (const target of browser.targets()) {
    if (target.type() === 'worker' || target.type() === 'shared_worker'
        || target.type() === 'service_worker') {
      try {
        const w = await target.worker();
        if (w) {
          console.log('Found worker:', target.url());
          w.on('console', msg => onLog('wrkr', msg.text()));
        }
      } catch(e) {}
    }
  }

  // Also: monitor the page's in-app log by polling the DOM
  const pollAppLog = setInterval(async () => {
    try {
      const newLogs = await page.evaluate(() => {
        const lines = document.querySelectorAll('.ll-msg');
        return Array.from(lines).map(l => l.textContent).slice(-20);
      });
      for (const line of newLogs) {
        if (!logs.some(l => l.text === line)) {
          onLog('app', line);
        }
      }
    } catch(e) {} // page might be closed
  }, 1000);

  console.log('\n=== Output ===');

  const startTime = Date.now();
  while (Date.now() - startTime < TIMEOUT * 1000) {
    await new Promise(r => setTimeout(r, 1000));
    if (hasError) {
      console.log('\n--- Error detected, collecting remaining output ---');
      await new Promise(r => setTimeout(r, 3000));
      break;
    }
    if (bootstrapPercent >= 100) {
      console.log('\n--- Bootstrap complete! ---');
      break;
    }
  }

  // ── Test hidden service start ──
  if (bootstrapPercent >= 100 && !hasError) {
    console.log('\n=== Testing Hidden Service ===');

    // Click "Start Service" button
    const hsClicked = await page.evaluate(() => {
      for (const b of document.querySelectorAll('button')) {
        if (b.textContent.includes('Start Service')) { b.click(); return true; }
      }
      return false;
    });
    console.log('HS Start clicked:', hsClicked);

    // Wait for HS to initialize
    await new Promise(r => setTimeout(r, 3000));

    // Check if .onion address was generated
    const hsStatus = await page.evaluate(() => {
      const glow = document.querySelector('.onion-glow');
      const text = glow ? glow.textContent : '';
      return {
        address: text,
        hasOnion: text.endsWith('.onion') && text.length > 20,
      };
    });
    console.log('HS Address:', hsStatus.address);
    console.log('HS Valid:  ', hsStatus.hasOnion);

    if (!hsStatus.hasOnion) {
      onLog('test', 'FAIL: Hidden service did not generate .onion address');
      hasError = true;
    }

    // Check TCPServerSocket listener status from logs
    const hsLogs = logs.filter(l =>
      l.text.includes('TCPServerSocket') || l.text.includes('Hidden service')
    );
    console.log(`HS Logs:    ${hsLogs.length}`);
    hsLogs.forEach(l => console.log(`  [${l.source}] ${l.text}`));

    // ── Test WebMCP tool availability ──
    console.log('\n=== Testing WebMCP ===');
    const webmcpStatus = await page.evaluate(() => {
      return {
        modelContextAvailable: !!navigator.modelContext,
        directSocketsAvailable: typeof TCPSocket !== 'undefined',
        serverSocketAvailable: typeof TCPServerSocket !== 'undefined',
      };
    });
    console.log('modelContext:', webmcpStatus.modelContextAvailable);
    console.log('TCPSocket:  ', webmcpStatus.directSocketsAvailable);
    console.log('TCPServerSocket:', webmcpStatus.serverSocketAvailable);

    if (!webmcpStatus.directSocketsAvailable) {
      console.log('WARN: TCPSocket not available (expected in IWA context)');
    }
    if (!webmcpStatus.serverSocketAvailable) {
      console.log('WARN: TCPServerSocket not available (expected in IWA context)');
    }
  }

  console.log(`\n=== Summary ===`);
  console.log(`Duration:   ${((Date.now() - startTime) / 1000).toFixed(1)}s`);
  console.log(`Bootstrap:  ${bootstrapPercent}%`);
  console.log(`Errors:     ${hasError}`);
  console.log(`Log lines:  ${logs.length}`);

  const traces = logs.filter(l => l.text.includes('TRACE'));
  if (traces.length) {
    console.log(`\n=== TRACE (${traces.length}) ===`);
    traces.forEach(l => console.log(`  ${l.text}`));
  }

  const errs = logs.filter(l =>
    l.text.includes('assertion') || l.text.includes('Abort') ||
    l.text.includes('INVALID') || l.source === 'pageerror');
  if (errs.length) {
    console.log(`\n=== Errors (${errs.length}) ===`);
    errs.forEach(l => console.log(`  [${l.source}] ${l.text}`));
  }

  clearInterval(pollAppLog);
  try { await session.send('PWA.uninstall', { manifestId: MANIFEST_ID }); }
  catch (e) { /* ok */ }

  process.exit(hasError ? 1 : 0);
} catch (e) {
  console.error('Fatal:', e);
  process.exit(2);
} finally {
  if (browser) try { await browser.close(); } catch(e) {}
}
