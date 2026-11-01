#!/usr/bin/env node
/**
 * Runs the compiled OCR / QR / PDF pipeline under ELECTRON'S OWN runtime (not plain Node) against the synthetic fixtures.
 * Why: tesseract.js behaves differently when process.versions.electron is set; a plain-Node test run cannot catch that.
 * Usage:  npm run build:electron && npm run verify:ocr        (works on Windows, macOS, Linux)
 */
const { spawnSync } = require('node:child_process'); const path = require('node:path'); const fs = require('node:fs');
const root = path.join(__dirname, '..');
const electron = require('electron'); // path to the electron binary
const inner = `
const path = require('path'), fs = require('fs'); const root = ${JSON.stringify(root)};
const { analyzeFile } = require(path.join(root, 'dist-electron/analysis/analyzer'));
const { contextFor, extractContent } = require(path.join(root, 'dist-electron/content/extractor'));
const { shutdownOcr } = require(path.join(root, 'dist-electron/content/ocr'));
const checks = [
  ['test-phishing-image.png', (r) => /suspended/i.test(r.ocrText || '')],
  ['test-phishing-image.webp', (r) => /password/i.test(r.ocrText || '')],
  ['test-qr-phishing.png', (r) => r.visual.qrCodes.length === 1 && /suspended|invoice|payment/i.test(r.ocrText || '')],
  ['test-scanned-phishing.pdf', (r) => r.visual.pdfKind === 'IMAGE_ONLY' && /suspended/i.test(r.ocrText || '')],
  ['test-mixed-phishing.pdf', (r) => JSON.stringify(r.visual.ocrPages) === '[2,4]'],
  ['test-large-image.png', (r) => r.visual.downscaled === true && /planning|budget/i.test(r.ocrText || '')]
];
(async () => {
  let bad = 0; console.log('runtime: node ' + process.versions.node + ', electron ' + process.versions.electron);
  for (const [f, ok] of checks) {
    const p = path.join(root, 'tests/fixtures', f); const t = Date.now();
    try { const r = await extractContent(contextFor(p, f, fs.statSync(p).size, await analyzeFile(p), {})); const pass = r.status === 'COMPLETED' && ok(r); if (!pass) bad++;
      console.log((pass ? 'PASS ' : 'FAIL ') + f + '  status=' + r.status + ' ocr=' + (r.visual && r.visual.ocrStatus) + '  ' + ((Date.now() - t) / 1000).toFixed(1) + 's'); }
    catch (e) { bad++; console.log('FAIL ' + f + '  ' + e.message); }
  }
  await shutdownOcr(); console.log(bad ? bad + ' check(s) FAILED' : 'ALL CHECKS PASSED'); process.exit(bad ? 1 : 0);
})();`;
if (!fs.existsSync(path.join(root, 'dist-electron/content/extractor.js'))) { console.error('Run "npm run build:electron" first.'); process.exit(2); }
const r = spawnSync(electron, ['-e', inner], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 600000, encoding: 'utf8' });
process.stdout.write((r.stdout || '').split('\n').filter((l) => /^(runtime|PASS|FAIL|ALL|\d+ check)/.test(l)).join('\n') + '\n');
process.exit(r.status ?? 1);
