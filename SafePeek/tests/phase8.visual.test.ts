import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeFile } from '../electron/analysis/analyzer';
import { contextFor, extractContent } from '../electron/content/extractor';
import { shutdownOcr } from '../electron/content/ocr';
import { LIMITS } from '../electron/content/limits';
import { classifyPayload } from '../electron/content/visual/qr';
import { assessThreat } from '../electron/threat';

const FIX = path.join(__dirname, 'fixtures');
let tmp: string; let cache: string;
beforeAll(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sp8-')); cache = path.join(tmp, 'ocr-cache'); });
afterAll(async () => { await shutdownOcr(); fs.rmSync(tmp, { recursive: true, force: true }); });

async function run(p: string, useCache = false) { const a = await analyzeFile(p); const c = await extractContent(contextFor(p, path.basename(p), fs.statSync(p).size, a, useCache ? { visualCacheDir: cache } : {})); return { a, c, t: assessThreat({ fileName: path.basename(p), analysis: a, content: c }) }; }
const fx = (n: string) => path.join(FIX, n);
const ruleIds = (t: ReturnType<typeof assessThreat>) => t.indicators.filter((i) => i.severity !== 'INFO').map((i) => i.ruleId);

describe('Phase 8 - standalone images (real local OCR)', () => {
  for (const ext of ['png', 'jpg', 'webp']) {
    it(`normal ${ext.toUpperCase()}: readable text, no false alarm`, async () => {
      const { c, t } = await run(fx(`test-normal-image.${ext}`));
      expect(c.status).toBe('COMPLETED'); expect(c.visual?.ocrStatus).toBe('COMPLETED'); expect(c.ocrText).toMatch(/lunch/i); expect(t.status).toBe('SAFE');
    }, 90_000);
    it(`phishing ${ext.toUpperCase()}: OCR text reaches the EXISTING threat engine and extracts the URL`, async () => {
      const { c, t } = await run(fx(`test-phishing-image.${ext}`));
      expect(c.ocrText).toMatch(/suspended/i); expect(c.ocrText).toMatch(/password/i);
      expect(c.links.map((l) => l.url)).toContain('https://secure-login.account-verify.example.test/verify');
      expect(['HIGH_RISK', 'CRITICAL']).toContain(t.status); expect(ruleIds(t)).toEqual(expect.arrayContaining(['CONTENT_URGENT_CREDENTIALS', 'CORR_CREDENTIAL_LURE_URL']));
      expect(t.indicators.find((i) => i.ruleId === 'CONTENT_URGENT_CREDENTIALS')!.origins).toEqual(['OCR']);
      expect(t.engineVersion).toBe('5.1.0'); expect(t.executionPerformed).toBe(false); expect(t.uploaded).toBe(false);
    }, 90_000);
  }
  it('large image is downsampled, not skipped, and OCR still reads it quickly', async () => {
    const t0 = Date.now(); const { c } = await run(fx('test-large-image.png'));
    expect(c.status).toBe('COMPLETED'); expect(c.visual?.downscaled).toBe(true); expect(c.ocrText).toMatch(/budget|planning/i); expect(Date.now() - t0).toBeLessThan(40_000);
    expect(c.extractionWarnings.join(' ')).toMatch(/reduced in size/);
  }, 90_000);
  it('corrupt image: PARTIAL, OCR FAILED, risk UNKNOWN (never SAFE), no crash', async () => {
    const { c, t } = await run(fx('test-corrupt-image.png'));
    expect(c.status).toBe('PARTIAL'); expect(c.visual?.ocrStatus).toBe('FAILED'); expect(t.status).toBe('UNKNOWN'); expect(t.analysisComplete).toBe(false);
    expect(c.extractionWarnings.join(' ')).toMatch(/could not be decoded/);
  }, 60_000);
  it('pixel bomb header: OCR skipped, PARTIAL, limit recorded, never SAFE', async () => {
    const hdr = Buffer.alloc(40); Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(hdr); hdr.writeUInt32BE(12000, 16); hdr.writeUInt32BE(12000, 20);
    const p = path.join(tmp, 'bomb.png'); fs.writeFileSync(p, hdr); const { c, t } = await run(p);
    expect(c.status).toBe('PARTIAL'); expect(c.visual?.ocrStatus).toBe('PARTIAL'); expect(c.visual?.limitsHit.length).toBeGreaterThan(0); expect(c.ocrText).toBeUndefined(); expect(t.status).toBe('UNKNOWN');
    expect(c.extractionWarnings.join(' ')).toMatch(/could not be fully analyzed/);
  });
});

describe('Phase 8 - QR codes', () => {
  it('HTTPS URL: decoded, never opened, analyzed by the existing URL analyzer', async () => {
    const { c, t } = await run(fx('test-qr-benign.png'));
    expect(c.visual!.qrCodes).toHaveLength(1); expect(c.visual!.qrCodes[0]).toMatchObject({ kind: 'url', url: 'https://menu.example.org/lunch' });
    expect(c.links.some((l) => l.source.startsWith('QR code'))).toBe(true); expect(t.status).toBe('SAFE'); expect(t.indicators.some((i) => i.ruleId === 'VISUAL_QR_PRESENT')).toBe(true);
  }, 60_000);
  it('suspicious URL + credential wording: CRITICAL/HIGH, evidence tagged QR and OCR, cross-modal correlation', async () => {
    const { c, t } = await run(fx('test-qr-phishing.png'));
    expect(c.visual!.qrCodes[0].url).toBe('https://paypal-secure-login.example.test/verify/account');
    expect(['HIGH_RISK', 'CRITICAL']).toContain(t.status);
    expect(t.indicators.find((i) => i.ruleId === 'URL_BRAND_LOOKALIKE')!.origins).toEqual(['QR']);
    expect(t.indicators.find((i) => i.ruleId === 'CONTENT_URGENT_CREDENTIALS')!.origins).toContain('OCR');
    expect(ruleIds(t)).toContain('CORR_CROSS_MODAL_LURE_URL'); expect(t.evidence.some((e) => e.origin === 'QR')).toBe(true);
  }, 60_000);
  it('plain-text QR payload is shown as text (and not treated as a link)', async () => {
    const { c } = await run(fx('test-qr-text.png')); expect(c.visual!.qrCodes[0]).toMatchObject({ kind: 'text', payload: 'Just some plain text in a QR code' }); expect(c.links.filter((l) => l.source.startsWith('QR'))).toHaveLength(0);
  }, 60_000);
  it('non-HTTP payload (wifi:) is displayed only, never analyzed as a link, no scary warning', async () => {
    const { c, t } = await run(fx('test-qr-wifi.png')); const q = c.visual!.qrCodes[0];
    expect(q.kind).toBe('wifi'); expect(q.url).toBeUndefined(); expect(c.links).toHaveLength(0); expect(t.status).toBe('SAFE'); expect(t.indicators.some((i) => i.ruleId === 'VISUAL_QR_NON_WEB' && i.severity === 'INFO')).toBe(true);
  }, 60_000);
  it('several QR codes in one image are all found', async () => {
    const { c } = await run(fx('test-qr-multi.png')); expect(c.visual!.qrCodes.map((q) => q.url).sort()).toEqual(['https://one.example.org/a', 'https://two-secure-login.example.test/verify']);
  }, 60_000);
  it('an image with no QR code: empty list, no warning', async () => {
    const { c } = await run(fx('test-normal-image.png')); expect(c.visual!.qrCodes).toEqual([]); expect(c.visual!.sources.qr).toBe(false);
  }, 60_000);
  it('invalid / garbled QR (noise) decodes to nothing without throwing', async () => {
    const sharp = require('sharp'); const p = path.join(tmp, 'noise.png');
    await sharp({ create: { width: 400, height: 400, channels: 3, noise: { type: 'gaussian', mean: 128, sigma: 60 } } }).png().toFile(p);
    const { c } = await run(p); expect(c.visual!.qrCodes).toEqual([]); expect(['COMPLETED', 'PARTIAL']).toContain(c.status);
  }, 60_000);
  it('payload classification: schemes are labelled and never invoked; control characters stripped', () => {
    expect(classifyPayload('mailto:a@b.example', 1, 'image').kind).toBe('email'); expect(classifyPayload('tel:+10000000', 1, 'image').kind).toBe('phone');
    expect(classifyPayload('javascript:alert(1)', 1, 'image')).toMatchObject({ kind: 'other-scheme', scheme: 'javascript' }); expect(classifyPayload('javascript:alert(1)', 1, 'image').url).toBeUndefined();
    expect(classifyPayload('example.org/path', 1, 'image')).toMatchObject({ kind: 'url', schemeAssumed: true, url: 'https://example.org/path' });
    expect(classifyPayload('hello\u0000 \u202eworld', 1, 'image').payload).not.toMatch(/[\u0000\u202e]/);
    expect(classifyPayload('x'.repeat(5000), 1, 'image')).toMatchObject({ truncated: true });
    expect(LIMITS.MAX_QR_PAYLOAD_CHARS).toBe(2000);
  });
});

describe('Phase 8 - PDFs (direct text, scanned, mixed)', () => {
  it('normal text PDF: no OCR needed, no visual noise', async () => {
    const { c, t } = await run(fx('test-text-only.pdf')); expect(c.status).toBe('COMPLETED'); expect(c.visual?.ocrStatus).toBe('NOT_ATTEMPTED'); expect(c.visual?.pdfKind).toBe('TEXT'); expect(c.ocrText).toBeUndefined(); expect(t.status).toBe('SAFE');
  }, 60_000);
  it('image-only PDF: detected as IMAGE_ONLY, read with OCR page by page, text enters the threat engine', async () => {
    const { c, t } = await run(fx('test-scanned-phishing.pdf'));
    expect(c.extractedText!.trim()).toBe(''); expect(c.visual).toMatchObject({ pdfKind: 'IMAGE_ONLY', ocrStatus: 'COMPLETED', ocrPages: [1] }); expect(c.pages![0].source).toBe('ocr');
    expect(c.ocrText).toMatch(/suspended/i); expect(c.links.map((l) => l.url)).toContain('https://secure-login.account-verify.example.test/verify');
    expect(['HIGH_RISK', 'CRITICAL']).toContain(t.status); expect(t.indicators.find((i) => i.ruleId === 'CONTENT_URGENT_CREDENTIALS')!.origins).toEqual(['OCR']);
    expect(c.executionPerformed).toBe(false); expect(c.uploaded).toBe(false);
  }, 90_000);
  it('normal scanned document: OCR completes, nothing flagged', async () => {
    const { c, t } = await run(fx('test-normal-scanned-document.pdf')); expect(c.status).toBe('COMPLETED'); expect(c.visual!.ocrPages).toEqual([1, 2]); expect(c.ocrText).toMatch(/lunch/i); expect(t.status).toBe('SAFE');
  }, 90_000);
  it('mixed PDF: text pages keep direct text, only the image pages are OCR\'d, sources are distinguished', async () => {
    const { c, t } = await run(fx('test-mixed-phishing.pdf'));
    expect(c.visual).toMatchObject({ pdfKind: 'MIXED', ocrPages: [2, 4], ocrStatus: 'COMPLETED' }); expect(c.pages!.map((p) => p.source)).toEqual(['text', 'ocr', 'text', 'ocr']);
    expect(c.extractedText).toMatch(/normal selectable text/); expect(c.ocrText).toMatch(/password/i); expect(c.visual!.sources).toMatchObject({ directText: true, ocrText: true });
    expect(['HIGH_RISK', 'CRITICAL']).toContain(t.status);
  }, 90_000);
  it('PDF with a QR image: QR decoded from the embedded image, URL analyzed, attributed to the QR code', async () => {
    const { c, t } = await run(fx('test-pdf-qr.pdf')); expect(c.visual!.qrCodes[0]).toMatchObject({ kind: 'url', location: 'page 2' });
    expect(t.indicators.find((i) => i.ruleId === 'URL_BRAND_LOOKALIKE')!.origins).toEqual(['QR']); expect(['SUSPICIOUS', 'HIGH_RISK', 'CRITICAL']).toContain(t.status);
  }, 60_000);
  it('too many scanned pages: first 10 are OCR\'d, the rest reported as a limit -> PARTIAL, never SAFE', async () => {
    const { c, t } = await run(fx('test-multipage-scanned.pdf'));
    expect(c.visual!.ocrPages).toHaveLength(LIMITS.MAX_PDF_OCR_PAGES); expect(c.status).toBe('PARTIAL'); expect(c.visual!.ocrStatus).toBe('PARTIAL');
    expect(c.visual!.limitsHit.join(' ')).toMatch(/more page\(s\) needed OCR/); expect(c.extractionWarnings.join(' ')).toMatch(/could not be fully analyzed/);
    expect(t.status).toBe('UNKNOWN'); expect(t.coverage.notes.join(' ')).toMatch(/visual content could not be fully analyzed/);
  }, 120_000);
  it('opening a PDF for OCR never follows actions or URLs (embedded JS/OpenAction stay data)', async () => {
    const js = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n');
    const p = path.join(tmp, 'active.pdf'); fs.writeFileSync(p, js); const { c } = await run(p); expect(c.executionPerformed).toBe(false); expect(c.embeddedContentWarning).toBe(true);
  }, 60_000);
});

describe('Phase 8 - evidence de-duplication across extraction paths', () => {
  it('the same phrases in PDF text AND in an image count once (same score as the image alone) and carry both origins', async () => {
    const both = await run(fx('test-pdf-text-and-same-ocr.pdf')); const img = await run(fx('test-scanned-phishing.pdf'));
    expect(both.t.score).toBe(img.t.score);
    expect(both.t.indicators.find((i) => i.ruleId === 'CONTENT_URGENT_CREDENTIALS')!.origins!.sort()).toEqual(['OCR', 'TEXT']);
    expect(ruleIds(both.t).filter((r) => r === 'CONTENT_URGENT_CREDENTIALS')).toHaveLength(1); expect(ruleIds(both.t)).not.toContain('CORR_CROSS_MODAL_LURE_URL');
    expect(both.c.links.filter((l) => /secure-login/.test(l.url))).toHaveLength(1);
  }, 90_000);
});

describe('Phase 8 - cache keyed by SHA-256', () => {
  it('second analysis of the same bytes is a cache hit (no repeated OCR); changed bytes are not', async () => {
    const p = path.join(tmp, 'cached.png'); fs.copyFileSync(fx('test-phishing-image.png'), p);
    const first = await run(p, true); expect(first.c.visual!.cacheHit).toBe(false);
    const second = await run(p, true); expect(second.c.visual!.cacheHit).toBe(true); expect(second.c.ocrText).toBe(first.c.ocrText); expect(second.t.score).toBe(first.t.score);
    fs.copyFileSync(fx('test-normal-image.png'), p); const third = await run(p, true); expect(third.c.visual!.cacheHit).toBe(false); expect(third.c.ocrText).toMatch(/lunch/i);
    const pdf1 = await run(fx('test-mixed-phishing.pdf'), true); const pdf2 = await run(fx('test-mixed-phishing.pdf'), true); expect(pdf1.c.visual!.cacheHit).toBe(false); expect(pdf2.c.visual!.cacheHit).toBe(true); expect(pdf2.c.visual!.ocrPages).toEqual([2, 4]);
    expect(fs.readdirSync(cache).every((n) => /^[a-f0-9]{64}\.json$/.test(n))).toBe(true);
  }, 120_000);
});
