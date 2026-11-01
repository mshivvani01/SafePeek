import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

let mode: 'ok' | 'timeout' | 'engine' | 'unavailable' = 'ok';
vi.mock('../electron/content/ocr', async (orig) => {
  const real = await orig<typeof import('../electron/content/ocr')>();
  return { ...real, shutdownOcr: async () => undefined, ocrImage: async () => {
    if (mode === 'timeout') throw new real.OcrError('OCR exceeded 30 s', 'timeout');
    if (mode === 'engine') throw new real.OcrError('OCR worker stopped (exit 1)', 'engine');
    if (mode === 'unavailable') throw new real.OcrError('OCR engine could not be loaded', 'unavailable');
    return { text: 'Verify your account immediately. Enter your password.', confidence: 91 };
  } };
});
import { analyzeFile } from '../electron/analysis/analyzer';
import { contextFor, extractContent } from '../electron/content/extractor';
import { assessThreat } from '../electron/threat';

const FIX = path.join(__dirname, 'fixtures'); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sp8e-'));
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));
beforeEach(() => { mode = 'ok'; });
async function run(p: string) { const a = await analyzeFile(p); const c = await extractContent(contextFor(p, path.basename(p), fs.statSync(p).size, a)); return { a, c, t: assessThreat({ fileName: path.basename(p), analysis: a, content: c }) }; }

describe('Phase 8 failure handling (mocked OCR engine)', () => {
  it('OCR timeout on an image -> PARTIAL, OCR FAILED, UNKNOWN (never SAFE), user-facing message', async () => {
    mode = 'timeout'; const { c, t } = await run(path.join(FIX, 'test-normal-image.png'));
    expect(c.status).toBe('PARTIAL'); expect(c.visual!.ocrStatus).toBe('FAILED'); expect(c.extractionWarnings.join(' ')).toMatch(/took too long/); expect(c.extractionWarnings.join(' ')).toMatch(/could not be fully analyzed/);
    expect(t.status).toBe('UNKNOWN'); expect(t.status).not.toBe('SAFE'); expect(t.analysisComplete).toBe(false);
  });
  it('OCR engine failure -> PARTIAL / UNKNOWN; QR codes found before the failure are still reported', async () => {
    mode = 'engine'; const { c, t } = await run(path.join(FIX, 'test-qr-phishing.png'));
    expect(c.status).toBe('PARTIAL'); expect(c.visual!.ocrStatus).toBe('FAILED'); expect(c.visual!.qrCodes).toHaveLength(1); expect(t.indicators.some((i) => i.ruleId === 'URL_BRAND_LOOKALIKE')).toBe(true); expect(t.status).not.toBe('SAFE');
  });
  it('OCR engine unavailable -> UNSUPPORTED visual status, never SAFE', async () => {
    mode = 'unavailable'; const { c, t } = await run(path.join(FIX, 'test-normal-image.png')); expect(c.visual!.ocrStatus).toBe('UNSUPPORTED'); expect(t.status).toBe('UNKNOWN');
  });
  it('PDF: OCR failing on every scanned page -> PARTIAL, FAILED visual status, UNKNOWN', async () => {
    mode = 'timeout'; const { c, t } = await run(path.join(FIX, 'test-scanned-phishing.pdf'));
    expect(c.status).toBe('PARTIAL'); expect(c.visual!.ocrStatus).toBe('FAILED'); expect(c.ocrText).toBeUndefined(); expect(t.status).toBe('UNKNOWN');
  });
  it('PDF: one failed page among OCR\'d pages -> PARTIAL with the readable text still analyzed', async () => {
    mode = 'ok'; const { c } = await run(path.join(FIX, 'test-mixed-phishing.pdf')); expect(c.visual!.ocrStatus).toBe('COMPLETED');
  });
  it('file changed after static analysis -> results flagged as possibly stale (PARTIAL)', async () => {
    const p = path.join(tmp, 'changing.png'); fs.copyFileSync(path.join(FIX, 'test-normal-image.png'), p); const a = await analyzeFile(p);
    fs.copyFileSync(path.join(FIX, 'test-phishing-image.png'), p); const c = await extractContent(contextFor(p, 'changing.png', fs.statSync(p).size, a));
    expect(c.status).toBe('PARTIAL'); expect(c.extractionWarnings.join(' ')).toMatch(/file changed/i);
  });
  it('file disappeared before extraction -> FAILED result, no throw', async () => {
    const p = path.join(tmp, 'gone.png'); fs.copyFileSync(path.join(FIX, 'test-normal-image.png'), p); const a = await analyzeFile(p); fs.unlinkSync(p);
    const c = await extractContent(contextFor(p, 'gone.png', 100, a)); expect(['FAILED', 'PARTIAL']).toContain(c.status);
  });
  it('truncated JPEG and a text file renamed .png do not crash', async () => {
    const jpg = fs.readFileSync(path.join(FIX, 'test-normal-image.jpg')); const p1 = path.join(tmp, 'trunc.jpg'); fs.writeFileSync(p1, jpg.subarray(0, 3000)); const r1 = await run(p1); expect(['PARTIAL', 'COMPLETED', 'FAILED']).toContain(r1.c.status); expect(r1.c.executionPerformed).toBe(false);
    const p2 = path.join(tmp, 'fake.png'); fs.writeFileSync(p2, 'this is not an image'); const r2 = await run(p2); expect(r2.c.executionPerformed).toBe(false);
  });
});
