import { afterAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MonitoringAgent } from '../electron/agent/agent';
import { StateStore } from '../electron/agent/store';
import { AnalysisService } from '../electron/analysis/service';
import { ContentService } from '../electron/content/contentService';
import { OcrError, ocrImage, shutdownOcr } from '../electron/content/ocr';
import { prepareImage } from '../electron/content/visual/imagePipeline';
import { ThreatService } from '../electron/threat/threatService';

const FIX = path.join(__dirname, 'fixtures');
afterAll(async () => { await shutdownOcr(); });

describe('Phase 8 full pipeline: watcher -> static -> content (OCR + QR) -> threat -> persisted -> events', () => {
  it('image, scanned PDF and QR files dropped into Downloads are assessed end to end; benign visual files stay SAFE', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp8p-')), dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined;
    let a: AnalysisService, c: ContentService, t: ThreatService;
    const agent = new MonitoringAgent(store, { log, emitChange: () => undefined, notify: () => undefined, onFileRecorded: (f) => a.enqueue(f), stability: { intervalMs: 60, requiredStableChecks: 2, timeoutMs: 5000 } });
    t = new ThreatService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: (id) => c.get(id) });
    c = new ContentService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'content'), visualCacheDir: path.join(root, 'ocr-cache'), onFinished: (f) => t.enqueue(f) });
    a = new AnalysisService(store, agent.events, { log, emitChange: () => undefined, onAnalyzed: (f) => c.enqueue(f), onFailed: (f) => t.enqueue(f) });
    await agent.start(); await new Promise((r) => setTimeout(r, 300));
    const names = ['test-phishing-image.png', 'test-scanned-phishing.pdf', 'test-qr-phishing.png', 'test-normal-image.png', 'test-normal-scanned-document.pdf', 'test-qr-benign.png'];
    for (const n of names) fs.copyFileSync(path.join(FIX, n), path.join(dl, n));
    const done = () => store.state.files.filter((f) => f.threatAnalysisStatus && ['COMPLETED', 'INCOMPLETE', 'FAILED'].includes(f.threatAnalysisStatus)).length;
    const t0 = Date.now(); while (done() < names.length && Date.now() - t0 < 90000) await new Promise((r) => setTimeout(r, 100));
    await a.idle(); await c.idle(); await t.idle();
    const by = (n: string) => store.state.files.find((f) => f.name === n)!;
    for (const n of ['test-phishing-image.png', 'test-scanned-phishing.pdf', 'test-qr-phishing.png']) expect(['high', 'critical']).toContain(by(n).riskLevel);
    for (const n of ['test-normal-image.png', 'test-normal-scanned-document.pdf', 'test-qr-benign.png']) expect(by(n).threatStatus).toBe('SAFE');
    const full = await t.get(by('test-qr-phishing.png').id); expect(full!.indicators.some((i) => i.origins?.includes('QR'))).toBe(true); expect(full!.coverage.content).toBe('COMPLETE');
    const stored = await c.get(by('test-scanned-phishing.pdf').id); expect(stored!.visual!.ocrPages).toEqual([1]); expect(stored!.visual!.pdfKind).toBe('IMAGE_ONLY');
    expect(fs.readdirSync(path.join(root, 'ocr-cache')).length).toBeGreaterThan(0);
    expect(store.state.events.map((e) => e.type)).toEqual(expect.arrayContaining(['content-completed', 'threat-completed', 'high-risk-file-detected']));
    for (const n of names) expect(fs.existsSync(path.join(dl, n))).toBe(true); // nothing was moved, opened or deleted
    await agent.stopAll(); fs.rmSync(root, { recursive: true, force: true });
  }, 180_000);
});

describe('Phase 8 resource bounds (real engines)', () => {
  it('a real OCR timeout stops the worker, and the next image is read normally (no runaway/queued worker)', async () => {
    const dense = path.join(os.tmpdir(), `sp8-dense-${process.pid}.png`);
    const sharp = require('sharp'); const W = 4000, H = 3000; let rows = '';
    for (let y = 30; y < H; y += 34) rows += `<text x="30" y="${y}" font-size="26" font-family="DejaVu Sans, Arial, sans-serif">payment account statement balance quarterly invoice customer reference transaction summary department approval payment account</text>`;
    await sharp(Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}"><rect width="100%" height="100%" fill="white"/>${rows}</svg>`)).png().toFile(dense);
    const prep = await prepareImage(fs.readFileSync(dense), { needOcr: true }); fs.rmSync(dense, { force: true });
    expect(prep.downscaled).toBe(true); expect(prep.workWidth * prep.workHeight).toBeLessThanOrEqual(LIMITS_PIXELS); expect(prep.ocrBands.length).toBeGreaterThan(1);
    const t0 = Date.now(); let err: unknown;
    try { await ocrImage(prep.ocrPng!, { timeoutMs: 1_000 }); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(OcrError); expect((err as OcrError).kind).toBe('timeout'); expect(Date.now() - t0).toBeLessThan(15_000);
    const ok = await ocrImage(fs.readFileSync(path.join(FIX, 'test-normal-image.png')), { timeoutMs: 40_000 }); expect(ok.text).toMatch(/lunch/i);
  }, 120_000);
  it('prepareImage enforces pixel and size bounds and applies EXIF orientation', async () => {
    const sharp = require('sharp');
    const tall = await sharp({ create: { width: 3000, height: 800, channels: 3, background: '#fff' } }).jpeg().withMetadata({ orientation: 6 }).toBuffer();
    const p = await prepareImage(tall, { needOcr: true }); expect(p.sourceWidth).toBe(800); expect(p.sourceHeight).toBe(3000); expect(Math.max(p.workWidth, p.workHeight)).toBeLessThanOrEqual(2200);
    const tiny = await sharp({ create: { width: 120, height: 40, channels: 3, background: '#fff' } }).png().toBuffer(); const q = await prepareImage(tiny, { needOcr: true }); expect(q.upscaled).toBe(true);
    await expect(prepareImage(Buffer.from('not an image'), { needOcr: true })).rejects.toThrow();
  }, 60_000);
});
const LIMITS_PIXELS = 4_500_000;
