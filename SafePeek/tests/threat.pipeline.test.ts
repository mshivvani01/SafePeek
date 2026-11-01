import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { StateStore } from '../electron/agent/store';
import { FileEventService } from '../electron/agent/fileEventService';
import type { DetectedFile } from '../electron/agent/types';
import { AnalysisService } from '../electron/analysis/service';
import { ThreatService } from '../electron/threat/threatService';
import { assessThreat } from '../electron/threat';
import { makePE, makeZip, PDF_SAFE } from './helpers/fixtures';
import { contentStub } from './helpers/threat';

const record = (dir: string, name: string): DetectedFile => {
  const p = path.join(dir, name); const st = fs.statSync(p);
  return { id: randomUUID(), name, path: p, extension: path.extname(name).slice(1).toLowerCase(), mimeType: 'unknown', size: st.size, createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString(), detectedAt: new Date().toISOString(), sourceFolder: 'Downloads', sourceFolderPath: dir, signature: `${st.size}:1`, sha256: null, status: 'detected', riskLevel: 'unknown', analysisStatus: 'pending', contentSummary: null, detectedUrls: [], indicators: [], previewAvailable: false };
};

describe('service pipeline: static analysis -> content (stubbed) -> threat engine -> persisted result -> events', () => {
  it('flows a real Phase 3 result through ThreatService, persists it and emits events', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp5s-')); const dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined; let changes = 0;
    const events = new FileEventService(store, { emitChange: () => { changes++; }, notify: () => undefined, isFolderActive: () => true, log });
    const texts: Record<string, string | null> = { 'invoice.pdf.exe': null, 'notes.txt': 'Meeting notes for Monday.', 'scholarship.zip': null, 'win.txt': 'Congratulations, you won a prize! Pay a processing fee of Rs 999 to claim your prize.' };
    fs.writeFileSync(path.join(dl, 'invoice.pdf.exe'), makePE()); fs.writeFileSync(path.join(dl, 'notes.txt'), texts['notes.txt']!);
    fs.writeFileSync(path.join(dl, 'scholarship.zip'), makeZip({ 'form.pdf': PDF_SAFE, 'form.pdf.exe': 'MZ x' })); fs.writeFileSync(path.join(dl, 'win.txt'), texts['win.txt']!);
    const contents = new Map<string, ReturnType<typeof contentStub>>();
    const threat = new ThreatService(store, events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: async (id) => contents.get(id) ?? null });
    const analysis = new AnalysisService(store, events, { log, emitChange: () => undefined, onAnalyzed: (f) => {
      const rec = store.state.files.find((x) => x.id === f.id)!; const t = texts[rec.name]; const c = contentStub(t ?? null); contents.set(rec.id, c); rec.contentStatus = c.status; threat.enqueue(rec);
    } });
    for (const n of Object.keys(texts)) { const r = record(dl, n); store.state.files.unshift(r); analysis.enqueue(r); }
    await analysis.idle(); await threat.idle();
    const by = (n: string) => store.state.files.find((f) => f.name === n)!;

    expect(by('invoice.pdf.exe')).toMatchObject({ threatAnalysisStatus: 'COMPLETED' }); expect(['high', 'critical']).toContain(by('invoice.pdf.exe').riskLevel);
    expect(by('notes.txt')).toMatchObject({ threatStatus: 'SAFE', riskLevel: 'safe', threatScore: 0 });
    expect(by('win.txt').riskLevel).not.toBe('safe'); expect(by('scholarship.zip').threatScore!).toBeGreaterThan(40);
    const full = await threat.get(by('invoice.pdf.exe').id); expect(full!.status).toBe(by('invoice.pdf.exe').threatStatus); expect(full!.indicators.length).toBeGreaterThan(0); expect(full!.evidence.length).toBeGreaterThan(0);
    expect(full!.executionPerformed).toBe(false); expect(full!.uploaded).toBe(false); expect(await threat.get('../../etc/passwd')).toBeNull();
    const types = store.state.events.map((e) => e.type);
    expect(types).toEqual(expect.arrayContaining(['analysis-started', 'analysis-completed', 'threat-started', 'threat-completed', 'high-risk-file-detected']));
    expect(store.state.events.find((e) => e.type === 'high-risk-file-detected')!.riskLevel).toMatch(/high|critical/); expect(changes).toBeGreaterThan(0);
    await store.flush(); const saved = JSON.parse(fs.readFileSync(path.join(root, 's.json'), 'utf8')); expect(saved.files.find((f: DetectedFile) => f.name === 'notes.txt').threatStatus).toBe('SAFE');
    // restart: persisted assessment is loaded again, nothing to redo
    const store2 = new StateStore(path.join(root, 's.json'), dl, () => undefined); const t2 = new ThreatService(store2, events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: async () => null });
    expect((await t2.get(by('win.txt').id))!.status).toBe(by('win.txt').threatStatus);
    fs.rmSync(root, { recursive: true, force: true });
  }, 30_000);

  it('static analysis failure still ends in a recorded UNKNOWN assessment (never SAFE)', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp5f-')); const dl = path.join(root, 'D'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined;
    const events = new FileEventService(store, { emitChange: () => undefined, notify: () => undefined, isFolderActive: () => true, log });
    const threat = new ThreatService(store, events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: async () => null });
    const analysis = new AnalysisService(store, events, { log, emitChange: () => undefined, onFailed: (f) => threat.enqueue(f) });
    fs.writeFileSync(path.join(dl, 'gone.pdf'), PDF_SAFE); const r = record(dl, 'gone.pdf'); fs.rmSync(path.join(dl, 'gone.pdf')); store.state.files.unshift(r);
    analysis.enqueue(r); await analysis.idle(); await threat.idle();
    expect(store.state.files[0]).toMatchObject({ analysisStatus: 'failed', threatStatus: 'UNKNOWN', riskLevel: 'unknown' }); fs.rmSync(root, { recursive: true, force: true });
  });

  it('a thrown engine error becomes FAILED, not a crash or a SAFE verdict', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp5e-')); const dl = path.join(root, 'D'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined;
    const events = new FileEventService(store, { emitChange: () => undefined, notify: () => undefined, isFolderActive: () => true, log });
    const threat = new ThreatService(store, events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: async () => null, assess: () => { throw new Error('boom'); } });
    fs.writeFileSync(path.join(dl, 'a.txt'), 'hi'); const r = record(dl, 'a.txt'); r.analysisStatus = 'complete'; store.state.files.unshift(r); threat.enqueue(r); await threat.idle();
    expect(store.state.files[0]).toMatchObject({ threatAnalysisStatus: 'FAILED', riskLevel: 'unknown' }); expect(store.state.events.map((e) => e.type)).toContain('threat-failed'); expect(typeof assessThreat).toBe('function'); fs.rmSync(root, { recursive: true, force: true });
  });
});
