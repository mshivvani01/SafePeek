import { afterAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MonitoringAgent } from '../electron/agent/agent';
import { StateStore } from '../electron/agent/store';
import { AnalysisService } from '../electron/analysis/service';
import { ContentService } from '../electron/content/contentService';
import { shutdownOcr } from '../electron/content/ocr';
import { ThreatService } from '../electron/threat/threatService';
import { makeDocx, makeTextPdf } from './helpers/builders';
import { makePE, makeZip } from './helpers/fixtures';

afterAll(async () => { await shutdownOcr(); });

/** The complete real pipeline: chokidar watcher -> Phase 3 -> Phase 4 (real extractors) -> Phase 5 -> persisted -> events. Requires the project's real dependencies. */
describe('full pipeline: watcher -> static -> content -> threat -> persist -> UI event', () => {
  it('assesses files copied into a monitored folder end to end', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp5p-')), dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined; let changes = 0;
    let a: AnalysisService, c: ContentService, t: ThreatService;
    const agent = new MonitoringAgent(store, { log, emitChange: () => { changes++; }, notify: () => undefined, onFileRecorded: (f) => a.enqueue(f), stability: { intervalMs: 60, requiredStableChecks: 2, timeoutMs: 5000 } });
    t = new ThreatService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: (id) => c.get(id) });
    c = new ContentService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'content'), onFinished: (f) => t.enqueue(f) });
    a = new AnalysisService(store, agent.events, { log, emitChange: () => undefined, onAnalyzed: (f) => c.enqueue(f), onFailed: (f) => t.enqueue(f) });
    await agent.start(); await new Promise((r) => setTimeout(r, 300));
    const phish = makeTextPdf([['Security alert', 'Your account will be suspended. Verify your password immediately.', 'Log in now to avoid suspension.']], { linkUrl: 'http://secure-login.example.net/verify' });
    fs.writeFileSync(path.join(dl, 'notice.pdf'), phish); fs.writeFileSync(path.join(dl, 'invoice.pdf.exe'), makePE());
    fs.writeFileSync(path.join(dl, 'minutes.txt'), 'Team meeting minutes. Next review on Friday.'); fs.writeFileSync(path.join(dl, 'macro.docx'), makeDocx({ paragraphs: [{ text: 'Please enable content to view this document.' }], macro: true }));
    fs.writeFileSync(path.join(dl, 'pack.zip'), makeZip({ 'invoice.pdf': 'x', 'invoice.pdf.exe': 'MZ' }));
    const done = () => store.state.files.filter((f) => f.threatAnalysisStatus && ['COMPLETED', 'INCOMPLETE', 'FAILED'].includes(f.threatAnalysisStatus)).length;
    const t0 = Date.now(); while (done() < 5 && Date.now() - t0 < 25000) await new Promise((r) => setTimeout(r, 50));
    await a.idle(); await c.idle(); await t.idle();
    const by = (n: string) => store.state.files.find((f) => f.name === n)!;
    expect(done()).toBe(5);
    expect(['high', 'critical', 'suspicious']).toContain(by('notice.pdf').riskLevel); expect(by('notice.pdf').threatCategories).toContain('PHISHING');
    expect(['high', 'critical']).toContain(by('invoice.pdf.exe').riskLevel); expect(by('minutes.txt').threatStatus).toBe('SAFE');
    expect(by('macro.docx').threatCategories).toContain('MACRO_RISK'); expect(by('pack.zip').threatScore!).toBeGreaterThan(40);
    const full = await t.get(by('notice.pdf').id); expect(full!.reasons.length).toBeGreaterThan(0); expect(full!.coverage.static).toBe('COMPLETE'); expect(full!.coverage.content).toBe('COMPLETE');
    const types = store.state.events.map((e) => e.type);
    expect(types).toEqual(expect.arrayContaining(['file-detected', 'analysis-completed', 'content-completed', 'threat-completed', 'high-risk-file-detected']));
    expect(changes).toBeGreaterThan(5);
    await agent.stopAll(); fs.rmSync(root, { recursive: true, force: true });
  }, 60_000);
});
