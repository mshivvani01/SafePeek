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
import { ExplanationService, SecretStore } from '../electron/ai';
import { AlertService, HistoryService, ProtectionService, QuarantineService, SecuritySettingsStore } from '../electron/protection';
import type { SecurityAlert } from '../electron/protection';
import { makePE } from './helpers/fixtures';

afterAll(async () => { await shutdownOcr(); });

/** The complete real chain, no stubs for the analysis stages: watcher -> Phase 3 -> Phase 4 -> Phase 5 -> Phase 6 (explanation, alert, notification) -> user quarantines. */
describe('Phase 6 full pipeline', () => {
  it('suspicious file arrives -> analyzed -> HIGH/CRITICAL -> explanation -> alert -> notification -> user quarantines -> file moved -> activity recorded', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp6f-')); const dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined;
    const settings = new SecuritySettingsStore(path.join(root, 'sec', 'settings.json'));
    const secrets = new SecretStore(path.join(root, 'sec', 'secrets.json'), { isAvailable: () => true, encrypt: (p) => Buffer.from(p), decrypt: (b) => b.toString() });
    const quarantine = new QuarantineService({ dir: path.join(root, 'quarantine', 'files'), log, fallbackRestoreDir: dl });
    const alerts = new AlertService(path.join(root, 'sec', 'alerts.json')); const history = new HistoryService(path.join(root, 'sec', 'history.json'));
    const notified: SecurityAlert[] = []; const opened: string[] = [];
    let a!: AnalysisService; let c!: ContentService; let t!: ThreatService; let p!: ProtectionService; let ex!: ExplanationService;
    const agent = new MonitoringAgent(store, { log, emitChange: () => undefined, notify: () => undefined, onFileRecorded: (f) => a.enqueue(f), isExcluded: (x) => quarantine.isQuarantinePath(x), stability: { intervalMs: 60, requiredStableChecks: 2, timeoutMs: 5000 } });
    ex = new ExplanationService({ dir: path.join(root, 'expl'), log, getAssessment: (id) => t.get(id), getAiSettings: () => settings.ai(), secrets });
    t = new ThreatService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: (id) => c.get(id), onAssessed: (id) => p.handleAssessment(id) });
    c = new ContentService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'content'), onFinished: (f) => t.enqueue(f) });
    a = new AnalysisService(store, agent.events, { log, emitChange: () => undefined, onAnalyzed: (f) => c.enqueue(f), onFailed: (f) => t.enqueue(f) });
    p = new ProtectionService({ store, events: agent.events, alerts, history, quarantine, settings, getAssessment: (id) => t.get(id), explain: (id) => ex.get(id), notify: (al) => { notified.push(al); }, rescan: (id) => a.reanalyze(id), monitoringActive: () => true, log, emitChange: () => undefined,
      system: { openPath: async (x) => { opened.push(x); return ''; }, showItemInFolder: () => undefined, writeClipboard: () => undefined } });
    await agent.start(); await new Promise((r) => setTimeout(r, 300));

    const target = path.join(dl, 'salary_update.pdf.exe'); fs.writeFileSync(target, makePE()); fs.writeFileSync(path.join(dl, 'minutes.txt'), 'Team meeting minutes. Next review on Friday.');
    const t0 = Date.now(); while ((alerts.list({ state: 'all' }).length < 1 || store.state.files.filter((f) => f.threatAnalysisStatus === 'COMPLETED').length < 2) && Date.now() - t0 < 25000) await new Promise((r) => setTimeout(r, 50));
    await a.idle(); await c.idle(); await t.idle();

    const f = store.state.files.find((x) => x.name === 'salary_update.pdf.exe')!;
    expect(['HIGH_RISK', 'CRITICAL']).toContain(f.threatStatus); // Phase 5 decided this
    const bundle = (await ex.get(f.id))!; expect(bundle.local.generatedBy).toBe('LOCAL_RULE_ENGINE'); expect(bundle.status).toBe(f.threatStatus); expect(bundle.score).toBe(f.threatScore);
    expect(bundle.local.whatWasFound.join(' ')).toMatch(/double extension/i); expect(bundle.local.recommendedAction).toMatch(/Do not open/);
    expect(alerts.list()).toHaveLength(1); expect(alerts.list()[0]).toMatchObject({ fileName: 'salary_update.pdf.exe', score: f.threatScore }); expect(notified).toHaveLength(1);
    expect(store.state.files.find((x) => x.name === 'minutes.txt')!.threatStatus).toBe('SAFE'); expect(history.list().length).toBeGreaterThanOrEqual(2);
    expect(fs.existsSync(target)).toBe(true); expect(opened).toHaveLength(0); // protection is OFF by default: nothing was moved or opened

    // Opening is gated.
    expect(await p.openFile(f.id, false)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(opened).toHaveLength(0);

    // The user quarantines it.
    const r = await p.quarantineFile(f.id); expect(r.ok).toBe(true);
    expect(fs.existsSync(target)).toBe(false); const q = quarantine.list()[0]; expect(fs.existsSync(q.quarantinePath)).toBe(true); expect(q).toMatchObject({ originalPath: target, riskStatus: f.threatStatus });
    expect(store.state.files.find((x) => x.id === f.id)!.quarantineState).toBe('QUARANTINED'); expect(alerts.list()[0].actionTaken).toBe('Quarantined');
    // The watcher must not treat the quarantine folder as a new download.
    await new Promise((r) => setTimeout(r, 400)); expect(store.state.files.filter((x) => x.name === 'salary_update.pdf.exe')).toHaveLength(1);
    const types = store.state.events.map((e) => e.type);
    expect(types).toEqual(expect.arrayContaining(['file-detected', 'analysis-completed', 'content-completed', 'threat-completed', 'high-risk-file-detected', 'explanation-generated', 'alert-created', 'alert-shown', 'file-quarantined']));
    expect(history.list().find((h) => h.fileId === f.id)!.action).toBe('Quarantined');
    expect((await p.openFile(f.id, true))).toMatchObject({ ok: false, code: 'QUARANTINED' });

    // Restore (explicit) -> back in place, never executed, re-analyzed through the whole pipeline.
    expect((await p.restoreFile(q.id, { confirmed: true })).ok).toBe(true); expect(fs.existsSync(target)).toBe(true); expect(opened).toHaveLength(0);
    const t1 = Date.now(); while (store.state.files.find((x) => x.id === f.id)?.threatAnalysisStatus !== 'COMPLETED' && Date.now() - t1 < 15000) await new Promise((r) => setTimeout(r, 50));
    await a.idle(); await c.idle(); await t.idle(); expect(['HIGH_RISK', 'CRITICAL']).toContain(store.state.files.find((x) => x.id === f.id)!.threatStatus);
    await agent.stopAll(); fs.rmSync(root, { recursive: true, force: true });
  }, 90_000);
});
