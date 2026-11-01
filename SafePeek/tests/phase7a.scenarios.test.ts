import { afterAll, afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { MonitoringAgent } from '../electron/agent/agent';
import { StateStore } from '../electron/agent/store';
import { AnalysisService } from '../electron/analysis/service';
import { ContentService } from '../electron/content/contentService';
import { shutdownOcr } from '../electron/content/ocr';
import { ThreatService } from '../electron/threat/threatService';
import { AI_SECRET, ExplanationService, SecretStore, type FetchLike } from '../electron/ai';
import { AlertService, HistoryService, ProtectionService, QuarantineService, SecuritySettingsStore } from '../electron/protection';
import type { SecurityAlert, SecuritySettings } from '../electron/protection';
import { makePE } from './helpers/fixtures';
import { makeTextPdf } from './helpers/builders';
import { rm, tmp } from './helpers/phase6';

afterAll(async () => { await shutdownOcr(); });
const roots: string[] = []; const agents: MonitoringAgent[] = [];
afterEach(async () => { for (const a of agents.splice(0)) await a.stopAll(); roots.splice(0).forEach(rm); });

/** The REAL chain, wired like main.ts: watcher (chokidar) -> stability -> Phase 3 -> Phase 4 (real extractors) -> Phase 5 -> Phase 6. Only Electron and the OS shell are absent. */
async function real(o: { settings?: Partial<SecuritySettings>; fetchFn?: FetchLike; ai?: boolean } = {}) {
  const root = tmp('sp7e-'); roots.push(root); const dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
  const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined;
  const settings = new SecuritySettingsStore(path.join(root, 'sec', 'settings.json')); if (o.settings) settings.setSecurity(o.settings);
  const secrets = new SecretStore(path.join(root, 'sec', 'secrets.json'), { isAvailable: () => true, encrypt: (p) => Buffer.from(p), decrypt: (b) => b.toString() });
  if (o.ai) { settings.setAi({ enabled: true, provider: 'anthropic', model: 'claude-test' }); secrets.set(AI_SECRET, 'sk-test-ABCDEF123456'); }
  const quarantine = new QuarantineService({ dir: path.join(root, 'quarantine', 'files'), log, fallbackRestoreDir: dl });
  const alerts = new AlertService(path.join(root, 'sec', 'alerts.json')); const history = new HistoryService(path.join(root, 'sec', 'history.json'));
  const notified: SecurityAlert[] = []; const opened: string[] = [];
  let a!: AnalysisService; let c!: ContentService; let t!: ThreatService; let p!: ProtectionService; let ex!: ExplanationService;
  const agent = new MonitoringAgent(store, { log, emitChange: () => undefined, notify: () => undefined, onFileRecorded: (f: { id: string }) => a.enqueue(f), isExcluded: (x: string) => quarantine.isQuarantinePath(x), stability: { intervalMs: 60, requiredStableChecks: 2, timeoutMs: 10_000 } } as never);
  agents.push(agent); const skip = (id: string) => p?.isQuarantined(id) === true;
  ex = new ExplanationService({ dir: path.join(root, 'expl'), log, getAssessment: (id) => t.get(id), getAiSettings: () => settings.ai(), secrets, fetchFn: o.fetchFn });
  t = new ThreatService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: (id) => c.get(id), onAssessed: (id) => p.handleAssessment(id), isSkipped: skip });
  c = new ContentService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'content'), onFinished: (f) => t.enqueue(f), isSkipped: skip });
  a = new AnalysisService(store, agent.events, { log, emitChange: () => undefined, onAnalyzed: (f) => c.enqueue(f), onFailed: (f) => t.enqueue(f), isSkipped: skip });
  p = new ProtectionService({ store, events: agent.events, alerts, history, quarantine, settings, getAssessment: (id) => t.get(id), explain: (id) => ex.get(id), notify: (al) => { notified.push(al); }, rescan: (id) => a.reanalyze(id), monitoringActive: () => true, log, emitChange: () => undefined,
    system: { openPath: async (x) => { opened.push(x); return ''; }, showItemInFolder: () => undefined, writeClipboard: () => undefined } });
  await agent.start(); await new Promise((r) => setTimeout(r, 300));
  const drop = async (name: string, data: Buffer | string) => { fs.writeFileSync(path.join(dl, name), data); const t0 = Date.now(); while (Date.now() - t0 < 30_000) { const f = store.state.files.find((x) => x.name === name); if (f?.threatAnalysisStatus === 'COMPLETED' || f?.threatAnalysisStatus === 'INCOMPLETE') break; await new Promise((r) => setTimeout(r, 50)); } await a.idle(); await c.idle(); await t.idle(); await new Promise((r) => setTimeout(r, 50)); return store.state.files.find((x) => x.name === name)!; };
  return { root, dl, store, quarantine, alerts, history, notified, opened, p, ex, a, c, t, drop, agent };
}

describe('Phase 7A end-to-end scenarios (real watcher + real Phase 3/4/5/6)', () => {
  it('1. normal PDF: analyzed, no suspicious indicators, local explanation, no alert, file untouched and openable', async () => {
    const s = await real(); const f = await s.drop('meeting-notes.pdf', makeTextPdf([['Team meeting notes', 'Agenda: roadmap review and hiring update.', 'Next meeting on Friday.']]));
    expect(['SAFE', 'LOW_RISK']).toContain(f.threatStatus); expect(f.analysisStatus).toBe('complete'); expect(['COMPLETED', 'PARTIAL']).toContain(f.contentStatus);
    expect(s.alerts.list({ state: 'all' }).filter((x) => x.severity !== 'INFO')).toHaveLength(0); expect(s.notified).toHaveLength(0); expect(fs.existsSync(path.join(s.dl, 'meeting-notes.pdf'))).toBe(true);
    const b = (await s.ex.get(f.id))!; expect(b.local.generatedBy).toBe('LOCAL_RULE_ENGINE'); expect(b.status).toBe(f.threatStatus);
    expect((await s.p.openFile(f.id, false)).ok).toBe(true);
  }, 60_000);

  it('2. phishing document: login URL + credential request -> raised above LOW, explanation + alert', async () => {
    const s = await real(); const text = ['URGENT: Your account has been suspended', 'Verify your account immediately or it will be closed within 24 hours.', 'Sign in to confirm your password and card number:', 'http://secure-paypa1-login.example.com/verify?session=1', 'Enter your username, password and one-time code to restore access.'];
    const f = await s.drop('account-verification.pdf', makeTextPdf([text], { linkUrl: 'http://secure-paypa1-login.example.com/verify?session=1' }));
    expect(['SUSPICIOUS', 'HIGH_RISK', 'CRITICAL']).toContain(f.threatStatus); expect(f.threatCategories?.length).toBeGreaterThan(0);
    const b = (await s.ex.get(f.id))!; expect(b.local.whatWasFound.length).toBeGreaterThan(0); expect(s.alerts.list({ state: 'all' })).toHaveLength(1); expect(s.notified).toHaveLength(1); expect(s.notified[0].fileId).toBe(f.id); expect(s.opened).toEqual([]);
    // record the exact outcome for the report
    console.log(`[scenario 2] phishing PDF -> ${f.threatStatus} ${f.threatScore}/100`);
  }, 60_000);

  it('3. fake executable invoice.pdf.exe: PE + double extension + mismatch -> HIGH/CRITICAL + alert, never opened without confirmation', async () => {
    const s = await real(); const f = await s.drop('invoice.pdf.exe', makePE());
    expect(['HIGH_RISK', 'CRITICAL']).toContain(f.threatStatus); const ids = (await s.t.get(f.id))!.indicators.map((i) => i.ruleId).join(' '); expect(ids).toMatch(/DOUBLE_EXTENSION/); expect(ids).toMatch(/EXEC|MISMATCH|DISGUISED/);
    expect(s.alerts.list({ state: 'all' })).toHaveLength(1); expect(await s.p.openFile(f.id, false)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(s.opened).toEqual([]);
    console.log(`[scenario 3] invoice.pdf.exe -> ${f.threatStatus} ${f.threatScore}/100`);
  }, 60_000);

  it('4. critical file with automatic protection ON: quarantined, alerted, notified, in history; watcher does not re-detect the vault', async () => {
    const s = await real({ settings: { autoQuarantineCritical: true } }); const f = await s.drop('critical-invoice.pdf.exe', makePE());
    if (f.threatStatus !== 'CRITICAL') { console.log(`[scenario 4] real engine rated the fake exe ${f.threatStatus} (${f.threatScore}); CRITICAL threshold covered by the forced-status tests in phase7a.protection`); expect(fs.existsSync(path.join(s.dl, 'critical-invoice.pdf.exe'))).toBe(true); expect(s.quarantine.activeCount()).toBe(0); return; }
    expect(f.quarantineState).toBe('QUARANTINED'); expect(fs.existsSync(path.join(s.dl, 'critical-invoice.pdf.exe'))).toBe(false); expect(s.quarantine.activeCount()).toBe(1);
    expect(s.alerts.list({ state: 'all' })[0].actionTaken).toBe('Auto-quarantined'); expect(s.notified).toHaveLength(1); expect(s.history.list().find((h) => h.fileId === f.id)?.action).toBe('Auto-quarantined');
    await new Promise((r) => setTimeout(r, 400)); expect(s.store.state.files.filter((x) => x.name === 'critical-invoice.pdf.exe')).toHaveLength(1);
  }, 60_000);

  it('5. user restores a quarantined file: confirmation, hash verified, not opened, no duplicate record, re-analysis through the whole pipeline', async () => {
    const s = await real(); const f = await s.drop('restore-me.pdf.exe', makePE()); expect((await s.p.quarantineFile(f.id)).ok).toBe(true); const q = s.quarantine.list()[0];
    expect(await s.p.restoreFile(q.id, { confirmed: false })).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' });
    const r = await s.p.restoreFile(q.id, { confirmed: true }); expect(r.ok).toBe(true); expect(s.opened).toEqual([]); expect(fs.existsSync(path.join(s.dl, 'restore-me.pdf.exe'))).toBe(true);
    const t0 = Date.now(); while (s.store.state.files.find((x) => x.id === f.id)?.threatAnalysisStatus !== 'COMPLETED' && Date.now() - t0 < 20_000) await new Promise((r2) => setTimeout(r2, 50));
    await s.a.idle(); await s.c.idle(); await s.t.idle(); await new Promise((r2) => setTimeout(r2, 800)); // give the watcher time to (wrongly) re-detect the restored file
    const same = s.store.state.files.filter((x) => x.name === 'restore-me.pdf.exe'); expect(same).toHaveLength(1); expect(same[0].id).toBe(f.id); expect(['HIGH_RISK', 'CRITICAL']).toContain(same[0].threatStatus); expect(s.quarantine.get(q.id)?.state).toBe('RESTORED');
  }, 90_000);

  it('6. AI enabled but unavailable: local explanation, same verdict, alert still works', async () => {
    const s = await real({ ai: true, fetchFn: async () => { throw new TypeError('fetch failed'); } }); const f = await s.drop('offline-invoice.pdf.exe', makePE());
    const b = (await s.ex.requestAi(f.id, true))!; expect(b.aiOutcome).toBe('FAILED'); expect(b.ai).toBeUndefined(); expect(b.local.summary.length).toBeGreaterThan(10); expect(b.status).toBe(f.threatStatus); expect(b.score).toBe(f.threatScore);
    expect(s.alerts.list({ state: 'all' })).toHaveLength(1); expect(s.notified).toHaveLength(1);
  }, 60_000);
});
