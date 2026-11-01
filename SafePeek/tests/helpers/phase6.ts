import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { StateStore } from '../../electron/agent/store';
import { FileEventService } from '../../electron/agent/fileEventService';
import type { DetectedFile } from '../../electron/agent/types';
import { AnalysisService } from '../../electron/analysis/service';
import { ThreatService } from '../../electron/threat/threatService';
import type { ThreatAssessment, ThreatIndicator, ThreatInput, ThreatSeverity, ThreatStatus } from '../../electron/threat/types';
import { ExplanationService, SecretStore } from '../../electron/ai';
import { AlertService, HistoryService, ProtectionService, QuarantineService, SecuritySettingsStore } from '../../electron/protection';
import type { SecurityAlert, SecuritySettings } from '../../electron/protection';
import { contentStub } from './threat';

export const tmp = (p = 'sp6-') => fs.mkdtempSync(path.join(os.tmpdir(), p));
/** Retries: the Phase 2 StateStore writes asynchronously, so a write can land while a test folder is being removed. */
export const rm = (d: string) => { try { fs.rmSync(d, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }); } catch { /* temp dir; best effort */ } };

/** Synthetic Phase 5 assessment for rule-independent tests. Real engine outputs are used wherever a real file can produce the status. */
export function fakeAssessment(status: ThreatStatus, o: Partial<ThreatAssessment> & { inds?: [string, ThreatSeverity, string, string?][] } = {}): ThreatAssessment {
  const inds: ThreatIndicator[] = (o.inds ?? []).map(([id, severity, title, category]) => ({ id, ruleId: id, category: (category ?? 'UNKNOWN') as ThreatIndicator['category'], severity, title, description: `${title} (description)`, source: 'STATIC_ANALYSIS', points: 10, correlated: false }));
  const cats = [...new Set(inds.map((i) => i.category).filter((c) => c !== 'UNKNOWN'))];
  const score = o.score ?? ({ SAFE: 0, LOW_RISK: 15, SUSPICIOUS: 40, HIGH_RISK: 65, CRITICAL: 90, UNKNOWN: 0 } as const)[status];
  const { inds: _i, ...rest } = o;
  return {
    version: 1, fileName: 'file.bin', status, score, confidence: 80, confidenceLevel: 'HIGH', headline: status, analysisComplete: true, indicators: inds, reasons: [], categories: cats, evidence: [], recommendations: [],
    coverage: { static: 'COMPLETE', content: 'COMPLETE', threat: 'COMPLETE', notes: [] }, breakdown: { contributions: [], correlationBonus: 0, breadthBonus: 0, rawScore: score, finalScore: score, notes: [] },
    limitations: [], disclaimer: 'x', analyzedAt: new Date().toISOString(), engineVersion: '5.0.0', scoreKind: 'heuristic', executionPerformed: false, uploaded: false, ...rest
  };
}

export const record = (dir: string, name: string): DetectedFile => {
  const p = path.join(dir, name); const st = fs.statSync(p);
  return { id: randomUUID(), name, path: p, extension: path.extname(name).slice(1).toLowerCase(), mimeType: 'unknown', size: st.size, createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString(), detectedAt: new Date().toISOString(), sourceFolder: 'Downloads', sourceFolderPath: dir, signature: `${st.size}:${st.mtimeMs}`, sha256: null, status: 'detected', riskLevel: 'unknown', analysisStatus: 'pending', contentSummary: null, detectedUrls: [], indicators: [], previewAvailable: false };
};

export interface StackOpts { assess?: (i: ThreatInput) => ThreatAssessment; settings?: Partial<SecuritySettings>; texts?: Record<string, string | null>; move?: (a: string, b: string) => Promise<void>; notifyThrows?: boolean }
/** Phase 3 -> Phase 4 (stub) -> Phase 5 -> Phase 6, wired exactly like main.ts but without Electron. */
export function buildStack(root: string, o: StackOpts = {}) {
  const dl = path.join(root, 'Downloads'); fs.mkdirSync(dl, { recursive: true });
  const store = new StateStore(path.join(root, 's.json'), dl, () => undefined); const log = () => undefined;
  const events = new FileEventService(store, { emitChange: () => undefined, notify: () => undefined, isFolderActive: () => true, log });
  const settings = new SecuritySettingsStore(path.join(root, 'security', 'settings.json'), log); if (o.settings) settings.setSecurity(o.settings);
  const secrets = new SecretStore(path.join(root, 'security', 'secrets.json'), { isAvailable: () => true, encrypt: (p) => Buffer.from(`enc:${p.split('').reverse().join('')}`), decrypt: (b) => b.toString().slice(4).split('').reverse().join('') });
  const quarantine = new QuarantineService({ dir: path.join(root, 'quarantine', 'files'), log, fallbackRestoreDir: dl, move: o.move });
  const alerts = new AlertService(path.join(root, 'security', 'alerts.json'), log);
  const history = new HistoryService(path.join(root, 'security', 'history.json'), log);
  const sink = { notified: [] as SecurityAlert[], opened: [] as string[], revealed: [] as string[], clipboard: [] as string[], rescans: [] as string[] };
  let threat!: ThreatService; let protection!: ProtectionService; let analysis!: AnalysisService;
  const explanations = new ExplanationService({ dir: path.join(root, 'explanations'), log, getAssessment: (id) => threat.get(id), getAiSettings: () => settings.ai(), secrets });
  const texts = o.texts ?? {}; const contents = new Map<string, ReturnType<typeof contentStub>>();
  threat = new ThreatService(store, events, { log, emitChange: () => undefined, dir: path.join(root, 'threat'), getContent: async (id) => contents.get(id) ?? null, assess: o.assess, isSkipped: (id) => protection?.isQuarantined(id) === true, onAssessed: (id) => protection.handleAssessment(id) });
  analysis = new AnalysisService(store, events, { log, emitChange: () => undefined, onAnalyzed: (f) => {
    const rec = store.state.files.find((x) => x.id === f.id)!; const t = texts[rec.name]; const c = contentStub(t ?? null); contents.set(rec.id, c); rec.contentStatus = c.status; threat.enqueue(rec);
  }, onFailed: (f) => threat.enqueue(f), isSkipped: (id) => protection?.isQuarantined(id) === true });
  protection = new ProtectionService({
    store, events, alerts, history, quarantine, settings, getAssessment: (id) => threat.get(id), explain: (id) => explanations.get(id),
    notify: (a) => { if (o.notifyThrows) throw new Error('notification backend down'); sink.notified.push(a); }, rescan: (id) => { sink.rescans.push(id); analysis.reanalyze(id); }, monitoringActive: () => true, log, emitChange: () => undefined,
    system: { openPath: async (p) => { sink.opened.push(p); return ''; }, showItemInFolder: (p) => { sink.revealed.push(p); }, writeClipboard: (t) => { sink.clipboard.push(t); } }
  });
  const settle = async () => { for (let i = 0; i < 3; i++) { await analysis.idle(); await threat.idle(); } };
  const add = async (name: string, data: Buffer | string, text?: string | null) => {
    fs.writeFileSync(path.join(dl, name), data); if (text !== undefined) texts[name] = text; else if (typeof data === 'string') texts[name] = data;
    const r = record(dl, name); store.state.files.unshift(r); analysis.enqueue(r); await settle(); return store.state.files.find((f) => f.id === r.id)!;
  };
  return { root, dl, store, events, settings, secrets, quarantine, alerts, history, explanations, threat, protection, analysis, sink, settle, add, texts };
}
export type Stack = ReturnType<typeof buildStack>;

/** Forces the Phase 5 result by file name prefix (crit-, high-, susp-, low-, safe-, unk-) so Phase 6 thresholds can be tested exactly. The rest of the pipeline is real. */
export const assessByPrefix = (i: ThreatInput): ThreatAssessment => {
  const n = i.fileName.toLowerCase(); const st: ThreatStatus = n.startsWith('crit') ? 'CRITICAL' : n.startsWith('high') ? 'HIGH_RISK' : n.startsWith('susp') ? 'SUSPICIOUS' : n.startsWith('low') ? 'LOW_RISK' : n.startsWith('unk') ? 'UNKNOWN' : 'SAFE';
  const inds: [string, ThreatSeverity, string, string][] = st === 'SAFE' || st === 'UNKNOWN' ? [] : [['FILE_DOUBLE_EXTENSION', st === 'LOW_RISK' ? 'LOW' : 'HIGH', 'Double file extension', 'SOCIAL_ENGINEERING'], ['FILE_EXEC_DISGUISED', st === 'CRITICAL' ? 'CRITICAL' : 'MEDIUM', 'Executable disguised with a non-executable extension', 'FILE_TYPE_MISMATCH']];
  const reasons = inds.map(([id, severity, text, category]) => ({ id: `reason:${id}`, text, severity, category: category as never, indicatorIds: [id] }));
  return fakeAssessment(st, { fileName: i.fileName, inds, reasons, analysisComplete: st !== 'UNKNOWN' });
};
