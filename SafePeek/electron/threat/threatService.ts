import fs from 'node:fs';
import path from 'node:path';
import type { StateStore } from '../agent/store';
import type { FileEventService } from '../agent/fileEventService';
import type { DetectedFile } from '../agent/types';
import type { ContentResult } from '../content/types';
import { assessThreat } from './threatEngine';
import type { ThreatAssessment, ThreatInput, ThreatStatus } from './types';

export interface ThreatDeps {
  log(m: string): void; emitChange(): void; dir: string;
  /** Loads the stored Phase 4 result (read-only). */
  getContent(id: string): Promise<ContentResult | null>;
  assess?: (i: ThreatInput) => ThreatAssessment; concurrency?: number; /** Phase 7A: true when the file was quarantined; a result computed meanwhile is discarded. */ isSkipped?(id: string): boolean;
  /** Phase 6 hook: called after an assessment was stored and the file record updated. Phase 5 stays authoritative; the hook only reads it. */
  onAssessed?(id: string): void | Promise<void>;
}
const safeId = (id: string) => /^[A-Za-z0-9-]{8,64}$/.test(id);
const TERMINAL_CONTENT = new Set(['COMPLETED', 'PARTIAL', 'UNSUPPORTED', 'FAILED']);
export const RISK_LEVEL: Record<ThreatStatus, DetectedFile['riskLevel']> = { SAFE: 'safe', LOW_RISK: 'low', SUSPICIOUS: 'suspicious', HIGH_RISK: 'high', CRITICAL: 'critical', UNKNOWN: 'unknown' };
const LABEL: Record<ThreatStatus, string> = { SAFE: 'no suspicious indicators', LOW_RISK: 'low risk', SUSPICIOUS: 'SUSPICIOUS', HIGH_RISK: 'HIGH RISK', CRITICAL: 'CRITICAL', UNKNOWN: 'analysis incomplete' };

/**
 * Phase 5 queue. Runs after Phase 3 (static) and Phase 4 (content) have both finished for a file, reusing their stored results (nothing is
 * re-read or re-scanned). The full ThreatAssessment is stored in userData/threat/<id>.json; the FileRecord keeps only summary fields.
 */
export class ThreatService {
  private queue: string[] = []; private queued = new Set<string>(); private running = 0; private idleWaiters: (() => void)[] = []; private stopped = false;
  constructor(private store: StateStore, private events: FileEventService, private deps: ThreatDeps) {}

  enqueue(f: { id: string }) {
    if (this.stopped || this.queued.has(f.id)) return;
    const rec = this.find(f.id); if (rec) { rec.threatAnalysisStatus = 'QUEUED'; this.store.save(); this.deps.emitChange(); }
    this.queued.add(f.id); this.queue.push(f.id); this.pump();
  }
  /** Files left unassessed by a previous session (e.g. app closed mid-pipeline). */
  resume() {
    for (const f of this.store.state.files) {
      const pendingThreat = !f.threatAnalysisStatus || ['NOT_STARTED', 'QUEUED', 'ANALYZING'].includes(f.threatAnalysisStatus);
      const ready = f.analysisStatus === 'failed' || (f.analysisStatus === 'complete' && !!f.contentStatus && TERMINAL_CONTENT.has(f.contentStatus));
      if (pendingThreat && ready) this.enqueue(f);
    }
  }
  rerun(id: string) { if (this.find(id) && !this.queued.has(id)) this.enqueue({ id }); }
  stop() { this.stopped = true; }
  idle(): Promise<void> { return this.running === 0 && this.queue.length === 0 ? Promise.resolve() : new Promise((r) => this.idleWaiters.push(r)); }

  async get(id: string): Promise<ThreatAssessment | null> {
    if (!safeId(id)) return null;
    try { const o = JSON.parse(await fs.promises.readFile(path.join(this.deps.dir, `${id}.json`), 'utf8')); return o && typeof o === 'object' && typeof o.status === 'string' && Array.isArray(o.indicators) ? (o as ThreatAssessment) : null; }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') this.deps.log(`[SafePeek] Stored threat result unreadable (${(e as Error).message})`); return null; }
  }
  private find(id: string) { return this.store.state.files.find((f) => f.id === id); }
  private pump() {
    while (this.running < (this.deps.concurrency ?? 1) && this.queue.length) {
      const id = this.queue.shift()!; this.running++;
      this.run(id).catch((e) => this.deps.log(`[SafePeek] Threat analysis error: ${(e as Error).message}`)).finally(() => {
        this.running--; this.queued.delete(id); this.pump();
        if (this.running === 0 && this.queue.length === 0) { this.idleWaiters.forEach((r) => r()); this.idleWaiters = []; }
      });
    }
  }
  private async run(id: string) {
    const f = this.find(id); if (!f) return;
    if (this.deps.isSkipped?.(id)) { this.deps.log(`[SafePeek] Threat analysis skipped (file is quarantined): ${f.name}`); return; }
    f.threatAnalysisStatus = 'ANALYZING'; this.store.save(); this.deps.emitChange();
    this.deps.log(`[SafePeek] Threat analysis started: ${f.name}`);
    this.events.addEvent('threat-started', 'Threat analysis started', { fileName: f.name, folder: f.sourceFolder });
    await new Promise<void>((r) => setImmediate(r)); // let the main loop breathe before the CPU-bound rules run
    let res: ThreatAssessment | null = null; let error: string | null = null;
    try {
      const content = f.analysisStatus === 'failed' ? null : await this.deps.getContent(id);
      res = (this.deps.assess ?? assessThreat)({ fileName: f.name, analysis: f.analysis ?? null, content, contentStatus: f.contentStatus });
    } catch (e) { error = (e as Error).message; this.deps.log(`[SafePeek] Threat engine failed for ${f.name}: ${error}`); }
    const cur = this.find(id); if (!cur) return; // record replaced by a newer version of the file
    if (this.deps.isSkipped?.(id)) return; // quarantined meanwhile: keep the verdict it was quarantined with
    if (!res) {
      cur.threatAnalysisStatus = 'FAILED'; cur.riskLevel = 'unknown'; cur.threatStatus = 'UNKNOWN'; this.store.save();
      this.events.addEvent('threat-failed', 'Threat analysis failed', { fileName: f.name, folder: f.sourceFolder, riskLevel: 'unknown' }); return;
    }
    try { await fs.promises.mkdir(this.deps.dir, { recursive: true }); await fs.promises.writeFile(path.join(this.deps.dir, `${id}.json`), JSON.stringify(res), 'utf8'); }
    catch (e) { this.deps.log(`[SafePeek] Could not store threat result: ${(e as Error).message}`); }
    cur.threatStatus = res.status; cur.threatScore = res.score; cur.threatConfidence = res.confidence; cur.threatCategories = res.categories; cur.threatIndicatorCount = res.indicators.filter((i) => i.severity !== 'INFO').length;
    cur.threatAnalyzedAt = res.analyzedAt; cur.threatHeadline = res.headline; cur.threatTopReason = res.reasons[0]?.text; cur.threatRecommendation = res.recommendations[0]?.action; cur.threatAnalysisComplete = res.analysisComplete;
    cur.threatAnalysisStatus = res.analysisComplete ? 'COMPLETED' : 'INCOMPLETE'; cur.riskLevel = RISK_LEVEL[res.status];
    this.store.save();
    const rl = RISK_LEVEL[res.status];
    this.deps.log(`[SafePeek] Threat analysis completed: ${f.name} — ${res.status} (${res.score}/100, confidence ${res.confidence})`);
    this.events.addEvent('threat-completed', `Threat analysis completed — ${LABEL[res.status]}${res.status === 'UNKNOWN' ? '' : ` (score ${res.score}/100)`}`, { fileName: f.name, folder: f.sourceFolder, riskLevel: rl, score: res.score });
    if (res.status === 'SUSPICIOUS') this.events.addEvent('suspicious-file-detected', 'Suspicious file detected', { fileName: f.name, folder: f.sourceFolder, riskLevel: rl, score: res.score });
    if (res.status === 'HIGH_RISK' || res.status === 'CRITICAL') this.events.addEvent('high-risk-file-detected', 'High-risk file detected', { fileName: f.name, folder: f.sourceFolder, riskLevel: rl, score: res.score });
    try { await this.deps.onAssessed?.(id); } catch (e) { this.deps.log(`[SafePeek] Protection hook failed for ${f.name}: ${(e as Error).message}`); }
  }
}
