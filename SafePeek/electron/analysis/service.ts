import fs from 'node:fs';
import type { StateStore } from '../agent/store';
import type { FileEventService } from '../agent/fileEventService';
import type { DetectedFile } from '../agent/types';
import { analyzeFile } from './analyzer';
import type { AnalysisResult } from './types';

export interface AnalysisDeps { log(m: string): void; emitChange(): void; analyze?: (p: string, o?: { name?: string }) => Promise<AnalysisResult>; concurrency?: number; /** Phase 7A: wall-clock limit for one static analysis; on expiry the result is 'failed' (analysis incomplete), never safe. */ timeoutMs?: number; /** Phase 7A: true when the file was quarantined/removed from the pipeline; results are then discarded instead of overwriting its verdict. */ isSkipped?(id: string): boolean; /** Phase 4 hook: called after static analysis stored a result (not for failed analyses). */ onAnalyzed?(f: { id: string }): void; /** Phase 5 hook: static analysis failed, so no content stage will run; the threat engine still records an UNKNOWN assessment. */ onFailed?(f: { id: string }): void }

/** Async analysis queue. Runs after Phase 2 records a file; I/O is streaming/async so the main process and UI stay responsive. */
export class AnalysisService {
  private queue: string[] = [];
  private queued = new Set<string>();
  private running = 0;
  private idleWaiters: (() => void)[] = [];
  private stopped = false;
  constructor(private store: StateStore, private events: FileEventService, private deps: AnalysisDeps) {}

  enqueue(f: { id: string }) {
    if (this.stopped || this.queued.has(f.id)) return;
    this.queued.add(f.id); this.queue.push(f.id); this.pump();
  }
  /** Re-queue files left 'pending'/'analyzing' by a previous session. */
  resume() { for (const f of this.store.state.files) if (f.analysisStatus === 'pending' || f.analysisStatus === 'analyzing') this.enqueue(f); }
  reanalyze(id: string) {
    const f = this.store.state.files.find((x) => x.id === id);
    if (f && this.deps.isSkipped?.(id)) { this.deps.log(`[SafePeek] Rescan ignored (file is quarantined): ${f.name}`); return; }
    if (f && !this.queued.has(id)) {
      f.analysisStatus = 'pending';
      // The earlier verdict no longer describes the file the moment a rescan starts; nothing may keep treating it as current.
      f.contentStatus = 'NOT_STARTED'; f.threatAnalysisStatus = 'NOT_STARTED'; f.threatStatus = undefined; f.threatScore = undefined; f.riskLevel = 'unknown';
      this.store.save(); this.deps.emitChange(); this.enqueue(f);
    }
  }
  stop() { this.stopped = true; }
  idle(): Promise<void> { return this.running === 0 && this.queue.length === 0 ? Promise.resolve() : new Promise((r) => this.idleWaiters.push(r)); }

  private pump() {
    while (this.running < (this.deps.concurrency ?? 2) && this.queue.length) {
      const id = this.queue.shift()!; this.running++;
      this.run(id).catch((e) => this.deps.log(`[SafePeek] Analysis error: ${(e as Error).message}`)).finally(() => {
        this.running--; this.queued.delete(id); this.pump();
        if (this.running === 0 && this.queue.length === 0) { this.idleWaiters.forEach((r) => r()); this.idleWaiters = []; }
      });
    }
  }

  private find(id: string): DetectedFile | undefined { return this.store.state.files.find((f) => f.id === id); }

  private async run(id: string) {
    const f = this.find(id); if (!f) return;
    if (this.deps.isSkipped?.(id)) { this.deps.log(`[SafePeek] Static analysis skipped (file is quarantined): ${f.name}`); return; }
    f.analysisStatus = 'analyzing'; this.store.save(); this.deps.emitChange();
    this.deps.log(`[SafePeek] Static analysis started: ${f.name}`);
    this.events.addEvent('analysis-started', 'Static analysis started', { fileName: f.name, folder: f.sourceFolder });
    let res: AnalysisResult;
    // A file that changes while it is being analyzed would leave a result that describes bytes that no longer exist: re-run (bounded) against the new state.
    for (let attempt = 0; ; attempt++) {
      const before = await statSig(f.path);
      try { res = await withTimeout((this.deps.analyze ?? analyzeFile)(f.path, { name: f.name }), this.deps.timeoutMs ?? ANALYSIS_TIMEOUT_MS); }
      catch (e) { this.deps.log(`[SafePeek] Analysis ${e instanceof TimeoutError ? 'timed out' : 'crashed'} for ${f.name}: ${(e as Error).message}`); res = failed(f, e instanceof TimeoutError ? 'Analysis timed out; the result is incomplete.' : (e as Error).message); break; }
      if (res.status === 'failed') break;
      const after = await statSig(f.path);
      if (!before || !after || before === after) { if (after && after !== f.signature) { f.signature = after; } break; }
      if (attempt >= 2) { res.partialReasons.push('The file kept changing while it was being analyzed; the result may be out of date. Rescan once it stops changing.'); res.status = 'partial'; f.signature = after; break; }
      this.deps.log(`[SafePeek] File changed during analysis, analyzing again: ${f.name}`);
      f.signature = after;
    }
    const cur = this.find(id);
    if (!cur) return; // record replaced (file changed) or removed: a newer record has its own analysis
    if (this.deps.isSkipped?.(id)) { this.deps.log(`[SafePeek] Static analysis result discarded (file was quarantined meanwhile): ${f.name}`); return; }
    cur.contentStatus = 'NOT_STARTED';
    cur.threatAnalysisStatus = 'NOT_STARTED'; cur.threatStatus = undefined; cur.threatScore = undefined; cur.riskLevel = 'unknown'; // any earlier verdict is stale now
    cur.analysis = res; cur.sha256 = res.sha256; cur.mimeType = res.identity.mimeType ?? cur.mimeType;
    cur.detectedType = res.identity.detectedType; cur.detectedUrls = res.urls;
    cur.indicators = res.indicators.map((i) => ({ type: i.type, severity: i.severity, title: i.title, description: i.description, evidence: i.evidence, code: i.code })) as DetectedFile['indicators'];
    cur.analysisStatus = res.status === 'failed' ? 'failed' : 'complete';
    if (res.status !== 'failed') cur.status = 'analyzed' as DetectedFile['status'];
    this.store.save();
    const n = res.indicators.length;
    const msg = res.status === 'failed' ? `Static analysis failed: ${res.partialReasons[0] ?? 'unknown error'}` : `Static analysis ${res.status === 'partial' ? 'partially completed' : 'completed'} — ${res.identity.detectedType}, ${n} indicator${n === 1 ? '' : 's'}${res.sha256 ? ', SHA-256 calculated' : ''}`;
    this.deps.log(`[SafePeek] ${msg}: ${f.name}`);
    this.events.addEvent(res.status === 'failed' ? 'analysis-failed' : 'analysis-completed', msg, { fileName: f.name, folder: f.sourceFolder });
    if (res.status !== 'failed') { try { this.deps.onAnalyzed?.(cur); } catch (e) { this.deps.log(`[SafePeek] Content enqueue failed: ${(e as Error).message}`); } }
    else { try { this.deps.onFailed?.(cur); } catch (e) { this.deps.log(`[SafePeek] Threat enqueue failed: ${(e as Error).message}`); } }
  }
}

const ANALYSIS_TIMEOUT_MS = 120_000;
class TimeoutError extends Error {}
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout;
  return Promise.race([p, new Promise<T>((_, rej) => { t = setTimeout(() => rej(new TimeoutError(`timed out after ${Math.round(ms / 1000)}s`)), ms); t.unref?.(); })]).finally(() => clearTimeout(t));
}
async function statSig(p: string): Promise<string | null> { try { const st = await fs.promises.stat(p); return `${st.size}:${st.mtimeMs}`; } catch { return null; } }

function failed(f: DetectedFile, reason: string): AnalysisResult {
  const now = new Date().toISOString();
  return { version: 1, status: 'failed', partialReasons: [reason], startedAt: now, completedAt: now, analysisTimestamp: now,
    identity: { name: f.name, path: f.path, extension: f.extension, declaredType: null, detectedType: 'Unknown', detectedTypeId: 'unknown', mimeType: null, category: 'unknown', typeMismatch: false, executionPerformed: false },
    metadata: { size: f.size, createdAt: f.createdAt, modifiedAt: f.modifiedAt, accessedAt: null, sizeClass: 'normal' }, sha256: null, urls: [], embeddedObjects: [], indicators: [] };
}
