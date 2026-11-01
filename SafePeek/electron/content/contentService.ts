import fs from 'node:fs';
import path from 'node:path';
import type { StateStore } from '../agent/store';
import type { FileEventService } from '../agent/fileEventService';
import type { DetectedFile } from '../agent/types';
import { contextFor, extractContent } from './extractor';
import { shutdownOcr } from './ocr';
import type { ContentResult } from './types';

export interface ContentDeps { log(m: string): void; emitChange(): void; dir: string; /** Phase 8: SHA-256-keyed OCR cache directory. */ visualCacheDir?: string; extract?: (f: DetectedFile) => Promise<ContentResult>; concurrency?: number; /** Phase 7A: true when the file was quarantined; results are discarded. */ isSkipped?(id: string): boolean; /** Phase 5 hook: called once content analysis finished for a file (any outcome, including FAILED/UNSUPPORTED). */ onFinished?(f: { id: string }): void }
const safeId = (id: string) => /^[A-Za-z0-9-]{8,64}$/.test(id);

/**
 * Phase 4 queue. Runs after Phase 3 completes for a file. The full ContentResult (text, tables, thumbnails) is stored in its own JSON
 * file in userData so the shared state file stays small; the FileRecord keeps only status + summary fields.
 */
export class ContentService {
  private queue: string[] = []; private queued = new Set<string>(); private running = 0; private idleWaiters: (() => void)[] = []; private stopped = false;
  constructor(private store: StateStore, private events: FileEventService, private deps: ContentDeps) {}

  enqueue(f: { id: string }) {
    if (this.stopped || this.queued.has(f.id)) return;
    const rec = this.find(f.id); if (rec) { rec.contentStatus = 'QUEUED'; this.store.save(); this.deps.emitChange(); }
    this.queued.add(f.id); this.queue.push(f.id); this.pump();
  }
  resume() { for (const f of this.store.state.files) if (f.analysisStatus === 'complete' && (!f.contentStatus || f.contentStatus === 'NOT_STARTED' || f.contentStatus === 'QUEUED' || f.contentStatus === 'ANALYZING')) this.enqueue(f); }
  rerun(id: string) { if (this.find(id) && !this.queued.has(id)) this.enqueue({ id }); }
  stop() { this.stopped = true; void shutdownOcr(); }
  idle(): Promise<void> { return this.running === 0 && this.queue.length === 0 ? Promise.resolve() : new Promise((r) => this.idleWaiters.push(r)); }

  async get(id: string): Promise<ContentResult | null> {
    if (!safeId(id)) return null;
    try { const o = JSON.parse(await fs.promises.readFile(path.join(this.deps.dir, `${id}.json`), 'utf8')); return o && typeof o === 'object' && typeof o.status === 'string' ? (o as ContentResult) : null; }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') this.deps.log(`[SafePeek] Stored content result unreadable (${(e as Error).message})`); return null; }
  }
  private find(id: string) { return this.store.state.files.find((f) => f.id === id); }
  private pump() {
    while (this.running < (this.deps.concurrency ?? 1) && this.queue.length) {
      const id = this.queue.shift()!; this.running++;
      this.run(id).catch((e) => this.deps.log(`[SafePeek] Content error: ${(e as Error).message}`)).finally(() => {
        this.running--; this.queued.delete(id); this.pump();
        if (this.running === 0 && this.queue.length === 0) { this.idleWaiters.forEach((r) => r()); this.idleWaiters = []; }
      });
    }
  }
  private async run(id: string) {
    const f = this.find(id); if (!f) return;
    if (this.deps.isSkipped?.(id)) { this.deps.log(`[SafePeek] Content analysis skipped (file is quarantined): ${f.name}`); return; }
    f.contentStatus = 'ANALYZING'; this.store.save(); this.deps.emitChange();
    this.deps.log(`[SafePeek] Content analysis started: ${f.name}`);
    this.events.addEvent('content-started', 'Content analysis started', { fileName: f.name, folder: f.sourceFolder });
    let res: ContentResult;
    try { res = await (this.deps.extract ?? ((x) => extractContent(contextFor(x.path, x.name, x.size, x.analysis, { visualCacheDir: this.deps.visualCacheDir }))))(f); }
    catch (e) { const now = new Date().toISOString(); res = { version: 1, status: 'FAILED', extractorType: 'none', fileName: f.name, textLength: 0, links: [], summary: { documentType: 'Unknown', title: null, description: '', pageCount: null, textLength: 0, entities: { organizations: [], people: [], amounts: [], dates: [], emails: [], phones: [] }, keySections: [] }, previewType: 'unsupported', previewAvailable: false, embeddedContentWarning: false, extractionWarnings: ['SafePeek could not analyze the content of this file.'], technicalDetails: (e as Error).message.slice(0, 300), truncated: false, startedAt: now, analyzedAt: now, executionPerformed: false, uploaded: false }; }
    const cur = this.find(id); if (!cur) return; // record replaced by a newer version of the file
    if (this.deps.isSkipped?.(id)) return; // quarantined meanwhile: do not overwrite its verdict
    try { await fs.promises.mkdir(this.deps.dir, { recursive: true }); await fs.promises.writeFile(path.join(this.deps.dir, `${id}.json`), JSON.stringify(res), 'utf8'); }
    catch (e) { this.deps.log(`[SafePeek] Could not store content result: ${(e as Error).message}`); res.extractionWarnings.push('Result could not be saved to disk.'); }
    cur.contentStatus = res.status; cur.contentType = res.extractorType; cur.contentSummary = res.summary.description || null; cur.documentType = res.summary.documentType;
    cur.previewAvailable = res.previewAvailable; cur.previewType = res.previewType; cur.contentTruncated = res.truncated;
    this.store.save();
    const done = res.status === 'COMPLETED' || res.status === 'PARTIAL';
    this.deps.log(`[SafePeek] Content analysis ${res.status}: ${f.name}`);
    this.events.addEvent(res.status === 'FAILED' ? 'content-failed' : 'content-completed', res.status === 'FAILED' ? 'Content analysis failed' : res.status === 'UNSUPPORTED' ? 'Content preview not available for this file type' : res.status === 'PARTIAL' ? 'Content partially extracted' : 'Content extracted', { fileName: f.name, folder: f.sourceFolder });
    if (done && res.previewAvailable) this.events.addEvent('preview-generated', 'Safe preview generated', { fileName: f.name, folder: f.sourceFolder });
    try { this.deps.onFinished?.(cur); } catch (e) { this.deps.log(`[SafePeek] Threat enqueue failed: ${(e as Error).message}`); }
  }
}
