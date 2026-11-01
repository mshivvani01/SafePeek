import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { DEFAULT_STABILITY, StabilityOptions, isTemporaryFile } from './config';
import { isInside, pathKey } from './paths';
import { waitForStable } from './stability';
import type { StateStore } from './store';
import type { AgentEvent, AgentEventType, DetectedFile, MonitoredFolder } from './types';

export interface FileEventDeps {
  emitChange(): void;
  notify(file: DetectedFile, kind: 'new' | 'modified'): void;
  isFolderActive(folderId: string): boolean;
  log(msg: string): void;
  stability?: StabilityOptions;
  /** Phase 3 hook: called after a FileRecord is stored. */
  onFileRecorded?(file: DetectedFile): void;
  /** Phase 6: paths that must never be treated as new files (SafePeek's own quarantine folder). */
  isExcluded?(filePath: string): boolean;
}

/** Watcher event -> filter temp files -> dedupe -> stability check -> FileRecord -> store -> notify. Never reads file content (Phase 3 analysis runs afterwards via onFileRecorded). */
export class FileEventService {
  private inflight = new Map<string, { cancelled: boolean }>();
  constructor(private store: StateStore, private deps: FileEventDeps) {}

  addEvent(type: AgentEventType, message: string, extra: { fileName?: string; folder?: string; riskLevel?: string; score?: number } = {}) {
    const e: AgentEvent = { id: randomUUID(), timestamp: new Date().toISOString(), type, message, ...extra };
    this.store.state.events.unshift(e);
    this.store.save();
    this.deps.emitChange();
  }

  cancelAll() { this.inflight.forEach((t) => (t.cancelled = true)); this.inflight.clear(); }

  async handle(folder: MonitoredFolder, rawPath: string, kind: 'add' | 'change'): Promise<void> {
    const file = path.resolve(rawPath);
    const key = pathKey(file);
    if (!isInside(folder.path, file)) return;
    if (this.deps.isExcluded?.(file)) return;
    if (isTemporaryFile(file)) { this.deps.log(`[SafePeek] Ignoring temporary file: ${path.basename(file)}`); return; }
    if (this.inflight.has(key)) return; // duplicate event while already waiting
    // A quarantined record keeps its original path but the file is no longer there: a new file with the same name is a NEW file, and the quarantined record must survive.
    const live = (f: DetectedFile) => pathKey(f.path) === key && f.quarantineState !== 'QUARANTINED';
    const known = this.store.state.files.find(live);
    if (kind === 'change' && !known) return; // pre-existing file edited; only track files we detected arriving

    this.deps.log(`[SafePeek] File detected: ${path.basename(file)}`);
    const token = { cancelled: false };
    this.inflight.set(key, token);
    try {
      this.deps.log('[SafePeek] Waiting for file stability');
      const res = await waitForStable(file, this.deps.stability ?? DEFAULT_STABILITY, token);
      if (!res.stable) {
        this.deps.log(`[SafePeek] File not processed (${res.reason}${res.error ? `: ${res.error}` : ''}): ${path.basename(file)}`);
        // A file that vanished or was cancelled is normal; one that never settled or could not be read must be visible, not silently skipped.
        if (res.reason === 'timeout' || res.reason === 'error') this.addEvent('watcher-error', res.reason === 'timeout' ? 'File was still changing or locked after 10 minutes, so it was not analyzed. Move or copy it again to retry.' : `File could not be checked: ${res.error ?? 'unknown error'}`, { fileName: path.basename(file), folder: folder.label });
        return;
      }
      if (!this.deps.isFolderActive(folder.id)) return;
      this.deps.log('[SafePeek] File stable');

      const signature = `${res.size}:${res.mtimeMs}`;
      const existing = this.store.state.files.find(live);
      if (existing && existing.signature === signature) return; // same file state already recorded

      const name = path.basename(file);
      const rec: DetectedFile = {
        id: randomUUID(), name, path: file, extension: path.extname(name).slice(1).toLowerCase(), mimeType: 'unknown',
        size: res.size, createdAt: new Date(res.birthtimeMs).toISOString(), modifiedAt: new Date(res.mtimeMs).toISOString(),
        detectedAt: new Date().toISOString(), sourceFolder: folder.label, sourceFolderPath: folder.path, signature,
        sha256: null, status: 'detected', riskLevel: 'unknown', analysisStatus: 'pending',
        contentSummary: null, detectedUrls: [], indicators: [], previewAvailable: false
      };
      const files = this.store.state.files.filter((f) => !live(f));
      this.store.state.files = [rec, ...files];
      this.deps.log('[SafePeek] File record created');
      this.addEvent(existing ? 'file-modified' : 'file-detected', existing ? 'File changed — analysis pending' : 'New file detected — analysis pending', { fileName: name, folder: folder.label });
      this.deps.notify(rec, existing ? 'modified' : 'new');
      try { this.deps.onFileRecorded?.(rec); } catch (e) { this.deps.log(`[SafePeek] Analysis enqueue failed: ${(e as Error).message}`); }
    } catch (e) {
      this.deps.log(`[SafePeek] Error processing ${path.basename(file)}: ${(e as Error).message}`);
    } finally {
      if (this.inflight.get(key) === token) this.inflight.delete(key);
    }
  }
}
