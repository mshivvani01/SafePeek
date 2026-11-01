import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import chokidar, { FSWatcher } from 'chokidar';
import { FileEventService, FileEventDeps } from './fileEventService';
import { isRootDir, isUncPath, pathKey, validatePath } from './paths';
import type { StateStore } from './store';
import type { DetectedFile, MonitoredFolder, MonitoringStatus } from './types';

export class MonitoringAgent {
  readonly events: FileEventService;
  private watchers = new Map<string, FSWatcher>();
  private folderErrors: Record<string, string> = {};
  private lastError: string | null = null;

  constructor(private store: StateStore, private deps: Omit<FileEventDeps, 'isFolderActive'>) {
    this.events = new FileEventService(store, { ...deps, isFolderActive: (id) => this.store.state.monitoringEnabled && this.watchers.has(id) });
  }
  private log = (m: string) => this.deps.log(m);

  async start(): Promise<void> {
    if (!this.store.state.monitoringEnabled) { this.log('[SafePeek] Monitoring disabled in saved settings'); this.deps.emitChange(); return; }
    for (const f of this.store.state.folders) this.watchFolder(f);
    this.log('[SafePeek] Monitoring started');
    this.events.addEvent('monitoring-started', `Monitoring started (${this.watchers.size} folder${this.watchers.size === 1 ? '' : 's'})`);
  }

  private setFolderError(id: string, msg: string, label: string) {
    this.folderErrors[id] = msg; this.lastError = msg;
    this.log(`[SafePeek] Watcher problem for ${label}: ${msg}`);
    this.events.addEvent('watcher-error', msg, { folder: label });
  }

  private watchFolder(f: MonitoredFolder) {
    if (!f.enabled || this.watchers.has(f.id)) return;
    delete this.folderErrors[f.id];
    try {
      if (!fs.statSync(f.path).isDirectory()) throw new Error('Not a folder');
      fs.accessSync(f.path, fs.constants.R_OK);
    } catch (e) { this.setFolderError(f.id, `Cannot watch folder: ${(e as Error).message}`, f.label); return; }
    const w = chokidar.watch(f.path, {
      ignoreInitial: true, depth: 1, persistent: true, ignorePermissionErrors: true,
      ignored: (p: string) => p !== f.path && path.basename(p).startsWith('.')
    });
    const run = (kind: 'add' | 'change') => (p: string) => { this.events.handle(f, p, kind).catch((e) => this.log(`[SafePeek] ${(e as Error).message}`)); };
    w.on('add', run('add')).on('change', run('change'))
      .on('error', (e) => this.setFolderError(f.id, `Watcher error: ${(e as Error).message}`, f.label))
      .on('ready', () => this.log(`[SafePeek] Watching: ${f.path}`));
    this.watchers.set(f.id, w);
  }

  private async unwatch(id: string) { const w = this.watchers.get(id); this.watchers.delete(id); if (w) await w.close(); }
  async stopAll(): Promise<void> { this.events.cancelAll(); await Promise.all([...this.watchers.keys()].map((id) => this.unwatch(id))); }

  async setMonitoringEnabled(enabled: boolean) {
    this.store.state.monitoringEnabled = enabled; this.store.save();
    if (enabled) await this.start();
    else { await this.stopAll(); this.log('[SafePeek] Monitoring stopped'); this.events.addEvent('monitoring-stopped', 'Monitoring paused by user'); }
    this.deps.emitChange();
  }

  async addFolder(rawPath: unknown): Promise<MonitoredFolder> {
    const p = validatePath(rawPath);
    if (!fs.statSync(p).isDirectory()) throw new Error('Not a folder');
    if (isRootDir(p)) throw new Error('Drive roots cannot be monitored');
    if (isUncPath(p)) throw new Error('Network (UNC) folders cannot be monitored reliably. Choose a folder on a local drive.');
    try { fs.accessSync(p, fs.constants.R_OK); } catch { throw new Error('SafePeek cannot read this folder (access denied).'); }
    try { if (fs.lstatSync(p).isSymbolicLink()) throw new Error('symlink'); } catch (e) { if ((e as Error).message === 'symlink') throw new Error('Shortcuts/symbolic links cannot be monitored. Choose the real folder.'); throw e; }
    if (this.deps.isExcluded?.(p)) throw new Error('SafePeek\'s quarantine folder cannot be monitored');
    if (this.store.state.folders.some((f) => pathKey(f.path) === pathKey(p))) throw new Error('Folder is already monitored');
    const f: MonitoredFolder = { id: randomUUID(), path: p, label: path.basename(p) || p, enabled: true, isDefault: false, addedAt: new Date().toISOString() };
    this.store.state.folders.push(f); this.store.save();
    if (this.store.state.monitoringEnabled) this.watchFolder(f);
    this.events.addEvent('folder-added', `Now monitoring ${f.label}`, { folder: f.label });
    return f;
  }

  async removeFolder(id: string) {
    const f = this.store.state.folders.find((x) => x.id === id);
    if (!f) return;
    if (f.isDefault) throw new Error('The Downloads folder can be disabled but not removed');
    await this.unwatch(id); delete this.folderErrors[id];
    this.store.state.folders = this.store.state.folders.filter((x) => x.id !== id); this.store.save();
    this.events.addEvent('folder-removed', `Stopped monitoring ${f.label}`, { folder: f.label });
  }

  async setFolderEnabled(id: string, enabled: boolean) {
    const f = this.store.state.folders.find((x) => x.id === id);
    if (!f) return;
    f.enabled = enabled; this.store.save();
    if (!enabled) { await this.unwatch(id); delete this.folderErrors[id]; } else if (this.store.state.monitoringEnabled) this.watchFolder(f);
    this.deps.emitChange();
  }

  getFiles(): DetectedFile[] { return this.store.state.files; }
  getEvents(limit = 100) { return this.store.state.events.slice(0, limit); }
  getStatus(): MonitoringStatus {
    const last = this.store.state.files[0];
    return {
      enabled: this.store.state.monitoringEnabled, active: this.watchers.size > 0, folders: this.store.state.folders,
      folderErrors: { ...this.folderErrors }, lastError: this.lastError,
      lastDetection: last ? { fileName: last.name, at: last.detectedAt } : null, filesDetected: this.store.state.files.length
    };
  }
}
