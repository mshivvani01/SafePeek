import { randomUUID } from 'node:crypto';
import type { ThreatAssessment } from '../threat/types';
import { JsonStore } from './jsonStore';
import type { ThreatHistoryEntry } from './types';

interface HFile { version: 1; entries: ThreatHistoryEntry[] }
const isHFile = (x: unknown): x is HFile => typeof x === 'object' && x !== null && (x as HFile).version === 1 && Array.isArray((x as HFile).entries);
const MAX = 2000;

/** Persisted record of every completed Phase 5 assessment plus the decision taken (quarantine, restore, ...). */
export class HistoryService {
  private store: JsonStore<HFile>;
  constructor(file: string, log: (m: string) => void = () => undefined, private now: () => string = () => new Date().toISOString()) {
    this.store = new JsonStore<HFile>(file, () => ({ version: 1, entries: [] }), isHFile, log);
    const n = this.store.data.entries.length;
    this.store.data.entries = this.store.data.entries.filter((e) => !!e && typeof e === 'object' && typeof e.id === 'string' && typeof e.fileId === 'string' && typeof e.fileName === 'string' && typeof e.status === 'string' && typeof e.score === 'number');
    if (this.store.data.entries.length < n) log(`[SafePeek] Ignored ${n - this.store.data.entries.length} malformed history record(s)`);
  }
  flush() { return this.store.flush(); }
  record(f: { id: string; name: string; sha256: string | null }, a: ThreatAssessment): ThreatHistoryEntry {
    const e: ThreatHistoryEntry = { id: randomUUID(), fileId: f.id, fileName: f.name, sha256: f.sha256, status: a.status, score: a.score, assessedAt: a.analyzedAt, action: '—' };
    this.store.data.entries.unshift(e); this.store.data.entries = this.store.data.entries.slice(0, MAX); this.store.save(); return e;
  }
  /** Sets the decision on the most recent assessment of this file. */
  setAction(fileId: string, action: string, opts: { onlyIfEmpty?: boolean } = {}) {
    const e = this.store.data.entries.find((x) => x.fileId === fileId); if (!e) return;
    if (opts.onlyIfEmpty && e.action !== '—') return;
    e.action = action; e.actionAt = this.now(); this.store.save();
  }
  list(limit = 500): ThreatHistoryEntry[] { return this.store.data.entries.slice(0, Math.max(1, Math.min(limit, MAX))); }
}
