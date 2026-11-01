import fs from 'node:fs';
import type { AgentState } from './types';
import { atomicWriteFile, setAsideCorrupt } from '../util/atomicWrite';
import { MAX_STORED_EVENTS, MAX_STORED_FILES } from './config';

type Log = (msg: string) => void;

/** JSON state in userData. Atomic writes (tmp + rename); corrupted files are set aside, never crash the app. */
export class StateStore {
  state: AgentState;
  private chain: Promise<void> = Promise.resolve();

  constructor(readonly file: string, private downloadsPath: string, private log: Log = console.log) {
    this.state = this.load();
  }

  private defaults(): AgentState {
    return {
      version: 1, monitoringEnabled: true, files: [], events: [],
      folders: [{ id: 'downloads', path: this.downloadsPath, label: 'Downloads', enabled: true, isDefault: true, addedAt: new Date().toISOString() }]
    };
  }

  private load(): AgentState {
    let st: AgentState | null = null;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (raw?.version === 1 && typeof raw.monitoringEnabled === 'boolean' && Array.isArray(raw.folders) && Array.isArray(raw.files) && Array.isArray(raw.events)) st = raw;
      else throw new Error('unexpected state shape');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') {
        this.log(`[SafePeek] State file unreadable (${(e as Error).message}); starting fresh`);
        setAsideCorrupt(this.file);
      }
    }
    if (!st) { st = this.defaults(); }
    st = this.sanitize(st);
    const d = st.folders.find((f) => f.isDefault);
    if (d) d.path = this.downloadsPath; // follows the current Windows user
    return st;
  }

  /** Drops malformed records (null, wrong types, missing id/path) so one bad entry can never crash a lookup; keeps everything valid. */
  private sanitize(st: AgentState): AgentState {
    const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
    const before = st.files.length + st.folders.length + st.events.length;
    st.files = st.files.filter((f) => !!f && typeof f === 'object' && isStr(f.id) && isStr(f.path) && isStr(f.name) && typeof f.signature === 'string');
    st.folders = st.folders.filter((f) => !!f && typeof f === 'object' && isStr(f.id) && isStr(f.path) && typeof f.enabled === 'boolean');
    st.events = st.events.filter((e) => !!e && typeof e === 'object' && isStr(e.id) && isStr(e.type) && typeof e.message === 'string');
    if (!st.folders.some((f) => f.isDefault)) st.folders.unshift(this.defaults().folders[0]);
    const after = st.files.length + st.folders.length + st.events.length;
    if (after < before) this.log(`[SafePeek] Ignored ${before - after} malformed record(s) in the saved state`);
    return st;
  }

  save(): void {
    this.state.files = this.state.files.slice(0, MAX_STORED_FILES);
    this.state.events = this.state.events.slice(0, MAX_STORED_EVENTS);
    this.chain = this.chain.then(async () => {
      await atomicWriteFile(this.file, JSON.stringify(this.state));
    }).catch((e) => this.log(`[SafePeek] Failed to save state: ${(e as Error).message}`));
  }
  flush(): Promise<void> { return this.chain; }
}
