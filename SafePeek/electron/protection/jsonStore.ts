import fs from 'node:fs';
import path from 'node:path';
import { atomicWriteFileSync, setAsideCorrupt } from '../util/atomicWrite';

/** Small JSON persistence helper: atomic writes (tmp + rename), corrupted files are set aside instead of crashing the app. */
export class JsonStore<T> {
  data: T;
  constructor(readonly file: string, private fallback: () => T, private validate: (x: unknown) => x is T, private log: (m: string) => void = () => undefined) {
    this.data = this.load();
  }
  private load(): T {
    try { const raw = JSON.parse(fs.readFileSync(this.file, 'utf8')); if (this.validate(raw)) return raw; throw new Error('unexpected shape'); }
    catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') { this.log(`[SafePeek] ${path.basename(this.file)} unreadable (${(e as Error).message}); starting fresh`); setAsideCorrupt(this.file); }
      return this.fallback();
    }
  }
  /** Synchronous atomic write (tmp + rename): the files are small, and this keeps data safe if the app quits right after an action. */
  save(): void {
    try { atomicWriteFileSync(this.file, JSON.stringify(this.data)); }
    catch (e) { this.log(`[SafePeek] Could not save ${path.basename(this.file)}: ${(e as Error).message}`); }
  }
  flush(): Promise<void> { return Promise.resolve(); }
}
