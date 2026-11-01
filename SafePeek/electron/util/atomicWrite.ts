import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

const sleepSync = (ms: number) => { try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch { /* not available: retry immediately */ } };
const TRANSIENT = new Set(['EPERM', 'EBUSY', 'EACCES']);

/** Writes `data` to `file` via tmp + rename. On Windows, rename over an existing file can fail transiently (EPERM/EBUSY) while an indexer or antivirus holds it, so it is retried a few times. */
export function atomicWriteFileSync(file: string, data: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, data, 'utf8');
  let last: unknown;
  for (let i = 0; i < 5; i++) {
    try { fs.renameSync(tmp, file); return; }
    catch (e) { last = e; if (!TRANSIENT.has((e as NodeJS.ErrnoException).code ?? '')) break; sleepSync(25 * (i + 1)); }
  }
  try { fs.unlinkSync(tmp); } catch { /* tmp already gone */ }
  throw last;
}
export async function atomicWriteFile(file: string, data: string): Promise<void> {
  await fs.promises.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  await fs.promises.writeFile(tmp, data, 'utf8');
  let last: unknown;
  for (let i = 0; i < 5; i++) {
    try { await fs.promises.rename(tmp, file); return; }
    catch (e) { last = e; if (!TRANSIENT.has((e as NodeJS.ErrnoException).code ?? '')) break; await new Promise((r) => setTimeout(r, 25 * (i + 1))); }
  }
  await fs.promises.unlink(tmp).catch(() => undefined);
  throw last;
}
/** Keeps at most `keep` `<file>.corrupt-*` copies so a repeatedly corrupted store cannot fill the disk. */
export function setAsideCorrupt(file: string, keep = 3): void {
  try { fs.renameSync(file, `${file}.corrupt-${Date.now()}`); } catch { return; }
  try {
    const dir = path.dirname(file); const base = `${path.basename(file)}.corrupt-`;
    const old = fs.readdirSync(dir).filter((n) => n.startsWith(base)).sort();
    for (const n of old.slice(0, Math.max(0, old.length - keep))) fs.unlinkSync(path.join(dir, n));
  } catch { /* housekeeping only */ }
}
