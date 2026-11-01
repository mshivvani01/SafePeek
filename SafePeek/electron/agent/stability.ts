import fs from 'node:fs/promises';
import type { StabilityOptions } from './config';

export type StabilityResult =
  | { stable: true; size: number; mtimeMs: number; birthtimeMs: number }
  | { stable: false; reason: 'missing' | 'timeout' | 'cancelled' | 'error'; error?: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Polls stat() (never opens/reads content) until size+mtime are unchanged for N consecutive checks. Non-blocking (async). */
export async function waitForStable(file: string, opts: StabilityOptions, token: { cancelled: boolean } = { cancelled: false }): Promise<StabilityResult> {
  const start = Date.now();
  let prev: string | null = null;
  let stableCount = 0;
  for (;;) {
    if (token.cancelled) return { stable: false, reason: 'cancelled' };
    if (Date.now() - start > opts.timeoutMs) return { stable: false, reason: 'timeout' };
    try {
      const st = await fs.stat(file);
      if (!st.isFile()) return { stable: false, reason: 'missing' };
      const sig = `${st.size}:${st.mtimeMs}`;
      stableCount = sig === prev ? stableCount + 1 : 0;
      prev = sig;
      // Windows: a writer that holds the file open exclusively (browsers, download managers) makes open() fail even when size/mtime look steady.
      // Opening for read (without reading any bytes) proves the writer is done; a lock keeps us waiting.
      if (stableCount >= opts.requiredStableChecks) {
        try { const fh = await fs.open(file, 'r'); await fh.close(); }
        catch (e) { const c = (e as NodeJS.ErrnoException).code; if (c === 'EBUSY' || c === 'EPERM' || c === 'EACCES') { stableCount = 0; await sleep(opts.intervalMs); continue; } if (c === 'ENOENT') return { stable: false, reason: 'missing' }; return { stable: false, reason: 'error', error: (e as Error).message }; }
        return { stable: true, size: st.size, mtimeMs: st.mtimeMs, birthtimeMs: st.birthtimeMs };
      }
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return { stable: false, reason: 'missing' };
      if (code !== 'EBUSY' && code !== 'EPERM' && code !== 'EACCES') return { stable: false, reason: 'error', error: (e as Error).message };
      stableCount = 0; // locked by the writer: keep waiting
    }
    await sleep(opts.intervalMs);
  }
}
