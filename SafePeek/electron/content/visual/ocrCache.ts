import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { LIMITS } from '../limits';

/**
 * OCR cache keyed by the SHA-256 of the exact bytes that were read (not by path, name or mtime), so a changed file can never hit a stale entry.
 * Only fully COMPLETED results are stored. The key also covers a signature of the limits and engine version, so changing a bound invalidates old entries.
 */
export const CACHE_VERSION = 'p8-1';
const SIG = JSON.stringify([CACHE_VERSION, LIMITS.OCR_WORK_MAX_SIDE, LIMITS.OCR_WORK_MAX_PIXELS, LIMITS.QR_WORK_MAX_SIDE, LIMITS.MAX_QR_CODES, LIMITS.MAX_PDF_OCR_PAGES, LIMITS.MAX_PDF_VISUAL_PAGES, LIMITS.PDF_PAGE_TEXT_MIN_ALNUM, LIMITS.MAX_OCR_TEXT]);
export const sha256Hex = (b: Buffer): string => crypto.createHash('sha256').update(b).digest('hex');
const okKey = (k: string) => /^[a-f0-9]{64}$/.test(k);
const file = (dir: string, key: string) => path.join(dir, `${key}.json`);

export async function readOcrCache<T>(dir: string | undefined, sha: string, kind: string): Promise<T | null> {
  if (!dir || !okKey(sha)) return null;
  try {
    const o = JSON.parse(await fs.promises.readFile(file(dir, sha), 'utf8'));
    return o && o.sig === SIG && o.kind === kind && o.sha === sha && o.data ? (o.data as T) : null;
  } catch { return null; }
}

export async function writeOcrCache(dir: string | undefined, sha: string, kind: string, data: unknown): Promise<void> {
  if (!dir || !okKey(sha)) return;
  try {
    await fs.promises.mkdir(dir, { recursive: true });
    const tmp = file(dir, `${sha}.${process.pid}.tmp`);
    await fs.promises.writeFile(tmp, JSON.stringify({ sig: SIG, kind, sha, savedAt: Date.now(), data }), 'utf8');
    await fs.promises.rename(tmp, file(dir, sha));
    const names = (await fs.promises.readdir(dir)).filter((n) => /^[a-f0-9]{64}\.json$/.test(n));
    if (names.length > LIMITS.OCR_CACHE_MAX_ENTRIES) {
      const st = await Promise.all(names.map(async (n) => ({ n, t: (await fs.promises.stat(path.join(dir, n))).mtimeMs })));
      for (const x of st.sort((a, b) => a.t - b.t).slice(0, names.length - LIMITS.OCR_CACHE_MAX_ENTRIES)) await fs.promises.unlink(path.join(dir, x.n)).catch(() => undefined);
    }
  } catch { /* the cache is an optimization; failures are ignored */ }
}
