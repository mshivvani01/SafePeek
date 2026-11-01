import yauzl from 'yauzl';
import type { ZipHandle } from '../analysis/zip';
import { LIMITS } from './limits';

/** Reads one package part into memory with a hard byte cap (decompression-bomb safe). Never writes to disk. */
export function readPart(h: ZipHandle, name: string, cap: number = LIMITS.MAX_OFFICE_PART_BYTES): Promise<{ text: string; truncated: boolean } | null> {
  const e = h.entries.find((x) => x.name === name) ?? h.entries.find((x) => x.name.toLowerCase() === name.toLowerCase());
  return readEntry(h, e, cap);
}
export function readEntry(h: ZipHandle, e: (yauzl.Entry & { name: string }) | undefined, cap: number = LIMITS.MAX_OFFICE_PART_BYTES): Promise<{ text: string; truncated: boolean } | null> {
  return new Promise((resolve) => {
    if (!e || e.isEncrypted()) return resolve(null);
    h.zip.openReadStream(e, (err, stream) => {
      if (err || !stream) return resolve(null);
      const chunks: Buffer[] = []; let n = 0, done = false, truncated = false;
      const fin = () => { if (!done) { done = true; resolve({ text: Buffer.concat(chunks).toString('utf8'), truncated }); } };
      stream.on('data', (c: Buffer) => { n += c.length; if (n > cap) { truncated = true; stream.destroy(); fin(); } else chunks.push(c); });
      stream.on('end', fin); stream.on('close', fin); stream.on('error', () => { if (!done) { done = true; resolve(null); } });
    });
  });
}
