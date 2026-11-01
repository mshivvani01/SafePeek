import yauzl from 'yauzl';
import type { ArchiveEntry, ArchiveInfo } from './types';
import { DANGEROUS_EXTENSIONS, extOf } from './extensions';

export const MAX_ENTRIES = 5000;
export const MAX_PART_BYTES = 1024 * 1024; // cap when reading a single entry into memory (Office XML parts)

/** Zip Slip style names: absolute, drive-letter, UNC, or any ".." segment. Entries are NEVER written to disk by SafePeek. */
export function isUnsafeEntryName(n: string): boolean {
  const s = n.replace(/\\/g, '/');
  return s.startsWith('/') || /^[a-zA-Z]:/.test(s) || s.startsWith('//') || s.split('/').includes('..') || s.includes('\0');
}

export interface ZipHandle { zip: yauzl.ZipFile; entries: (yauzl.Entry & { name: string })[]; truncated: boolean }

/** Lists the central directory only (decodeStrings:false so malicious names are inspected, not rejected). No extraction. */
export function openZip(file: string): Promise<ZipHandle> {
  return new Promise((resolve, reject) => {
    yauzl.open(file, { lazyEntries: true, autoClose: false, decodeStrings: false, validateEntrySizes: true }, (err, zip) => {
      if (err || !zip) return reject(err ?? new Error('Cannot open ZIP'));
      const entries: ZipHandle['entries'] = [];
      let truncated = false;
      zip.on('entry', (e: yauzl.Entry) => {
        const raw = e.fileName as unknown as Buffer;
        const name = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw);
        entries.push(Object.assign(e, { name }));
        if (entries.length >= MAX_ENTRIES) { truncated = true; zip.close(); resolve({ zip, entries, truncated }); return; }
        zip.readEntry();
      });
      zip.on('end', () => resolve({ zip, entries, truncated }));
      zip.on('error', reject);
      zip.readEntry();
    });
  });
}

/** In-memory read of one entry with a hard byte cap (decompression-bomb safe). Returns null if encrypted/oversized/unreadable. */
export function readEntryText(h: ZipHandle, e: yauzl.Entry, cap = MAX_PART_BYTES): Promise<string | null> {
  return new Promise((resolve) => {
    if (e.isEncrypted()) return resolve(null);
    h.zip.openReadStream(e, (err, stream) => {
      if (err || !stream) return resolve(null);
      const chunks: Buffer[] = []; let n = 0, done = false;
      const fin = (v: string | null) => { if (!done) { done = true; resolve(v); } };
      stream.on('data', (c: Buffer) => { n += c.length; if (n > cap) { stream.destroy(); fin(Buffer.concat(chunks).toString('utf8')); } else chunks.push(c); });
      stream.on('end', () => fin(Buffer.concat(chunks).toString('utf8')));
      stream.on('error', () => fin(null));
      stream.on('close', () => fin(Buffer.concat(chunks).toString('utf8')));
    });
  });
}

export function toArchiveInfo(h: ZipHandle, format = 'ZIP'): ArchiveInfo {
  const entries: ArchiveEntry[] = h.entries.map((e) => ({
    name: e.name, size: e.uncompressedSize, isDirectory: /\/$/.test(e.name), encrypted: e.isEncrypted(),
    dangerous: !/\/$/.test(e.name) && DANGEROUS_EXTENSIONS.has(extOf(e.name.split('/').pop() ?? '')), unsafePath: isUnsafeEntryName(e.name)
  }));
  return {
    format, entryCount: entries.length, entries, truncated: h.truncated, encryptedEntries: entries.filter((e) => e.encrypted).length,
    totalUncompressed: entries.reduce((a, e) => a + e.size, 0), extracted: false
  };
}
