import zlib from 'node:zlib';

function crc32(b: Buffer): number { let c, crc = ~0; for (const x of b) { c = (crc ^ x) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1; crc = (crc >>> 8) ^ c; } return ~crc >>> 0; }

/** Minimal benign ZIP writer (deflate) for test fixtures. */
export function makeZip(files: Record<string, string | Buffer>): Buffer {
  const parts: Buffer[] = [], cd: Buffer[] = []; let off = 0;
  for (const [name, data] of Object.entries(files)) {
    const raw = Buffer.isBuffer(data) ? data : Buffer.from(data), def = zlib.deflateRawSync(raw), nm = Buffer.from(name), crc = crc32(raw);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(def.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nm.length, 26);
    parts.push(lh, nm, def);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(def.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    cd.push(ch, nm); off += 30 + nm.length + def.length;
  }
  const cdb = Buffer.concat(cd), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(cd.length / 2, 8); end.writeUInt16LE(cd.length / 2, 10); end.writeUInt32LE(cdb.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cdb, end]);
}

export const PDF_SAFE = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R /Info << /Title (Test) >> >>\n%%EOF\n');
export const PDF_ACTIVE = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n2 0 obj\n<< /S /URI /URI (https://example.com/page) >>\nendobj\n%%EOF\n');
export const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(32)]);

/** Header-only PE (benign, not runnable): x64 EXE, 1 section (.text), 1 import (KERNEL32.dll). */
export function makePE(): Buffer {
  const b = Buffer.alloc(0x500); b.write('MZ'); b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1'); b.writeUInt16LE(0x8664, 0x84); b.writeUInt16LE(1, 0x86); b.writeUInt16LE(0xf0, 0x94); b.writeUInt16LE(0x0022, 0x96);
  const o = 0x98; b.writeUInt16LE(0x20b, o); b.writeUInt32LE(0x1000, o + 16); b.writeUInt16LE(3, o + 68);
  const dd = o + 112; b.writeUInt32LE(0x2000, dd + 8); b.writeUInt32LE(40, dd + 12); // import dir RVA 0x2000
  const s = o + 0xf0; b.write('.text', s, 'latin1'); b.writeUInt32LE(0x1000, s + 8); b.writeUInt32LE(0x1000, s + 12); b.writeUInt32LE(0x200, s + 16); b.writeUInt32LE(0x200, s + 20);
  // section maps RVA 0x1000-0x2000 -> file 0x200; put import table at RVA 0x1100 instead
  b.writeUInt32LE(0x1100, dd + 8);
  const imp = 0x200 + 0x100; b.writeUInt32LE(0x1200, imp + 12); b.write('KERNEL32.dll\0', 0x200 + 0x200, 'latin1');
  return b;
}
