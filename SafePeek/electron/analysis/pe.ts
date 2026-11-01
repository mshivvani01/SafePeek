import fs from 'node:fs';
import type { PEInfo } from './types';

const MACHINES: Record<number, string> = { 0x14c: 'x86 (32-bit)', 0x8664: 'x64 (64-bit)', 0x1c0: 'ARM', 0xaa64: 'ARM64', 0x200: 'IA-64' };
const SUBSYSTEMS: Record<number, string> = { 1: 'Native', 2: 'Windows GUI', 3: 'Windows Console', 5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE', 10: 'EFI Application' };
const PE_READ = 4 * 1024 * 1024;
const MAX_IMPORTS = 256;

/** Read-only PE header parser (no library, no execution). Bounds-checked everywhere; throws only on non-PE input. */
export async function inspectPE(file: string, size: number): Promise<PEInfo> {
  const fh = await fs.promises.open(file, 'r');
  let b: Buffer;
  try { const n = Math.min(size, PE_READ); b = Buffer.alloc(n); const r = await fh.read(b, 0, n, 0); b = b.subarray(0, r.bytesRead); } finally { await fh.close(); }
  return parsePE(b, size);
}

export function parsePE(b: Buffer, fileSize = b.length): PEInfo {
  const ok = (o: number, n: number) => o >= 0 && o + n <= b.length;
  if (!ok(0, 0x40) || b.readUInt16LE(0) !== 0x5a4d) throw new Error('Not an MZ file');
  const pe = b.readUInt32LE(0x3c);
  if (!ok(pe, 24) || b.readUInt32LE(pe) !== 0x4550) throw new Error('PE signature not found');
  const machine = b.readUInt16LE(pe + 4), nSec = b.readUInt16LE(pe + 6), optSize = b.readUInt16LE(pe + 20), chars = b.readUInt16LE(pe + 22);
  const opt = pe + 24;
  let complete = true;
  const info: PEInfo = {
    architecture: MACHINES[machine] ?? `Unknown (0x${machine.toString(16)})`, kind: chars & 0x2000 ? 'DLL' : chars & 0x2 ? 'EXE' : 'Other',
    subsystem: null, entryPointRva: null, sections: [], imports: [], importsTruncated: false, hasSignatureBlock: false, signatureVerified: false, isDotNet: false, parseComplete: true
  };
  if (!ok(opt, Math.min(optSize, 96))) { info.parseComplete = false; return info; }
  const magic = b.readUInt16LE(opt);
  const plus = magic === 0x20b;
  info.entryPointRva = b.readUInt32LE(opt + 16);
  info.subsystem = SUBSYSTEMS[b.readUInt16LE(opt + 68)] ?? null;
  const ddBase = opt + (plus ? 112 : 96);
  const dd = (i: number): [number, number] | null => (ok(ddBase + i * 8, 8) && i * 8 + 8 <= optSize - (plus ? 112 : 96) ? [b.readUInt32LE(ddBase + i * 8), b.readUInt32LE(ddBase + i * 8 + 4)] : null);

  const secs: { va: number; vs: number; raw: number; rawSize: number }[] = [];
  const st = opt + optSize;
  for (let i = 0; i < Math.min(nSec, 96); i++) {
    const o = st + i * 40;
    if (!ok(o, 40)) { complete = false; break; }
    info.sections.push(b.toString('latin1', o, o + 8).replace(/\0+$/, '').replace(/[^\x20-\x7e]/g, '?'));
    secs.push({ vs: b.readUInt32LE(o + 8), va: b.readUInt32LE(o + 12), rawSize: b.readUInt32LE(o + 16), raw: b.readUInt32LE(o + 20) });
  }
  const off = (rva: number) => { for (const s of secs) if (rva >= s.va && rva < s.va + Math.max(s.vs, s.rawSize)) return s.raw + (rva - s.va); return -1; };

  const cert = dd(4); if (cert && cert[0] > 0 && cert[1] > 0 && cert[0] < fileSize) info.hasSignatureBlock = true; // presence only; NOT verified
  const clr = dd(14); if (clr && clr[0] > 0) info.isDotNet = true;
  const imp = dd(1);
  if (imp && imp[0] > 0) {
    let o = off(imp[0]);
    if (o < 0 || !ok(o, 20)) complete = false;
    else {
      for (let n = 0; ; n++) {
        if (n >= MAX_IMPORTS) { info.importsTruncated = true; break; }
        if (!ok(o + n * 20, 20)) { complete = false; break; }
        const d = o + n * 20;
        if (b.readUInt32LE(d + 12) === 0 && b.readUInt32LE(d) === 0) break;
        const no = off(b.readUInt32LE(d + 12));
        if (no < 0 || no >= b.length) { complete = false; continue; }
        let e = no; while (e < b.length && e - no < 128 && b[e] !== 0) e++;
        info.imports.push(b.toString('latin1', no, e).replace(/[^\x20-\x7e]/g, '?'));
      }
    }
  }
  info.parseComplete = complete;
  return info;
}
