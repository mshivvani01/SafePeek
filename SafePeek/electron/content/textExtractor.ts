import fs from 'node:fs';
import type { ContentExtractor, ExtractContext, ExtractOutput } from './types';
import { LIMITS } from './limits';
import { extractUrls } from '../analysis/urls';
import { sanitizeText } from './sanitizer';

const TEXT_EXT = new Set(['txt', 'csv', 'tsv', 'json', 'log', 'md', 'xml', 'ini', 'cfg', 'conf', 'yml', 'yaml', 'rtf', 'html', 'htm', 'js', 'vbs', 'ps1', 'bat', 'cmd', 'sh', 'py']);

/** Decodes a bounded buffer. BOM-aware; falls back to Latin-1 with a warning when UTF-8 is invalid. Returns null if the data looks binary. */
export function decodeText(buf: Buffer): { text: string; warn?: string } | null {
  if (buf[0] === 0xff && buf[1] === 0xfe) return { text: buf.subarray(2).toString('utf16le') };
  if (buf[0] === 0xfe && buf[1] === 0xff) { const sw = Buffer.from(buf.subarray(2)); sw.swap16(); return { text: sw.toString('utf16le') }; }
  const b = buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf ? buf.subarray(3) : buf;
  let nul = 0, ctl = 0; const n = Math.min(b.length, 8192);
  for (let i = 0; i < n; i++) { if (b[i] === 0) nul++; else if (b[i] < 9 || (b[i] > 13 && b[i] < 32)) ctl++; }
  if (nul > 0 || ctl > n * 0.05) return null;
  const s = b.toString('utf8');
  if (s.includes('\uFFFD')) return { text: b.toString('latin1'), warn: 'Text is not valid UTF-8; shown using a Latin-1 fallback, so some characters may be wrong.' };
  return { text: s };
}

/** Minimal CSV parser (quotes aware) producing a bounded table. */
export function parseCsv(text: string, delim = ','): string[][] {
  const rows: string[][] = []; let row: string[] = [], cur = '', q = false;
  for (let i = 0; i < text.length && rows.length < LIMITS.MAX_TABLE_ROWS + 1; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === delim) { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); rows.push(row.slice(0, LIMITS.MAX_TABLE_COLS)); row = []; cur = ''; }
    else if (c !== '\r') cur += c;
  }
  if (cur || row.length) { row.push(cur); rows.push(row.slice(0, LIMITS.MAX_TABLE_COLS)); }
  return rows;
}

export const textExtractor: ContentExtractor = {
  id: 'text',
  canHandle: (c: ExtractContext) => ['text', 'html', 'script', 'empty'].includes(c.typeId) || (c.typeId === 'unknown' && TEXT_EXT.has(c.name.split('.').pop()?.toLowerCase() ?? '')),
  async extract(ctx): Promise<ExtractOutput> {
    const fh = await fs.promises.open(ctx.path, 'r');
    let buf: Buffer;
    try { const want = Math.min(ctx.size, LIMITS.TEXT_PREVIEW_BYTES); buf = Buffer.alloc(want); const { bytesRead } = await fh.read(buf, 0, want, 0); buf = buf.subarray(0, bytesRead); } finally { await fh.close(); }
    const dec = decodeText(buf);
    if (!dec) return { status: 'UNSUPPORTED', previewType: 'unsupported', previewAvailable: false, unsupportedReason: 'This file looks like binary data, not text. No text preview is shown.', warnings: ['Binary data detected.'] };
    const { text } = sanitizeText(dec.text);
    const byteTrunc = ctx.size > LIMITS.TEXT_PREVIEW_BYTES;
    const ext = ctx.name.split('.').pop()?.toLowerCase();
    const out: ExtractOutput = {
      extractedText: text, truncated: byteTrunc, warnings: dec.warn ? [dec.warn] : [],
      links: extractUrls(text, LIMITS.MAX_LINKS).map((url) => ({ url, source: 'text' }))
    };
    if (byteTrunc) out.truncationNote = `Showing first ${Math.round(LIMITS.TEXT_PREVIEW_BYTES / 1024)} KB of ${(ctx.size / 1048576).toFixed(1)} MB`;
    if (ext === 'csv' || ext === 'tsv') { const rows = parseCsv(text, ext === 'tsv' ? '\t' : ','); out.tables = [{ name: ctx.name, rows: rows.slice(0, LIMITS.MAX_TABLE_ROWS), truncated: rows.length > LIMITS.MAX_TABLE_ROWS || byteTrunc }]; }
    if (ctx.typeId === 'html') out.warnings!.push('HTML is shown as plain text and was never rendered.');
    if (ctx.typeId === 'script') out.warnings!.push('Script source is shown as text only. It was not executed.');
    return out;
  }
};
