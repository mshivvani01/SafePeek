import fs from 'node:fs';
import zlib from 'node:zlib';
import type { PDFInfo } from './types';
import { extractUrls } from './urls';

export const PDF_MAX_SCAN = 16 * 1024 * 1024;
const MAX_OBJSTM = 64;

const lit = (s: string) => s.replace(/\\([()\\])/g, '$1').replace(/[^\x20-\x7e]/g, '').slice(0, 200);

/**
 * Safe RAW TOKEN SCAN (not a full PDF renderer/parser): reads the file as bytes, also inflates /ObjStm streams (size-capped) so actions
 * stored in compressed object streams are not missed. Encrypted PDFs are flagged and their content cannot be inspected.
 * The PDF is never opened by a reader and no action is executed.
 */
export async function inspectPDF(file: string, size: number): Promise<PDFInfo> {
  const n = Math.min(size, PDF_MAX_SCAN);
  const fh = await fs.promises.open(file, 'r');
  let buf: Buffer;
  try { buf = Buffer.alloc(n); const r = await fh.read(buf, 0, n, 0); buf = buf.subarray(0, r.bytesRead); } finally { await fh.close(); }
  return scanPDF(buf, size > n);
}

export function scanPDF(buf: Buffer, truncated = false): PDFInfo {
  let text = buf.toString('latin1');
  let objStreams = 0;
  for (let i = text.indexOf('/ObjStm'); i >= 0 && objStreams < MAX_OBJSTM; i = text.indexOf('/ObjStm', i + 7)) {
    const s = text.indexOf('stream', i); const e = s >= 0 ? text.indexOf('endstream', s) : -1;
    if (s < 0 || e < 0 || e - s > 8 * 1024 * 1024) continue;
    let start = s + 6; if (text[start] === '\r') start++; if (text[start] === '\n') start++;
    try { text += '\n' + zlib.inflateSync(buf.subarray(start, e), { maxOutputLength: 8 * 1024 * 1024 }).toString('latin1'); objStreams++; } catch { /* not flate / damaged */ }
  }
  const count = (re: RegExp) => (text.match(re) ?? []).length;
  const version = /%PDF-(\d\.\d)/.exec(text.slice(0, 1024))?.[1] ?? null;
  const encrypted = /\/Encrypt\b/.test(text);
  let pages: number | null = count(/\/Type\s*\/Page(?![s\w])/g);
  if (!pages) { const c = [...text.matchAll(/\/Type\s*\/Pages[^>]*?\/Count\s+(\d+)/g)].map((m) => +m[1]); pages = c.length ? Math.max(...c) : null; }
  const hasJavaScript = /\/(JavaScript|JS)\b/.test(text);
  const hasOpenAction = /\/OpenAction\b/.test(text);
  const hasLaunch = /\/Launch\b/.test(text);
  const embedded = count(/\/EmbeddedFile\b/g);
  const suspicious: string[] = [];
  if (hasJavaScript) suspicious.push('Embedded JavaScript (/JavaScript or /JS)');
  if (hasLaunch) suspicious.push('Launch action (/Launch)');
  if (hasOpenAction) suspicious.push('Automatic action on open (/OpenAction)');
  if (/\/AA\b/.test(text)) suspicious.push('Additional actions (/AA)');
  if (/\/SubmitForm\b/.test(text)) suspicious.push('Form submission (/SubmitForm)');
  if (/\/URI\b/.test(text) === false && /\/GoToR\b/.test(text)) suspicious.push('Remote go-to action (/GoToR)');
  const urls = new Set<string>();
  for (const m of text.matchAll(/\/URI\s*\(([^)]{1,2048})\)/g)) { for (const u of extractUrls(lit(m[1]))) urls.add(u); if (urls.size >= 200) break; }
  for (const u of extractUrls(text.length < 4_000_000 ? text : text.slice(0, 4_000_000), 200)) urls.add(u);
  const metadata: Record<string, string> = {};
  for (const k of ['Title', 'Author', 'Creator', 'Producer', 'CreationDate']) { const m = new RegExp(`/${k}\\s*\\(([^)]{1,300})\\)`).exec(text); if (m) metadata[k] = lit(m[1]); }
  return {
    version, pageCount: encrypted ? pages : pages, encrypted, hasJavaScript, hasOpenAction, hasLaunchAction: hasLaunch, embeddedFileCount: embedded,
    annotationCount: count(/\/Type\s*\/Annot\b/g), urls: [...urls].slice(0, 200), suspiciousActions: suspicious, metadata, scannedBytes: buf.length, truncated, objectStreamsScanned: objStreams, method: 'raw-token-scan'
  };
}
