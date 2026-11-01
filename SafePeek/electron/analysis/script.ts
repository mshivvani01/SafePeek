import fs from 'node:fs';
import type { ScriptInfo } from './types';
import { SCRIPT_LANGUAGES, extOf } from './extensions';
import { extractUrls } from './urls';

export const TEXT_MAX_READ = 2 * 1024 * 1024;

/** Reads text content (capped) for URL extraction / script identification. The text is data only; it is never evaluated. */
export async function readTextCapped(file: string, size: number): Promise<{ text: string; truncated: boolean }> {
  const n = Math.min(size, TEXT_MAX_READ);
  const fh = await fs.promises.open(file, 'r');
  try {
    const b = Buffer.alloc(n); const r = await fh.read(b, 0, n, 0); const buf = b.subarray(0, r.bytesRead);
    const utf16 = buf[0] === 0xff && buf[1] === 0xfe;
    return { text: buf.toString(utf16 ? 'utf16le' : 'utf8'), truncated: size > n };
  } finally { await fh.close(); }
}

export function scriptInfo(name: string, text: string, truncated: boolean, typeId: string): ScriptInfo {
  const ext = extOf(name);
  let language = SCRIPT_LANGUAGES[ext] ?? (typeId === 'html' ? 'HTML' : 'Script');
  if (!SCRIPT_LANGUAGES[ext]) { const sb = /^#!\s*\S*(?:\/|\s)(\w+)/.exec(text); if (sb) language = `Shell/${sb[1]} script`; }
  return {
    language, lineCount: text.split(/\r\n|\r|\n/).length, bytesRead: Buffer.byteLength(text), truncated,
    hasEmbeddedScriptTags: /<script[\s>]/i.test(text), executionPerformed: false, contentAvailable: true
  };
}
export { extractUrls };
