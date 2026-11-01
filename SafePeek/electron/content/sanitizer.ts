import { LIMITS } from './limits';

// Control chars (except \n \t), and bidi/zero-width characters commonly used to spoof file names / text.
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const BIDI = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;

/** Text is only ever shown as TEXT (React escapes it). This removes characters that spoof or confuse, and caps length. */
export function sanitizeText(s: string, max: number = LIMITS.MAX_TEXT_LENGTH): { text: string; truncated: boolean } {
  let t = String(s ?? '').replace(/\r\n?/g, '\n').replace(CONTROL, '').replace(BIDI, '');
  t = t.replace(/[ \t]+\n/g, '\n').replace(/\n{4,}/g, '\n\n\n');
  return t.length > max ? { text: t.slice(0, max), truncated: true } : { text: t, truncated: false };
}
export const cleanInline = (s: string, max = 2000): string => sanitizeText(s, max).text.replace(/\s+/g, ' ').trim();

/** Defensive HTML escaping for any code path that must build markup (the UI itself never uses innerHTML). */
export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** Only http(s)/mailto/ftp are kept as link data. javascript:, data:, file:, vbscript: etc. are dropped. */
export function safeLinkUrl(u: string): string | null {
  const s = cleanInline(u, 2048);
  if (!/^(https?:\/\/[^\s]+|mailto:[^\s]+|ftp:\/\/[^\s]+)$/i.test(s)) return null;
  return s;
}
