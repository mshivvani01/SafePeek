const URL_RE = /\bhttps?:\/\/[^\s"'<>()[\]{}\\^`|]{3,2048}/gi;
/** Extracts URLs as text only. Never fetched or opened. */
export function extractUrls(text: string, max = 200): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(URL_RE)) {
    const u = m[0].replace(/[.,;:!?]+$/, '');
    if (/^https?:\/\/[^/\s]+/i.test(u)) out.add(u);
    if (out.size >= max) break;
  }
  return [...out];
}

const BARE_TLDS = 'com|net|org|info|biz|io|co|in|me|xyz|top|click|tk|ml|ga|cf|gq|work|site|online|shop|live|app|dev|link|support|help|ru|cn|uk|de|us|icu|buzz|club|vip|cc|ly|gl|to|zip|mov|test|example|invalid';
const BARE_RE = new RegExp(`(?<![@\\w./:-])((?:www\\.)?(?:[a-z0-9][a-z0-9-]{0,62}\\.)+(?:${BARE_TLDS}))(?![\\w-])(:\\d{1,5})?((?:/[^\\s"'<>()[\\]{}\\\\^\`|]*)?)`, 'gi');
/**
 * URLs as they appear in OCR text / QR payloads, where the scheme is often missing ("www.bank-login.example/verify").
 * Complete http(s) URLs come back as written; scheme-less ones are returned as https://… with assumed = true.
 * A bare domain is accepted only when it looks like a link (www. prefix, a path, or a port), to avoid treating every "company.com" mention as a link.
 * Text only: nothing is resolved, fetched or opened.
 */
export function extractVisualUrls(text: string, max = 100): { url: string; assumed: boolean }[] {
  const out = new Map<string, boolean>();
  const full = extractUrls(text, max);
  for (const u of full) out.set(u, false);
  const stripped = text.replace(/\bhttps?:\/\/[^\s"'<>()[\]{}\\^`|]+/gi, ' ');
  for (const m of stripped.matchAll(BARE_RE)) {
    const host = m[1]; const port = m[2] ?? ''; const rest = (m[3] ?? '').replace(/[.,;:!?]+$/, '');
    if (!(/^www\./i.test(host) || rest.length > 1 || port)) continue;
    const u = `https://${host}${port}${rest}`;
    if (![...out.keys()].some((k) => k.toLowerCase().replace(/^https?:\/\//, '') === u.toLowerCase().replace(/^https?:\/\//, ''))) out.set(u, true);
    if (out.size >= max) break;
  }
  return [...out].map(([url, assumed]) => ({ url, assumed }));
}
/** Canonical key for de-duplicating the same address seen through different extraction paths (case, trailing slash, default ports, fragments). */
export function urlKey(u: string): string {
  const s = u.trim();
  try { const x = new URL(s); x.hash = ''; let p = x.pathname.replace(/\/+$/, ''); if (!p) p = ''; return `${x.protocol}//${x.hostname.toLowerCase()}${x.port && !['80', '443'].includes(x.port) ? `:${x.port}` : ''}${p}${x.search}`; }
  catch { return s.toLowerCase(); }
}
