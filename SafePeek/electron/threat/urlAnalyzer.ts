import type { UrlIssue, UrlResult } from './types';
import { urlKey } from '../analysis/urls';

/**
 * Local, deterministic URL heuristics. URLs are only ever PARSED as strings: they are never fetched, resolved (no DNS), opened or sent anywhere.
 * A match is an indicator, not proof; a clean URL is not proof of safety (no reputation data is consulted).
 */
const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'nic', 'res', 'or', 'ne']);
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'buff.ly', 'bl.ink', 'v.gd', 't.ly', 'lnkd.in', 'adf.ly', 'shorte.st', 'qr.ae']);
const RISKY_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'tk', 'gq', 'ml', 'cf', 'ga', 'work', 'rest', 'icu', 'buzz', 'cyou', 'monster', 'sbs', 'cfd', 'country', 'kim', 'loan', 'men']);
const HOSTING = ['pastebin.com', 'raw.githubusercontent.com', 'cdn.discordapp.com', 'discordapp.com', 'ngrok.io', 'ngrok-free.app', 'transfer.sh', 'anonfiles.com', 'mega.nz', 'gofile.io', 'file.io', 'temp.sh', 'api.telegram.org', 'paste.ee', 'hastebin.com'];
const KEYWORDS = ['login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'password', 'passwd', 'credential', 'credentials', 'authenticate', 'otp', 'webscr', 'secure', 'account', 'update', 'confirm', 'wallet', 'banking', 'payment', 'unlock', 'suspended', 'recover'];
const CRED_PARAMS = /^(password|passwd|pass|pwd|otp|pin|cvv|cvc|card|cardnumber|ssn)$/i;
const REDIRECT_PARAMS = /^(url|redirect|redirect_uri|redirecturl|next|return|returnurl|goto|dest|destination|continue|target|link)$/i;

/** Well-known brands and the registered domains they really use. Used ONLY to spot look-alike domains; it is not a trust list. */
const BRANDS: Record<string, string[]> = {
  paypal: ['paypal.com', 'paypal.me'], microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com', 'windows.com', 'sharepoint.com', 'office365.com', 'azure.com', 'bing.com'],
  google: ['google.com', 'gmail.com', 'googleapis.com', 'google.co.in', 'gstatic.com', 'youtube.com', 'googleusercontent.com', 'goo.gl'], amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazonaws.com', 'amazon.de'],
  apple: ['apple.com', 'icloud.com'], netflix: ['netflix.com'], facebook: ['facebook.com', 'fb.com', 'meta.com'], instagram: ['instagram.com'], linkedin: ['linkedin.com', 'lnkd.in'],
  whatsapp: ['whatsapp.com', 'whatsapp.net'], dropbox: ['dropbox.com'], docusign: ['docusign.com', 'docusign.net'], dhl: ['dhl.com', 'dhl.de'], fedex: ['fedex.com'], sbi: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
  hdfc: ['hdfcbank.com', 'hdfc.com'], hdfcbank: ['hdfcbank.com'], icici: ['icicibank.com', 'icici.com'], icicibank: ['icicibank.com'], axisbank: ['axisbank.com'], paytm: ['paytm.com'], irctc: ['irctc.co.in'], chase: ['chase.com'], wellsfargo: ['wellsfargo.com'], bankofamerica: ['bankofamerica.com']
};

export const registeredDomain = (host: string): string => {
  const l = host.split('.'); if (l.length <= 2) return host;
  const tld = l[l.length - 1], sld = l[l.length - 2];
  return tld.length === 2 && SECOND_LEVEL.has(sld) ? l.slice(-3).join('.') : l.slice(-2).join('.');
};
const isIPv4 = (h: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
const isPrivateHost = (h: string) => h === 'localhost' || h === '[::1]' || /^(10|127)\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || h.endsWith('.local');
const unleet = (s: string) => s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's');
const clean = (s: string, n = 120) => s.replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '').slice(0, n);

function brandIssue(host: string, path: string): UrlIssue | null {
  const reg = registeredDomain(host);
  const tokens = host.split(/[.\-_]/);
  const unl = unleet(host);
  for (const [brand, official] of Object.entries(BRANDS)) {
    if (official.includes(reg)) continue;
    const inHost = tokens.includes(brand) || (brand.length >= 6 && host.includes(brand));
    if (inHost) return { kind: 'BRAND_LOOKALIKE', weight: 22, detail: `host contains "${brand}" but is not a ${brand} domain` };
    const sq = tokens.some((t) => t !== unleet(t) && unleet(t) === brand) || (brand.length >= 6 && unl.includes(brand) && !host.includes(brand));
    if (sq) return { kind: 'BRAND_TYPOSQUAT', weight: 26, detail: `host imitates "${brand}" using look-alike characters` };
    if (brand.length >= 5 && path.includes(`/${brand}`)) return { kind: 'BRAND_IN_PATH', weight: 8, detail: `path mentions "${brand}" on an unrelated domain` };
  }
  return null;
}

export interface UrlInput { url: string; text?: string; source: string }

export function analyzeUrl(input: UrlInput, opts: { scriptContext?: boolean } = {}): UrlResult {
  const url = input.url.trim();
  const issues: UrlIssue[] = [];
  const add = (kind: string, weight: number, detail: string) => issues.push({ kind, weight, detail });
  const res = (host: string): UrlResult => {
    const w = issues.map((i) => i.weight).sort((a, b) => b - a);
    const score = Math.min(60, Math.round(w.reduce((s, x, i) => s + x * Math.pow(0.8, i), 0)));
    return { url, host, issues, score, suspicious: score >= 10, linkText: input.text, source: input.source };
  };
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(url)?.[1].toLowerCase() ?? '';
  if (['mailto', 'tel', 'sms'].includes(scheme)) return res('');
  if (scheme && !['http', 'https'].includes(scheme)) {
    add('SUSPICIOUS_SCHEME', ['javascript', 'vbscript', 'data', 'file', 'ms-msdt', 'search-ms', 'ms-officecmd'].includes(scheme) ? 35 : 10, `scheme "${scheme}:" can run code or reach local resources`);
    return res('');
  }
  if (/^\\\\/.test(url)) { add('UNC_PATH', 24, 'network share path (can leak Windows credentials)'); return res(''); }
  let u: URL;
  try { u = new URL(url); } catch { add('MALFORMED', 8, 'URL could not be parsed'); return res(''); }
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  const path = decodeSafe(u.pathname).toLowerCase();
  const authority = /^https?:\/\/([^/?#]*)/i.exec(url)?.[1] ?? '';

  if (u.protocol === 'http:') add('HTTP', 5, 'uses unencrypted HTTP');
  if (u.username || u.password || authority.includes('@')) {
    const ui = decodeSafe(u.username);
    add('USERINFO', /\./.test(ui) ? 30 : 15, /\./.test(ui) ? `text before "@" looks like a domain ("${clean(ui, 40)}"), hiding the real destination "${host}"` : 'contains a user name/password before the host name');
  }
  const ip = isIPv4(host) || host.startsWith('[');
  const bare = authority.replace(/^.*@/, '').replace(/:\d*$/, '').toLowerCase();
  const hostObf = /^(0x[0-9a-f]+|\d{8,10})$/.test(bare) || (/^[0-9a-fx.]+$/.test(bare) && bare.split('.').some((p) => /^0x/.test(p) || /^0\d+$/.test(p)));
  if (ip) add('IP_HOST', isPrivateHost(host) ? 6 : 22, isPrivateHost(host) ? `uses a private/local address (${host})` : `uses a raw IP address (${host}) instead of a domain name`);
  if (hostObf) add('OBFUSCATED_HOST', 22, 'host is written as a hexadecimal/decimal/octal number');
  if (host.split('.').some((l) => l.startsWith('xn--')) || /[^\x00-\x7f]/.test(authority)) add('PUNYCODE', 20, 'internationalized (punycode) domain, which can imitate a familiar name');
  if (u.port && !['80', '443'].includes(u.port)) add('PORT', ['8080', '8443', '8000', '8888', '3000'].includes(u.port) ? 5 : 10, `non-standard port ${u.port}`);
  if (!ip) {
    const reg = registeredDomain(host); const subs = host === reg ? 0 : host.slice(0, host.length - reg.length - 1).split('.').length;
    if (subs >= 4) add('EXCESSIVE_SUBDOMAINS', 8, `${subs} subdomain levels`);
    const tld = host.split('.').pop() ?? '';
    if (RISKY_TLDS.has(tld)) add('RISKY_TLD', 5, `top-level domain ".${tld}" is frequently abused`);
    if (SHORTENERS.has(reg) || SHORTENERS.has(host)) add('SHORTENER', 8, 'link shortener hides the real destination');
    { const h = HOSTING.find((x) => host === x || host.endsWith(`.${x}`)); if (h) add('HOSTING_SERVICE', opts.scriptContext ? 15 : 5, `file/text hosting service "${h}" (commonly used to host payloads)`); }
    const official = Object.values(BRANDS).some((d) => d.includes(reg));
    const b = brandIssue(host, path); if (b) add(b.kind, b.weight, b.detail);
    if (!official) {
      const found = KEYWORDS.filter((k) => host.includes(k) || path.includes(k));
      if (found.length) add('SENSITIVE_KEYWORDS', Math.min(16, 8 + 3 * (found.length - 1)), `contains account-related wording: ${found.slice(0, 4).join(', ')}`);
    }
  }
  if (!ip) {
    const reg = registeredDomain(host);
    // Deceptive hostname: a well-known site's own domain written INSIDE someone else's host ("paypal.com.secure-check.example").
    const embedded = Object.values(BRANDS).flat().find((d) => d !== reg && host.includes(`${d}.`) && !host.endsWith(`.${d}`) && host !== d);
    if (embedded) add('DECEPTIVE_HOSTNAME', 30, `host contains "${embedded}" but the real domain is "${reg}"`);
    // Account/login wording stacked in the sub-domain labels ("secure-login.verify-account.example.com").
    const subLabels = host === reg ? '' : host.slice(0, host.length - reg.length - 1);
    const subKw = KEYWORDS.filter((k) => subLabels.includes(k));
    if (subKw.length >= 2 && !Object.values(BRANDS).some((d) => d.includes(reg))) add('SUSPICIOUS_SUBDOMAIN', 12, `sub-domain stacks account wording (${subKw.slice(0, 3).join(', ')})`);
    if ((host.match(/-/g) ?? []).length >= 4) add('MANY_HYPHENS', 6, `${(host.match(/-/g) ?? []).length} hyphens in the host name`);
  }
  const pct = (url.match(/%[0-9a-f]{2}/gi) ?? []).length;
  if (/%[0-9a-f]{2}/i.test(authority) || pct >= 8 || /\/\/[^/]*\/\/|\\/.test(url.replace(/^https?:\/\//i, '')) || /[A-Za-z0-9+/_-]{48,}/.test(u.pathname + u.search)) add('OBFUSCATION', 14, pct >= 8 ? `${pct} percent-encoded characters` : 'encoded or unusually structured URL');
  if (url.length > 500) add('VERY_LONG', 10, `${url.length} characters long`); else if (url.length > 200) add('LONG', 6, `${url.length} characters long`);
  for (const [k, v] of u.searchParams) {
    if (CRED_PARAMS.test(k) && v) add('CREDENTIALS_IN_QUERY', 30, `query parameter "${clean(k, 20)}" carries a secret-like value`);
    else if (REDIRECT_PARAMS.test(k) && /^https?:\/\//i.test(v)) add('REDIRECT_PARAM', 12, `query parameter "${clean(k, 20)}" redirects to another URL`);
  }
  if (input.text) {
    const m = /(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i.exec(input.text.trim());
    if (m && m[0].length >= 4 && !ip && registeredDomain(m[1].toLowerCase()) !== registeredDomain(host)) add('LINK_TEXT_MISMATCH', 30, `link text shows "${clean(m[1], 60)}" but the link goes to "${clean(host, 60)}"`);
  }
  return res(host);
}

function decodeSafe(s: string) { try { return decodeURIComponent(s); } catch { return s; } }

export function analyzeUrls(inputs: UrlInput[], opts: { scriptContext?: boolean } = {}, max = 100): UrlResult[] {
  const seen = new Set<string>(); const out: UrlResult[] = [];
  for (const i of inputs) { const key = urlKey(i.url); if (!i.url.trim() || seen.has(key)) continue; seen.add(key); out.push(analyzeUrl(i, opts)); if (out.length >= max) break; }
  return out;
}
export const sanitizeForDisplay = clean;
