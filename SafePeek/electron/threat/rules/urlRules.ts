import type { Rule, RuleFinding, UrlResult } from '../types';
import { F, clip, list, sevOf } from './util';

const TITLES: Record<string, { t: string; d: string; cat: RuleFinding['category'] }> = {
  SUSPICIOUS_SCHEME: { t: 'Link uses a risky URL scheme', d: 'Schemes such as javascript:, data: or file: run code or reach local resources instead of opening a web page.', cat: 'MALICIOUS_URL' },
  UNC_PATH: { t: 'Link points to a network share', d: 'Opening a network-share path can make Windows send authentication data to another computer.', cat: 'CREDENTIAL_THEFT' },
  MALFORMED: { t: 'Malformed URL', d: 'The URL could not be parsed.', cat: 'MALICIOUS_URL' },
  HTTP: { t: 'Link uses unencrypted HTTP', d: 'Traffic to this address is not encrypted. Many older sites still do this; it matters more for login or payment pages.', cat: 'MALICIOUS_URL' },
  USERINFO: { t: 'URL contains credentials or a deceptive "user@host" part', d: 'Text before "@" is ignored by the browser, so a familiar-looking name can be placed in front of the real destination.', cat: 'PHISHING' },
  IP_HOST: { t: 'Link uses an IP address instead of a domain', d: 'Legitimate services almost always use domain names. Raw IP addresses are common for temporary attacker infrastructure (private/local addresses are rated lower).', cat: 'MALICIOUS_URL' },
  OBFUSCATED_HOST: { t: 'Link hides its IP address in an unusual number format', d: 'Hexadecimal, decimal or octal host notation is used to disguise the destination.', cat: 'OBFUSCATION' },
  PUNYCODE: { t: 'Link uses an internationalized (punycode) domain', d: 'Look-alike characters from other alphabets can make a domain resemble a familiar one.', cat: 'PHISHING' },
  PORT: { t: 'Link uses a non-standard port', d: 'Ordinary websites use ports 80/443. Other ports are used by test servers and by attacker infrastructure.', cat: 'MALICIOUS_URL' },
  EXCESSIVE_SUBDOMAINS: { t: 'Link has many subdomain levels', d: 'Long chains of subdomains can bury the real domain name.', cat: 'MALICIOUS_URL' },
  RISKY_TLD: { t: 'Link uses a frequently abused top-level domain', d: 'Some TLDs are cheap or free and are over-represented in phishing. Many are used legitimately.', cat: 'MALICIOUS_URL' },
  SHORTENER: { t: 'Link uses a URL shortener', d: 'The real destination is hidden. SafePeek does not resolve links.', cat: 'MALICIOUS_URL' },
  HOSTING_SERVICE: { t: 'Link points to a file/text hosting service', d: 'Paste and file-sharing sites are used both legitimately and to host payloads.', cat: 'MALICIOUS_URL' },
  BRAND_LOOKALIKE: { t: 'Domain contains a well-known brand name but is not that brand', d: 'Attackers include a brand name inside their own domain to look official.', cat: 'PHISHING' },
  BRAND_TYPOSQUAT: { t: 'Domain imitates a well-known brand with look-alike characters', d: 'Characters such as 0/o, 1/l or rn/m are swapped to resemble a brand name.', cat: 'PHISHING' },
  DECEPTIVE_HOSTNAME: { t: 'Host name embeds another site\'s real domain', d: 'A well-known domain is written inside the address of an unrelated site so the start of the host name looks trustworthy.', cat: 'PHISHING' },
  SUSPICIOUS_SUBDOMAIN: { t: 'Sub-domain stacks account / login wording', d: 'Words such as secure, login or verify are chained in the sub-domain to look official.', cat: 'PHISHING' },
  MANY_HYPHENS: { t: 'Host name contains many hyphens', d: 'Long hyphenated names are a common look-alike pattern.', cat: 'MALICIOUS_URL' },
  BRAND_IN_PATH: { t: 'Path mentions a well-known brand on an unrelated domain', d: 'A brand name in the path of an unrelated site is a weak impersonation signal.', cat: 'PHISHING' },
  SENSITIVE_KEYWORDS: { t: 'Link contains account / login wording', d: 'Words such as login, verify, password, secure or update appear in the address of a non-well-known site. Combined with other evidence this indicates phishing; alone it is common on real sites.', cat: 'PHISHING' },
  OBFUSCATION: { t: 'URL looks obfuscated', d: 'Heavy percent-encoding, doubled slashes or very long encoded tokens make the real target hard to read.', cat: 'OBFUSCATION' },
  VERY_LONG: { t: 'Very long URL', d: 'Extremely long URLs can hide the real destination.', cat: 'MALICIOUS_URL' }, LONG: { t: 'Long URL', d: 'Long URLs can hide the real destination; tracking links are often long too.', cat: 'MALICIOUS_URL' },
  CREDENTIALS_IN_QUERY: { t: 'URL carries password-like data', d: 'Secrets in a query string are logged and shared; pre-filled credentials in links are a phishing pattern.', cat: 'CREDENTIAL_THEFT' },
  REDIRECT_PARAM: { t: 'URL redirects to another address', d: 'A redirect parameter can bounce a trusted-looking link to an attacker site (open redirect).', cat: 'MALICIOUS_URL' },
  LINK_TEXT_MISMATCH: { t: 'Link text shows a different address than the real target', d: 'The visible text looks like one web address but the link goes elsewhere, a classic phishing trick.', cat: 'PHISHING' }
};

/** URL rules: one indicator per kind of issue across all URLs (so 20 similar links do not count 20 times). URLs are never visited. */
export const urlRules: Rule = (c) => {
  if (!c.urls.length) return [];
  const out: RuleFinding[] = [];
  const by = new Map<string, { w: number; urls: UrlResult[]; details: string[] }>();
  for (const u of c.urls) for (const i of u.issues) {
    const e = by.get(i.kind) ?? { w: 0, urls: [], details: [] };
    e.w = Math.max(e.w, i.weight); if (!e.urls.includes(u)) { e.urls.push(u); e.details.push(i.detail); } by.set(i.kind, e);
  }
  for (const [kind, e] of by) {
    const meta = TITLES[kind] ?? { t: kind, d: '', cat: 'MALICIOUS_URL' as const };
    const weight = e.w + Math.min(4, e.urls.length - 1);
    const shown = e.urls.slice(0, 3).map((u) => `${clip(u.url, 90)} — ${e.details[e.urls.indexOf(u)]}`);
    out.push(F({ ruleId: `URL_${kind}`, category: meta.cat, weight, severity: sevOf(weight), source: 'URL_ANALYSIS', title: e.urls.length > 1 ? `${meta.t} (${e.urls.length} links)` : meta.t, description: meta.d + ' The URL was not visited.',
      reason: `${meta.t}${e.urls.length === 1 ? ` (${clip(e.urls[0].host || e.urls[0].url, 50)})` : ` (${e.urls.length} links)`}.`, evidence: shown.join(' | '), capGroup: 'url', origins: [...new Set(e.urls.map((u) => u.origin ?? 'TEXT'))],
      dedupeKey: kind === 'SENSITIVE_KEYWORDS' ? 'credential-lure' : undefined, evidenceItems: e.urls.slice(0, 5).map((u) => ({ type: 'url', description: meta.t, value: clip(u.url, 120), origin: u.origin })) }));
  }
  out.push(F({ ruleId: 'URL_PRESENT', category: 'MALICIOUS_URL', weight: 0, severity: 'INFO', source: 'URL_ANALYSIS', title: `${c.urls.length} URL${c.urls.length === 1 ? '' : 's'} found`, description: 'URLs were extracted as text and checked locally for suspicious patterns. SafePeek did not visit them and has no reputation data, so a URL without findings is not proven safe.', evidence: list(c.urls.map((u) => u.url)) }));
  return out;
};
