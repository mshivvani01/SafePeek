import { describe, expect, it } from 'vitest';
import type { ContentResult, QrCodeInfo, VisualAnalysis } from '../electron/content/types';
import { assessThreat } from '../electron/threat';
import { analyzeUrl } from '../electron/threat/urlAnalyzer';
import { extractVisualUrls, urlKey } from '../electron/analysis/urls';
import { beforeAll } from 'vitest';
import path from 'node:path';
import { analyzeFile } from '../electron/analysis/analyzer';
import type { AnalysisResult } from '../electron/analysis/types';
import { contentStub } from './helpers/threat';
let IMG: AnalysisResult, PDF: AnalysisResult;
beforeAll(async () => { IMG = await analyzeFile(path.join(__dirname, 'fixtures', 'test-normal-image.png')); PDF = await analyzeFile(path.join(__dirname, 'fixtures', 'test-text-only.pdf')); });

const vis = (o: Partial<VisualAnalysis> = {}): VisualAnalysis => ({ version: 1, ocrStatus: 'COMPLETED', ocrLanguage: 'eng', ocrDurationMs: 1, ocrConfidence: 90, ocrWarnings: [], imagesAnalyzed: 1, ocrImageCount: 1, ocrPages: [], qrCodes: [], urlsDetected: 0, downscaled: false, limitsHit: [], cacheHit: false, sources: { directText: false, ocrText: true, qr: false }, ...o });
const qr = (payload: string, kind: QrCodeInfo['kind'] = 'url', extra: Partial<QrCodeInfo> = {}): QrCodeInfo => ({ index: 1, payload, kind, location: 'image', truncated: false, ...(kind === 'url' ? { url: payload, scheme: 'https' } : {}), ...extra });
/** Real static analysis of a harmless fixture of the matching type + a synthetic content result: isolates the threat rules from OCR. */
const png = (name: string, c: ContentResult) => assessThreat({ fileName: name, analysis: c.extractorType === 'pdf' ? PDF : IMG, content: c });
const imageContent = (ocr: string, v: Partial<VisualAnalysis> = {}, links: ContentResult['links'] = []): ContentResult => ({ ...contentStub(ocr, { extractorType: 'image', ocrText: ocr, links, visual: vis(v) }) });
const ids = (t: ReturnType<typeof assessThreat>) => t.indicators.filter((i) => i.severity !== 'INFO').map((i) => i.ruleId);
const PHISH = 'URGENT - your account will be suspended. Verify your account immediately. Enter your password and OTP.';

describe('OCR text goes through the existing deterministic rules', () => {
  it('credential, phishing and financial indicators from OCR text', () => {
    const t = png('x.png', imageContent(PHISH)); expect(ids(t)).toContain('CONTENT_URGENT_CREDENTIALS'); expect(t.indicators.find((i) => i.ruleId === 'CONTENT_URGENT_CREDENTIALS')!.origins).toEqual(['OCR']);
    const f = png('x.png', imageContent('Congratulations! You have won the lottery. Pay the processing fee of $50 to claim your prize.')); expect(ids(f)).toContain('CONTENT_PRIZE_FEE');
    expect(png('x.png', imageContent('Please verify now to keep access. Click here to confirm your account. Urgent.')).categories).toEqual(expect.arrayContaining(['PHISHING']));
  });
  it('a plain mention of "password" in OCR text is not flagged (existing negation/combination logic applies)', () => { expect(png('x.png', imageContent('Remember to change the password policy document.')).status).toBe('SAFE'); });
  it('OCR text with a URL: the URL is analyzed by the existing analyzer', () => {
    const t = png('x.png', imageContent(`${PHISH} http://203.0.113.9:8080/login`)); expect(ids(t)).toEqual(expect.arrayContaining(['URL_IP_HOST', 'URL_PORT'])); expect(t.indicators.find((i) => i.ruleId === 'URL_IP_HOST')!.origins).toEqual(['OCR']);
  });
});

describe('URL intelligence', () => {
  const kinds = (u: string) => analyzeUrl({ url: u, source: 't' }).issues.map((i) => i.kind);
  it('raw IP, suspicious port, login path, shortener, punycode, brand impersonation, deceptive hostname, stacked sub-domain', () => {
    expect(kinds('http://203.0.113.9/x')).toContain('IP_HOST'); expect(kinds('https://example.org:4444/a')).toContain('PORT'); expect(kinds('https://example.org/login/verify')).toContain('SENSITIVE_KEYWORDS');
    expect(kinds('https://bit.ly/abc')).toContain('SHORTENER'); expect(kinds('https://xn--pypal-4ve.example.com/')).toContain('PUNYCODE'); expect(kinds('https://paypal-help.example.net/')).toContain('BRAND_LOOKALIKE');
    expect(kinds('https://paypal.com.secure-check.example.net/')).toContain('DECEPTIVE_HOSTNAME'); expect(kinds('https://secure-login.verify-account.example.net/')).toContain('SUSPICIOUS_SUBDOMAIN');
  });
  it('official domains and ordinary URLs are not flagged by the new checks', () => { expect(kinds('https://www.paypal.com/signin')).not.toContain('DECEPTIVE_HOSTNAME'); expect(kinds('https://example.org/menu')).toEqual([]); });
  it('never makes network requests: analysis is a pure function of the string', () => { expect(analyzeUrl({ url: 'https://paypal.com.evil.example/', source: 't' }).host).toBe('paypal.com.evil.example'); });
  it('scheme-less URLs from OCR are found only when they look like links', () => {
    const r = extractVisualUrls('Visit www.bank-login.example.net/verify or company.com for info. Mail hr@company.com. Docs at http://x.example.org/a.');
    expect(r.map((x) => x.url)).toEqual(['http://x.example.org/a', 'https://www.bank-login.example.net/verify']); expect(r.find((x) => x.url.includes('bank-login'))!.assumed).toBe(true);
  });
  it('the same address through different paths is one URL', () => { expect(urlKey('https://Example.com/a/')).toBe(urlKey('https://example.com/a')); });
});

describe('QR evidence in the existing engine', () => {
  const links = (u: string) => [{ url: u, source: 'QR code' }];
  it('suspicious QR URL + OCR credential wording: strong, sourced, correlated', () => {
    const u = 'https://paypal-secure-login.example.test/verify/account';
    const t = png('invoice.pdf', imageContent(PHISH, { qrCodes: [qr(u)], sources: { directText: false, ocrText: true, qr: true } }, links(u)));
    expect(['HIGH_RISK', 'CRITICAL']).toContain(t.status); expect(ids(t)).toEqual(expect.arrayContaining(['URL_BRAND_LOOKALIKE', 'CONTENT_URGENT_CREDENTIALS', 'CORR_CROSS_MODAL_LURE_URL']));
    expect(t.indicators.find((i) => i.ruleId === 'URL_BRAND_LOOKALIKE')!.origins).toEqual(['QR']); expect(t.evidence.find((e) => e.indicatorId === 'URL_BRAND_LOOKALIKE')!.origin).toBe('QR');
  });
  it('benign QR URL alone adds nothing; with lure wording and a plain URL it adds only a modest correlation', () => {
    const u = 'https://menu.example.org/lunch';
    expect(png('menu.png', imageContent('Scan for the menu', { qrCodes: [qr(u)] }, links(u))).status).toBe('SAFE');
    const t = png('x.png', imageContent(PHISH, { qrCodes: [qr(u)] }, links(u))); expect(ids(t)).toContain('CORR_QR_LURE'); expect(ids(t)).not.toContain('CORR_CROSS_MODAL_LURE_URL');
  });
  it('non-HTTP payloads are informational only; dangerous schemes are analyzed as risky URIs', () => {
    expect(png('w.png', imageContent('Guest wifi', { qrCodes: [qr('WIFI:T:WPA;S:G;P:x;;', 'wifi', { scheme: 'wifi' })] })).status).toBe('SAFE');
    const t = png('j.png', imageContent('hello', { qrCodes: [qr('javascript:alert(1)', 'other-scheme', { scheme: 'javascript' })] })); expect(ids(t)).toContain('URL_SUSPICIOUS_SCHEME');
  });
  it('QR text payload with lure wording is analyzed as QR-origin text', () => {
    const t = png('q.png', imageContent('Scan me', { qrCodes: [qr(PHISH, 'text')] })); expect(ids(t)).toContain('CONTENT_URGENT_CREDENTIALS'); expect(t.indicators.find((i) => i.ruleId === 'CONTENT_URGENT_CREDENTIALS')!.origins).toEqual(['QR']);
  });
});

describe('Cross-modal correlation without double counting', () => {
  const pdf = (direct: string, ocr: string | undefined, link?: string): ContentResult => contentStub(direct, { extractorType: 'pdf', ocrText: ocr, links: link ? [{ url: link, source: 'text' }] : [], visual: vis({ pdfKind: ocr ? 'MIXED' : 'TEXT', ocrPages: ocr ? [2] : [], sources: { directText: true, ocrText: !!ocr, qr: false } }) });
  const URL = 'https://secure-login.account-verify.example.test/verify';
  it('PDF text phishing + the SAME phishing in an image + URL: same score as text alone, origins merged', () => {
    const textOnly = png('n.pdf', pdf(`${PHISH} ${URL}`, undefined)); const both = png('n.pdf', pdf(`${PHISH} ${URL}`, `${PHISH} ${URL}`));
    expect(both.score).toBe(textOnly.score); expect(both.indicators.find((i) => i.ruleId === 'CONTENT_URGENT_CREDENTIALS')!.origins!.sort()).toEqual(['OCR', 'TEXT']);
    expect(ids(both)).not.toContain('CORR_CROSS_MODAL_LURE_URL'); expect(both.indicators.filter((i) => i.ruleId === 'URL_SENSITIVE_KEYWORDS')).toHaveLength(1);
  });
  it('complementary evidence in different channels reinforces (urgency in text, OTP request in OCR, URL in QR)', () => {
    const c = contentStub('URGENT: payment required today.', { extractorType: 'pdf', ocrText: 'Enter your OTP to verify your account.', links: [{ url: 'https://paypal-secure-login.example.test/verify', source: 'QR code' }], visual: vis({ pdfKind: 'MIXED', ocrPages: [2], qrCodes: [qr('https://paypal-secure-login.example.test/verify')], sources: { directText: true, ocrText: true, qr: true } }) });
    const t = png('invoice.pdf', c); expect(['HIGH_RISK', 'CRITICAL']).toContain(t.status); expect(ids(t)).toEqual(expect.arrayContaining(['CORR_CROSS_MODAL_LURE_URL', 'CORR_CREDENTIAL_LURE_URL']));
    expect(t.breakdown.correlationBonus).toBeLessThanOrEqual(35); // the existing correlation cap still governs
  });
  it('text only in an image of a PDF is a weak, explained signal; ordinary image files do not get it', () => {
    expect(ids(png('s.pdf', contentStub('', { extractorType: 'pdf', extractedText: '', ocrText: PHISH, visual: vis({ pdfKind: 'IMAGE_ONLY', ocrPages: [1] }) })))).toContain('CORR_TEXT_IN_IMAGE');
    expect(ids(png('s.png', imageContent(PHISH)))).not.toContain('CORR_TEXT_IN_IMAGE');
  });
  it('visual coverage gaps are never reassuring', () => {
    const t = png('p.png', imageContent('Team lunch on Friday', { ocrStatus: 'PARTIAL', limitsHit: ['OCR time limit reached'] })); expect(t.coverage.notes.join(' ')).toMatch(/visual content could not be fully analyzed/); expect(t.limitations.join(' ')).toMatch(/OCR is not guaranteed/);
  });
});
