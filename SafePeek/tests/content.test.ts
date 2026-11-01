import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeFile } from '../electron/analysis/analyzer';
import { contextFor, extractContent } from '../electron/content/extractor';
import { shutdownOcr } from '../electron/content/ocr';
import { escapeHtml, safeLinkUrl, sanitizeText } from '../electron/content/sanitizer';
import { decodeText, parseCsv } from '../electron/content/textExtractor';
import { imageDimensions } from '../electron/content/imageExtractor';
import { LIMITS } from '../electron/content/limits';
import { MonitoringAgent } from '../electron/agent/agent';
import { StateStore } from '../electron/agent/store';
import { AnalysisService } from '../electron/analysis/service';
import { ContentService } from '../electron/content/contentService';
import { OFFER_DOCX, makeDocx, makeTextPdf, makeXlsx } from './helpers/builders';
import { makePE, makeZip } from './helpers/fixtures';

const FIX = path.join(__dirname, 'fixtures');
let dir: string;
const w = (n: string, d: string | Buffer) => { const p = path.join(dir, n); fs.writeFileSync(p, d); return p; };
async function run(p: string) { const a = await analyzeFile(p); return extractContent(contextFor(p, path.basename(p), fs.statSync(p).size, a)); }
beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sp4-')); });
afterAll(async () => { await shutdownOcr(); fs.rmSync(dir, { recursive: true, force: true }); });

describe('PDF', () => {
  it('extracts pages, text, links, metadata and a summary', async () => {
    const r = await run(path.join(FIX, 'salary-increment.pdf'));
    expect(r.status).toBe('COMPLETED'); expect(r.extractorType).toBe('pdf'); expect(r.pageCount).toBe(2); expect(r.pages).toHaveLength(2);
    expect(r.extractedText).toContain('Salary Increment Notification'); expect(r.extractedText).toContain('Priya Sharma');
    expect(r.links.map((l) => l.url)).toEqual(expect.arrayContaining(['https://hr.orbit-example.test/increment']));
    expect(r.properties?.Title).toBe('Salary Increment Notification');
    expect(r.summary.documentType).toBe('Salary increment letter'); expect(r.summary.description).toMatch(/appears to contain a salary increment/);
    expect(r.summary.entities.amounts[0]).toContain('85,000'); expect(r.summary.entities.emails).toContain('hr@orbit-example.test');
    expect(r.previewType).toBe('pdf'); expect(r.previewAvailable).toBe(true); expect(r.executionPerformed).toBe(false); expect(r.uploaded).toBe(false);
  });
  it('handles a malformed PDF without throwing', async () => {
    const r = await run(w('broken.pdf', Buffer.concat([Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog'), Buffer.alloc(200, 0x41)])));
    expect(['FAILED', 'PARTIAL']).toContain(r.status); expect(r.extractionWarnings.length).toBeGreaterThan(0); expect(r.previewAvailable).toBe(false);
  });
  it('caps the number of pages', async () => {
    const many = Array.from({ length: LIMITS.MAX_PDF_PAGES + 5 }, (_, i) => [`Page number ${i + 1}`]);
    const r = await run(w('many.pdf', makeTextPdf(many)));
    expect(r.pages).toHaveLength(LIMITS.MAX_PDF_PAGES); expect(r.truncated).toBe(true); expect(r.status).toBe('PARTIAL'); expect(r.pageCount).toBe(LIMITS.MAX_PDF_PAGES + 5);
  });
  it('does not execute or follow PDF actions (JavaScript / URI are only data)', async () => {
    const js = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n');
    const r = await run(w('active.pdf', js));
    expect(r.executionPerformed).toBe(false); expect(r.embeddedContentWarning).toBe(true);
    expect(r.extractionWarnings.join(' ')).toMatch(/Embedded content detected/);
  });
});

describe('DOCX', () => {
  it('extracts headings, paragraphs, table and hyperlinks', async () => {
    const r = await run(path.join(FIX, 'internship-offer.docx'));
    expect(r.status).toBe('COMPLETED'); expect(r.extractorType).toBe('docx');
    expect(r.sections!.filter((s) => s.kind === 'heading').map((s) => s.text)).toEqual(['ABC Technologies', 'Internship Offer', 'Position']);
    expect(r.sections!.some((s) => s.kind === 'paragraph' && s.text.includes('Stipend'))).toBe(true);
    expect(r.tables![0].rows).toEqual([['Item', 'Detail'], ['Position', 'Software Intern'], ['Duration', '6 months']]);
    expect(r.links.map((l) => l.url)).toContain('https://abc-technologies.example.test/policy'); expect(r.properties?.Author).toBe('SafePeek Fixtures');
    expect(r.summary.documentType).toBe('Internship offer letter'); expect(r.previewType).toBe('document');
  });
  it('flags macros / embedded objects but never executes them', async () => {
    const r = await run(w('macro.docx', OFFER_DOCX(true)));
    expect(r.embeddedContentWarning).toBe(true); expect(r.extractionWarnings.join(' ')).toContain('SafePeek has not executed this content');
    const r2 = await run(w('emb.docx', makeDocx({ paragraphs: [{ text: 'x y z' }], withEmbedded: true })));
    expect(r2.embeddedContentWarning).toBe(true);
  });
  it('handles a truncated/corrupt docx', async () => {
    const r = await run(w('bad.docx', Buffer.from(fs.readFileSync(path.join(FIX, 'internship-offer.docx')).subarray(0, 200))));
    expect(['FAILED', 'UNSUPPORTED', 'PARTIAL']).toContain(r.status);
  });
  it('rejects XML with a DOCTYPE entity bomb without expanding it', async () => {
    const evil = makeZip({ '[Content_Types].xml': '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>', 'word/document.xml': '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><w:document xmlns:w="x"><w:body><w:p><w:r><w:t>&b;ok</w:t></w:r></w:p></w:body></w:document>' });
    const r = await run(w('evil.docx', evil));
    expect(r.extractedText ?? '').not.toContain('AAAAAAAAAA');
  });
});

describe('XLSX / PPTX', () => {
  it('extracts sheets, cells and hyperlinks (formulas are never evaluated)', async () => {
    const r = await run(path.join(FIX, 'project-data.xlsx'));
    expect(r.extractorType).toBe('xlsx'); expect(r.sheets!.map((s) => s.name)).toEqual(['October', 'Employees']);
    expect(r.sheets![0].rows[0]).toEqual(['Employee', 'Salary']); expect(r.sheets![0].rows[1]).toEqual(['Asha', '52000']); expect(r.sheets![0].range).toBe('A1:B3');
    expect(r.links.map((l) => l.url)).toContain('https://payroll.example.test/oct'); expect(r.previewType).toBe('spreadsheet');
  });
  it('caps rows per sheet', async () => {
    const rows = Array.from({ length: 300 }, (_, i) => ['row', i]);
    const r = await run(w('big.xlsx', makeXlsx([{ name: 'S', rows }])));
    expect(r.sheets![0].rows).toHaveLength(LIMITS.MAX_SHEET_ROWS); expect(r.sheets![0].truncated).toBe(true); expect(r.truncated).toBe(true);
  });
  it('extracts slides, titles, notes and links', async () => {
    const r = await run(path.join(FIX, 'project-presentation.pptx'));
    expect(r.extractorType).toBe('pptx'); expect(r.slides).toHaveLength(2); expect(r.pageCount).toBe(2);
    expect(r.slides![0].title).toBe('Project Overview'); expect(r.slides![0].notes).toContain('Speaker note'); expect(r.slides![1].text).toContain('Static analysis');
    expect(r.links.map((l) => l.url)).toContain('https://project.example.test/'); expect(r.previewType).toBe('presentation');
  });
});

describe('Image OCR', () => {
  it('runs local OCR on a PNG and reports dimensions', async () => {
    const r = await run(path.join(FIX, 'job-offer.png'));
    expect(r.status).toBe('COMPLETED'); expect(r.extractorType).toBe('image'); expect(r.image).toMatchObject({ width: 900, height: 420, format: 'PNG' });
    expect(r.ocrText).toMatch(/ABC Technologies/); expect(r.ocrText).toMatch(/Software Intern/); expect(r.summary.entities.amounts.join(' ')).toContain('2,000');
    expect(r.links.map((l) => l.url)).toContain('https://example.com/offer'); expect(r.image!.dataUrl).toMatch(/^data:image\/png;base64,/); expect(r.previewType).toBe('image');
  }, 60_000);
  it('survives an undecodable image (OCR failure -> PARTIAL, no throw)', async () => {
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40)]);
    const r = await run(w('bad.png', png));
    expect(['PARTIAL', 'COMPLETED']).toContain(r.status); expect(r.image).toBeTruthy();
  }, 60_000);
  it('skips OCR for huge pixel counts', async () => {
    const hdr = Buffer.alloc(40); Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(hdr); hdr.writeUInt32BE(10000, 16); hdr.writeUInt32BE(10000, 20);
    const r = await run(w('huge.png', hdr));
    expect(r.status).toBe('PARTIAL'); expect(r.extractionWarnings.join(' ')).toMatch(/OCR skipped/); expect(r.ocrText).toBeUndefined();
  });
  it('reads dimensions from headers', () => {
    expect(imageDimensions(fs.readFileSync(path.join(FIX, 'job-offer.png')), 'png')).toEqual({ width: 900, height: 420 });
  });
});

describe('Text files', () => {
  it('extracts text and urls', async () => {
    const r = await run(path.join(FIX, 'college-notice.txt'));
    expect(r.status).toBe('COMPLETED'); expect(r.extractedText).toContain('hall tickets'); expect(r.links[0].url).toBe('https://greenfield.example.test/exams'); expect(r.summary.documentType).toBe('Academic / college notice'); expect(r.previewType).toBe('text');
  });
  it('reads only a bounded preview of huge files and says so', async () => {
    const p = w('huge.log', 'line of log text\n'.repeat(80_000)); // ~1.3 MB
    const r = await run(p);
    expect(r.truncated).toBe(true); expect(r.truncationNote).toMatch(/Showing first 100 KB of/); expect(r.extractedText!.length).toBeLessThanOrEqual(LIMITS.TEXT_PREVIEW_BYTES);
  });
  it('parses CSV into a table; JSON as text', async () => {
    const r = await run(w('d.csv', 'name,amt\n"Smith, J",5\nLee,7\n'));
    expect(r.tables![0].rows).toEqual([['name', 'amt'], ['Smith, J', '5'], ['Lee', '7']]); expect(parseCsv('a,b\n1,2')).toEqual([['a', 'b'], ['1', '2']]);
    expect((await run(w('d.json', '{"a":1}'))).extractedText).toContain('"a"');
  });
  it('detects UTF-16, falls back for invalid UTF-8, refuses binary', () => {
    expect(decodeText(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('hi', 'utf16le')]))!.text).toBe('hi');
    expect(decodeText(Buffer.from([0x48, 0xe9, 0x6c]))!.warn).toMatch(/Latin-1/);
    expect(decodeText(Buffer.from([0, 1, 2, 3, 0, 0, 5]))).toBeNull();
  });
  it('shows HTML and scripts as inert text with a notice', async () => {
    const r = await run(w('page.html', '<html><script>alert(1)</script><a href="javascript:alert(2)">x</a> https://evil.example.test/a</html>'));
    expect(r.extractedText).toContain('<script>'); expect(r.extractionWarnings.join(' ')).toMatch(/never rendered/); expect(r.links.every((l) => /^https?:/.test(l.url))).toBe(true);
  });
});

describe('Archives', () => {
  it('lists entries as a tree without extracting', async () => {
    const r = await run(path.join(FIX, 'scholarship.zip'));
    expect(r.extractorType).toBe('archive'); expect(r.previewType).toBe('archive');
    expect(r.archiveEntries!.map((e) => e.path)).toEqual(['documents/', 'documents/identity.pdf', 'instructions.txt', 'scholarship_form.pdf', 'verification.exe']);
    expect(r.archiveEntries!.find((e) => e.name === 'verification.exe')).toMatchObject({ dangerous: true, inspectable: false });
    expect(r.archiveEntries!.find((e) => e.name === 'identity.pdf')).toMatchObject({ depth: 1, inspectable: true });
    expect(r.summary.description).toMatch(/Nothing was extracted or run/);
  });
  it('flags path traversal names and never resolves them', async () => {
    const r = await run(w('slip.zip', makeZip({ '../../evil.txt': 'x', 'ok.txt': 'y' })));
    const bad = r.archiveEntries!.find((e) => e.path.includes('evil'))!; expect(bad.unsafePath).toBe(true); expect(bad.inspectable).toBe(false);
    expect(fs.existsSync(path.join(dir, '..', 'evil.txt'))).toBe(false);
  });
  it('caps archive entries', async () => {
    const files: Record<string, string> = {}; for (let i = 0; i < LIMITS.MAX_ARCHIVE_ENTRIES + 50; i++) files[`f${i}.txt`] = 'x';
    const r = await run(w('many.zip', makeZip(files)));
    expect(r.archiveEntries).toHaveLength(LIMITS.MAX_ARCHIVE_ENTRIES); expect(r.truncated).toBe(true); expect(r.status).toBe('PARTIAL');
  });
  it('says content preview is unavailable for unsupported archive types', async () => {
    const r = await run(w('x.gz', Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0]), Buffer.alloc(40)])));
    expect(r.previewAvailable).toBe(false); expect(r.unsupportedReason).toMatch(/Archive type detected.*Content preview unavailable/);
  });
  it('handles a malformed zip', async () => {
    const r = await run(w('trunc.zip', fs.readFileSync(path.join(FIX, 'scholarship.zip')).subarray(0, 60)));
    expect(['PARTIAL', 'FAILED', 'UNSUPPORTED']).toContain(r.status);
  });
});

describe('Unsupported / executables', () => {
  it('does not render an executable as a document', async () => {
    const r = await run(w('setup.exe', makePE()));
    expect(r.status).toBe('UNSUPPORTED'); expect(r.previewAvailable).toBe(false); expect(r.previewType).toBe('unsupported'); expect(r.extractedText).toBeUndefined();
    expect(r.unsupportedReason).toMatch(/will not execute this file/);
  });
  it('treats unknown binary as unsupported', async () => {
    const r = await run(w('blob.dat', Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 7) % 256))));
    expect(r.previewAvailable).toBe(false);
  });
  it('fails gracefully when static analysis failed or the file vanished', async () => {
    const p = w('gone.txt', 'x'); const a = await analyzeFile(p); fs.rmSync(p);
    const r = await extractContent(contextFor(p, 'gone.txt', 1, a));
    expect(['FAILED', 'PARTIAL']).toContain(r.status);
    const r2 = await extractContent(contextFor(p, 'gone.txt', 1, undefined)); expect(r2.status).toBe('FAILED');
  });
});

describe('Preview + sanitization + security', () => {
  it('selects the right preview type per format', async () => {
    const t: Record<string, string> = { 'salary-increment.pdf': 'pdf', 'internship-offer.docx': 'document', 'project-data.xlsx': 'spreadsheet', 'project-presentation.pptx': 'presentation', 'college-notice.txt': 'text', 'scholarship.zip': 'archive' };
    for (const [f, type] of Object.entries(t)) expect((await run(path.join(FIX, f))).previewType, f).toBe(type);
  });
  it('sanitizes control and bidi characters; escapes HTML; restricts link schemes', () => {
    expect(sanitizeText('a\u0000b\u202Ec\u200Bd').text).toBe('abcd');
    expect(sanitizeText('x'.repeat(50), 10)).toEqual({ text: 'x'.repeat(10), truncated: true });
    expect(escapeHtml('<img src=x onerror="a()">')).toBe('&lt;img src=x onerror=&quot;a()&quot;&gt;');
    expect(safeLinkUrl('javascript:alert(1)')).toBeNull(); expect(safeLinkUrl('data:text/html,hi')).toBeNull(); expect(safeLinkUrl('file:///c:/x')).toBeNull(); expect(safeLinkUrl('https://a.example.test/x')).toBe('https://a.example.test/x');
  });
  it('extracted scripts in a docx are plain data, links with javascript: are dropped', async () => {
    const r = await run(w('s.docx', makeDocx({ paragraphs: [{ text: '<script>alert(1)</script>' }, { text: 'bad', link: 'javascript:alert(1)' }, { text: 'good', link: 'https://ok.example.test/' }] })));
    expect(r.extractedText).toContain('<script>alert(1)</script>'); expect(r.links.map((l) => l.url)).toEqual(['https://ok.example.test/']);
  });
  it('no network or process APIs are used by the content module', () => {
    const base = path.join(__dirname, '..', 'electron', 'content');
    const files = [...fs.readdirSync(base).filter((f) => f.endsWith('.ts')), ...fs.readdirSync(path.join(base, 'visual')).filter((f) => f.endsWith('.ts')).map((f) => path.join('visual', f))]; // Phase 8: the visual/ subfolder is covered too
    for (const f of files) { const src = fs.readFileSync(path.join(base, f), 'utf8'); expect(src, f).not.toMatch(/child_process|shell\.open|openExternal|require\(['"]https?['"]\)|from 'node:https?'|fetch\(/); }
  });
});

describe('pipeline: watcher -> static analysis -> content', () => {
  it('extracts content for files copied into the monitored folder', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp4p-')), dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined);
    let a: AnalysisService, c: ContentService; const log = () => undefined;
    const agent = new MonitoringAgent(store, { log, emitChange: () => undefined, notify: () => undefined, onFileRecorded: (f) => a.enqueue(f), stability: { intervalMs: 60, requiredStableChecks: 2, timeoutMs: 5000 } });
    c = new ContentService(store, agent.events, { log, emitChange: () => undefined, dir: path.join(root, 'content') });
    a = new AnalysisService(store, agent.events, { log, emitChange: () => undefined, onAnalyzed: (f) => c.enqueue(f) });
    await agent.start(); await new Promise((r) => setTimeout(r, 300));
    for (const n of ['salary-increment.pdf', 'college-notice.txt', 'scholarship.zip']) fs.copyFileSync(path.join(FIX, n), path.join(dl, n));
    fs.writeFileSync(path.join(dl, 'x.crdownload'), 'partial'); fs.writeFileSync(path.join(dl, 'invoice.pdf.exe'), makePE());
    const t = Date.now(); while (store.state.files.filter((f) => f.contentStatus && ['COMPLETED', 'PARTIAL', 'UNSUPPORTED', 'FAILED'].includes(f.contentStatus)).length < 4 && Date.now() - t < 15000) await new Promise((r) => setTimeout(r, 50));
    await a.idle(); await c.idle();
    const by = (n: string) => store.state.files.find((f) => f.name === n)!;
    expect(store.state.files).toHaveLength(4);
    expect(by('salary-increment.pdf')).toMatchObject({ contentStatus: 'COMPLETED', contentType: 'pdf', previewAvailable: true, previewType: 'pdf', documentType: 'Salary increment letter' });
    expect(by('salary-increment.pdf').sha256).toHaveLength(64);
    expect(by('scholarship.zip')).toMatchObject({ contentStatus: 'COMPLETED', previewType: 'archive' });
    expect(by('invoice.pdf.exe')).toMatchObject({ contentStatus: 'UNSUPPORTED', previewAvailable: false });
    const full = await c.get(by('salary-increment.pdf').id); expect(full!.pages).toHaveLength(2); expect(await c.get('../../etc/passwd')).toBeNull();
    expect(store.state.events.map((e) => e.type)).toEqual(expect.arrayContaining(['content-started', 'content-completed', 'preview-generated']));
    expect(by('salary-increment.pdf').riskLevel).toBe('unknown'); // no verdict in Phase 4
    await agent.stopAll(); fs.rmSync(root, { recursive: true, force: true });
  }, 40_000);
});
