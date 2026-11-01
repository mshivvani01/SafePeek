import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { analyzeFile } from '../electron/analysis/analyzer';
import { sha256File } from '../electron/analysis/hash';
import { detectType } from '../electron/analysis/magic';
import { doubleExtension } from '../electron/analysis/extensions';
import { extractUrls } from '../electron/analysis/urls';
import { isUnsafeEntryName } from '../electron/analysis/zip';
import { isTemporaryFile } from '../electron/agent/config';
import { PDF_ACTIVE, PDF_SAFE, PNG, makePE, makeZip } from './helpers/fixtures';
import { MonitoringAgent } from '../electron/agent/agent';
import { StateStore } from '../electron/agent/store';
import { AnalysisService } from '../electron/analysis/service';

let dir: string;
const w = (n: string, d: string | Buffer) => { const p = path.join(dir, n); fs.writeFileSync(p, d); return p; };
const codes = (r: { indicators: { code: string }[] }) => r.indicators.map((i) => i.code);
beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sp3-')); });
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('hashing', () => {
  it('matches a known SHA-256', async () => {
    expect(await sha256File(w('abc.txt', 'abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    const big = Buffer.alloc(3 * 1024 * 1024, 7);
    expect(await sha256File(w('big.bin', big))).toBe(createHash('sha256').update(big).digest('hex'));
  });
});

describe('type detection', () => {
  it('detects PDF, PNG, ZIP, PE, text', async () => {
    expect((await analyzeFile(w('a.pdf', PDF_SAFE))).identity.detectedTypeId).toBe('pdf');
    expect((await analyzeFile(w('a.png', PNG))).identity.detectedTypeId).toBe('png');
    expect((await analyzeFile(w('a.zip', makeZip({ 'x.txt': 'hi' })))).identity.detectedTypeId).toBe('zip');
    expect((await analyzeFile(w('a.exe', makePE()))).identity.detectedTypeId).toBe('pe');
    expect(detectType(Buffer.from('hello world'), 'a.txt', 11).id).toBe('text');
    expect(detectType(Buffer.from([0x1f, 0x8b, 8, 0]), 'a.gz', 4).id).toBe('gzip');
  });
  it('matching extension produces no mismatch', async () => {
    const r = await analyzeFile(w('ok.pdf', PDF_SAFE));
    expect(r.identity.typeMismatch).toBe(false); expect(codes(r)).not.toContain('TYPE_MISMATCH'); expect(r.sha256).toHaveLength(64); expect(r.pdf?.pageCount).toBe(1);
  });
});

describe('mismatch / double extension / executables', () => {
  it('fake.pdf that is really a PE', async () => {
    const r = await analyzeFile(w('fake.pdf', makePE()));
    expect(r.identity.typeMismatch).toBe(true); expect(codes(r)).toContain('TYPE_MISMATCH'); expect(r.identity.detectedType).toMatch(/Windows Executable/);
    expect(r.pe?.architecture).toMatch(/x64/); expect(r.pe?.sections).toEqual(['.text']); expect(r.pe?.imports).toEqual(['KERNEL32.dll']); expect(r.identity.executionPerformed).toBe(false);
  });
  it('text pretending to be a PDF', async () => { expect(codes(await analyzeFile(w('notpdf.pdf', 'just text')))).toContain('TYPE_MISMATCH'); });
  it('double extension', async () => {
    expect(doubleExtension('invoice.pdf.exe')).toBe('.pdf.exe'); expect(doubleExtension('a.docx.scr')).toBe('.docx.scr'); expect(doubleExtension('photo.jpg.js')).toBe('.jpg.js');
    expect(doubleExtension('report.final.pdf')).toBeNull(); expect(doubleExtension('invoice.pdf .exe')).toBe('.pdf.exe');
    const r = await analyzeFile(w('invoice.pdf.exe', makePE()));
    expect(codes(r)).toEqual(expect.arrayContaining(['DOUBLE_EXTENSION', 'EXECUTABLE_FILE']));
  });
  it('script detection', async () => {
    const r = await analyzeFile(w('x.ps1', 'Write-Host "hi"\nvisit https://example.com/a.\n'));
    expect(r.script?.language).toBe('PowerShell'); expect(codes(r)).toContain('SCRIPT_FILE'); expect(r.script?.executionPerformed).toBe(false); expect(r.urls).toEqual(['https://example.com/a']);
  });
  it('empty file', async () => { expect(codes(await analyzeFile(w('empty.txt', '')))).toContain('EMPTY_FILE'); });
});

describe('archives', () => {
  it('lists entries without extracting', async () => {
    const r = await analyzeFile(w('test.zip', makeZip({ 'document.pdf': PDF_SAFE, 'test.exe': 'MZ', 'docs/': '', 'docs/readme.txt': 'x' })));
    const n = r.archive!.entries.map((e) => e.name);
    expect(n).toEqual(expect.arrayContaining(['document.pdf', 'test.exe', 'docs/']));
    expect(r.archive!.entries.find((e) => e.name === 'test.exe')!.dangerous).toBe(true); expect(r.archive!.extracted).toBe(false); expect(codes(r)).toContain('ARCHIVE_EXECUTABLE');
    expect(fs.readdirSync(dir).includes('test.exe')).toBe(false);
  });
  it('flags zip-slip names and does not throw', async () => {
    expect(isUnsafeEntryName('../../evil.txt')).toBe(true); expect(isUnsafeEntryName('C:\\x.txt')).toBe(true); expect(isUnsafeEntryName('a/b.txt')).toBe(false);
    const r = await analyzeFile(w('slip.zip', makeZip({ '../../evil.txt': 'x' })));
    expect(codes(r)).toContain('ARCHIVE_PATH_TRAVERSAL');
  });
  it('malformed archive gives partial result with metadata', async () => {
    const r = await analyzeFile(w('bad.zip', Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4]), Buffer.alloc(40, 1)])));
    expect(r.status).toBe('partial'); expect(r.sha256).toHaveLength(64); expect(r.metadata.size).toBe(44);
  });
});

describe('urls / pdf / office', () => {
  it('extracts URLs', () => { expect(extractUrls('see https://example.com, and http://login-example.xyz/x?y=1.')).toEqual(['https://example.com', 'http://login-example.xyz/x?y=1']); });
  it('PDF actions and URI', async () => {
    const r = await analyzeFile(w('active.pdf', PDF_ACTIVE));
    expect(r.pdf?.hasJavaScript).toBe(true); expect(codes(r)).toEqual(expect.arrayContaining(['SUSPICIOUS_PDF_ACTION', 'EXTERNAL_URL'])); expect(r.urls).toContain('https://example.com/page');
  });
  const ct = (extra = '') => `<?xml version="1.0"?><Types>${extra}</Types>`;
  it('DOCX type, external rels, embedded exe, macros', async () => {
    const plain = await analyzeFile(w('t.docx', makeZip({ '[Content_Types].xml': ct(), 'word/document.xml': '<w/>' })));
    expect(plain.identity.detectedTypeId).toBe('docx'); expect(plain.identity.typeMismatch).toBe(false); expect(plain.office?.hasMacros).toBe(false);
    const rich = await analyzeFile(w('inv.docx', makeZip({
      '[Content_Types].xml': ct('<Override ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'), 'word/document.xml': '<w/>', 'word/vbaProject.bin': 'x', 'word/embeddings/payload.exe': 'MZ',
      'word/_rels/document.xml.rels': '<Relationships><Relationship Id="1" Type="x/hyperlink" Target="https://example.com/z" TargetMode="External"/></Relationships>'
    })));
    expect(codes(rich)).toEqual(expect.arrayContaining(['MACRO_DETECTED', 'EMBEDDED_EXECUTABLE', 'EXTERNAL_RELATIONSHIP', 'EXTERNAL_URL'])); expect(rich.office?.externalRelationships).toHaveLength(1);
  });
  it('XLSX and PPTX', async () => {
    expect((await analyzeFile(w('t.xlsx', makeZip({ '[Content_Types].xml': ct(), 'xl/workbook.xml': '<w/>' })))).identity.detectedTypeId).toBe('xlsx');
    expect((await analyzeFile(w('t.pptx', makeZip({ '[Content_Types].xml': ct(), 'ppt/presentation.xml': '<w/>' })))).identity.detectedTypeId).toBe('pptx');
    expect(codes(await analyzeFile(w('plain.docx', makeZip({ 'a.txt': 'x' }))))).toContain('TYPE_MISMATCH');
  });
});

describe('errors', () => {
  it('deleted file -> failed, no throw', async () => { const r = await analyzeFile(path.join(dir, 'nope.pdf')); expect(r.status).toBe('failed'); expect(r.partialReasons[0]).toMatch(/no longer exists/); });
  it('temp files are not analysis candidates', () => { expect(isTemporaryFile('movie.mp4.crdownload')).toBe(true); });
});

describe('pipeline: watcher -> analysis -> store', () => {
  it('analyzes a file copied into the monitored folder; ignores .crdownload', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sp3p-')), dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
    const store = new StateStore(path.join(root, 's.json'), dl, () => undefined);
    let svc: AnalysisService;
    const agent = new MonitoringAgent(store, { log: () => undefined, emitChange: () => undefined, notify: () => undefined, onFileRecorded: (f) => svc.enqueue(f), stability: { intervalMs: 60, requiredStableChecks: 2, timeoutMs: 5000 } });
    svc = new AnalysisService(store, agent.events, { log: () => undefined, emitChange: () => undefined });
    await agent.start(); await new Promise((r) => setTimeout(r, 300));
    fs.writeFileSync(path.join(dl, 'partial.crdownload'), 'x');
    fs.writeFileSync(path.join(dl, 'invoice.pdf.exe'), makePE());
    fs.writeFileSync(path.join(dl, 'salary.pdf'), PDF_SAFE);
    const t = Date.now(); while (store.state.files.filter((f) => f.analysisStatus === 'complete').length < 2 && Date.now() - t < 8000) await new Promise((r) => setTimeout(r, 50));
    await svc.idle();
    expect(store.state.files.map((f) => f.name).sort()).toEqual(['invoice.pdf.exe', 'salary.pdf']);
    const exe = store.state.files.find((f) => f.name === 'invoice.pdf.exe')!, pdf = store.state.files.find((f) => f.name === 'salary.pdf')!;
    expect(pdf.sha256).toHaveLength(64); expect(pdf.detectedType).toBe('PDF Document'); expect(pdf.riskLevel).toBe('unknown');
    expect(exe.indicators.map((i) => i.code)).toContain('DOUBLE_EXTENSION');
    expect(store.state.events.map((e) => e.type)).toEqual(expect.arrayContaining(['analysis-started', 'analysis-completed']));
    await agent.stopAll(); fs.rmSync(root, { recursive: true, force: true });
  });
});
