import type { ContentExtractor, ExtractContext, ExtractOutput, LinkInfo, Section, SheetData, SlideData, TableData } from './types';
import { ExtractionError } from './types';
import { LIMITS } from './limits';
import { ZipHandle, openZip } from '../analysis/zip';
import { readPart } from './zipRead';
import { N, attr, findAll, findFirst, kids, parseXml, rawText, tagOf, textOf } from './xml';
import { cleanInline, safeLinkUrl } from './sanitizer';

const fmt = (c: ExtractContext) => c.officeFormat ?? c.typeId;
async function withZip<T>(ctx: ExtractContext, fn: (h: ZipHandle) => Promise<T>): Promise<T> {
  if (ctx.size > LIMITS.MAX_FILE_SIZE) throw new ExtractionError('File too large; content not extracted.', 'limit');
  let h: ZipHandle;
  try { h = await openZip(ctx.path); } catch (e) { throw new ExtractionError(`Package could not be opened: ${cleanInline((e as Error).message, 120)}`, 'corrupt'); }
  try { return await fn(h); } finally { try { h.zip.close(); } catch { /* ignore */ } }
}
async function xmlPart(h: ZipHandle, name: string, warnings: string[]): Promise<N[] | null> {
  const p = await readPart(h, name); if (!p) return null;
  if (p.truncated) warnings.push(`${name} is larger than ${LIMITS.MAX_OFFICE_PART_BYTES / 1048576} MB; only part of it was read.`);
  try { return parseXml(p.text); } catch { warnings.push(`${name} is malformed XML.`); return null; }
}
/** Relationship id -> {target, external}. Targets are data only; they are never fetched. */
async function rels(h: ZipHandle, name: string): Promise<Map<string, { target: string; external: boolean; type: string }>> {
  const m = new Map<string, { target: string; external: boolean; type: string }>();
  const p = await readPart(h, name, 1024 * 1024); if (!p) return m;
  try { for (const r of findAll(parseXml(p.text), 'Relationship')) { const id = attr(r, 'Id'); if (id) m.set(id, { target: attr(r, 'Target') ?? '', external: /external/i.test(attr(r, 'TargetMode') ?? ''), type: attr(r, 'Type') ?? '' }); } } catch { /* ignore */ }
  return m;
}
async function coreProps(h: ZipHandle): Promise<Record<string, string>> {
  const out: Record<string, string> = {}; const p = await readPart(h, 'docProps/core.xml', 256 * 1024); if (!p) return out;
  const g = (tag: string) => new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`).exec(p.text)?.[1];
  for (const [k, t] of [['Title', 'dc:title'], ['Author', 'dc:creator'], ['Last modified by', 'cp:lastModifiedBy'], ['Created', 'dcterms:created'], ['Modified', 'dcterms:modified']] as const) { const v = g(t); if (v?.trim()) out[k] = cleanInline(v, 200); }
  return out;
}
const embeddedWarn = (c: ExtractContext) => { const o = c.analysis?.office; return !!o && (o.hasMacros || o.hasActiveX || o.embeddedObjects.length > 0); };
const resolve = (base: string, target: string) => { if (target.startsWith('/')) return target.slice(1); const parts = base.split('/'); parts.pop(); for (const s of target.split('/')) { if (s === '..') parts.pop(); else if (s !== '.') parts.push(s); } return parts.join('/'); };
const addLink = (links: LinkInfo[], url: string | undefined, text: string | undefined, source: string) => { const u = url ? safeLinkUrl(url) : null; if (u && links.length < LIMITS.MAX_LINKS && !links.some((l) => l.url === u)) links.push({ url: u, text: text ? cleanInline(text, 120) : undefined, source }); };

// ---------------- DOCX ----------------
function tableFromTbl(tbl: N): TableData {
  const rows: string[][] = []; let truncated = false;
  for (const tr of kids(tbl).filter((k) => tagOf(k) === 'w:tr')) {
    if (rows.length >= LIMITS.MAX_TABLE_ROWS) { truncated = true; break; }
    rows.push(kids(tr).filter((k) => tagOf(k) === 'w:tc').slice(0, LIMITS.MAX_TABLE_COLS).map((tc) => findAll(kids(tc), 'w:p').map((p) => textOf(kids(p))).join('\n').trim()));
  }
  return { rows, truncated };
}
export const docxExtractor: ContentExtractor = {
  id: 'docx',
  canHandle: (c) => fmt(c) === 'docx',
  extract: (ctx) => withZip(ctx, async (h): Promise<ExtractOutput> => {
    const warnings: string[] = [];
    const doc = await xmlPart(h, 'word/document.xml', warnings);
    if (!doc) throw new ExtractionError('word/document.xml missing or unreadable', 'corrupt');
    const rl = await rels(h, 'word/_rels/document.xml.rels');
    const body = findFirst(doc, 'w:body'); if (!body) throw new ExtractionError('Document body missing', 'corrupt');
    const sections: Section[] = []; const tables: TableData[] = []; const links: LinkInfo[] = [];
    const walkBlocks = (nodes: N[]) => {
      for (const n of nodes) {
        const t = tagOf(n);
        if (t === 'w:p') {
          const text = textOf(kids(n)).replace(/[ \t]+/g, ' ').trim();
          for (const hl of findAll(kids(n), 'w:hyperlink')) { const id = attr(hl, 'r:id'); const r = id ? rl.get(id) : undefined; if (r?.external) addLink(links, r.target, textOf(kids(hl)), 'hyperlink'); }
          if (!text || sections.length >= LIMITS.MAX_SECTIONS) continue;
          const style = attr(findFirst(kids(n), 'w:pStyle') ?? {}, 'w:val') ?? '';
          const m = /^heading\s*([1-9])$/i.exec(style); const title = /^title$/i.test(style);
          sections.push({ level: m ? Number(m[1]) : title ? 1 : 0, kind: m || title ? 'heading' : 'paragraph', text });
        } else if (t === 'w:tbl') {
          if (tables.length < LIMITS.MAX_TABLES) { tables.push(tableFromTbl(n)); sections.push({ level: 0, kind: 'table', text: '', tableIndex: tables.length - 1 }); }
        } else if (t === 'w:sdt' || t === 'w:sdtContent' || t === 'w:customXml') walkBlocks(kids(n));
      }
    };
    walkBlocks(kids(body));
    const media = h.entries.filter((e) => /^word\/media\//i.test(e.name) && !/\/$/.test(e.name)).map((e) => ({ name: e.name.split('/').pop()!, size: e.uncompressedSize }));
    const flat = sections.map((s) => (s.kind === 'table' ? tables[s.tableIndex!].rows.map((r) => r.join('\t')).join('\n') : s.text)).join('\n\n');
    const ew = embeddedWarn(ctx);
    if (!flat.trim()) warnings.push('No readable text found in this document.');
    return { extractedText: flat, sections, tables, links, images: media.slice(0, 50), properties: await coreProps(h), embeddedContentWarning: ew, warnings, status: warnings.length ? 'PARTIAL' : 'COMPLETED', truncated: sections.length >= LIMITS.MAX_SECTIONS };
  })
};

// ---------------- XLSX ----------------
const colIndex = (ref: string) => { let n = 0; for (const ch of /^[A-Z]+/i.exec(ref)?.[0].toUpperCase() ?? '') n = n * 26 + ch.charCodeAt(0) - 64; return Math.max(0, n - 1); };
export const xlsxExtractor: ContentExtractor = {
  id: 'xlsx',
  canHandle: (c) => fmt(c) === 'xlsx',
  extract: (ctx) => withZip(ctx, async (h): Promise<ExtractOutput> => {
    const warnings: string[] = [];
    const wb = await xmlPart(h, 'xl/workbook.xml', warnings);
    if (!wb) throw new ExtractionError('xl/workbook.xml missing or unreadable', 'corrupt');
    const wrl = await rels(h, 'xl/_rels/workbook.xml.rels');
    const ss: string[] = [];
    const sst = await xmlPart(h, 'xl/sharedStrings.xml', warnings);
    if (sst) for (const si of findAll(sst, 'si')) { ss.push(textOf(kids(si))); if (ss.length > 200_000) break; }
    const sheets: SheetData[] = []; const links: LinkInfo[] = [];
    const defs = findAll(wb, 'sheet');
    if (defs.length > LIMITS.MAX_SHEETS) warnings.push(`Workbook has ${defs.length} sheets; only the first ${LIMITS.MAX_SHEETS} were read.`);
    for (const d of defs.slice(0, LIMITS.MAX_SHEETS)) {
      const name = cleanInline(attr(d, 'name') ?? 'Sheet', 80); const rid = attr(d, 'r:id'); const target = rid ? wrl.get(rid)?.target : undefined;
      if (!target) { sheets.push({ name, range: '', rows: [], rowCount: 0, truncated: false }); continue; }
      const path = resolve('xl/workbook.xml', target);
      const x = await xmlPart(h, path, warnings);
      if (!x) { sheets.push({ name, range: '', rows: [], rowCount: 0, truncated: false }); warnings.push(`Sheet "${name}" could not be read.`); continue; }
      const rows: string[][] = []; let truncated = false; let rowCount = 0;
      for (const row of findAll(x, 'row')) {
        rowCount++;
        if (rows.length >= LIMITS.MAX_SHEET_ROWS) { truncated = true; continue; }
        const cells: string[] = [];
        for (const c of kids(row).filter((k) => tagOf(k) === 'c')) {
          const ci = colIndex(attr(c, 'r') ?? ''); if (ci >= LIMITS.MAX_TABLE_COLS) { truncated = true; continue; }
          const t = attr(c, 't'); const v = rawText(findFirst(kids(c), 'v') ?? {}); let val = '';
          if (t === 's') val = ss[Number(v)] ?? ''; else if (t === 'inlineStr') val = textOf(kids(findFirst(kids(c), 'is') ?? {})); else if (t === 'b') val = v === '1' ? 'TRUE' : 'FALSE'; else val = v;
          // Formulas are NEVER evaluated: the cached value is shown; with none, the formula text is shown as data.
          if (!val) { const f = findFirst(kids(c), 'f'); if (f) val = `=${rawText(f)}`; }
          while (cells.length < ci) cells.push(''); cells[ci] = val;
        }
        rows.push(cells);
      }
      const rel = await rels(h, path.replace(/([^/]+)$/, '_rels/$1.rels'));
      for (const hl of findAll(x, 'hyperlink')) { const id = attr(hl, 'r:id'); const r = id ? rel.get(id) : undefined; if (r?.external) addLink(links, r.target, attr(hl, 'display'), `sheet ${name}`); }
      sheets.push({ name, range: attr(findFirst(x, 'dimension') ?? {}, 'ref') ?? '', rows, rowCount, truncated });
    }
    if (h.entries.some((e) => /^xl\/externalLinks\//i.test(e.name))) warnings.push('Workbook references external workbooks. They were not loaded.');
    const text = sheets.map((s) => `[${s.name}]\n${s.rows.map((r) => r.join('\t')).join('\n')}`).join('\n\n');
    const trunc = sheets.some((s) => s.truncated);
    return { extractedText: text, sheets, links, properties: await coreProps(h), embeddedContentWarning: embeddedWarn(ctx), warnings, truncated: trunc, truncationNote: trunc ? `Showing up to ${LIMITS.MAX_SHEET_ROWS} rows per sheet` : undefined, status: warnings.some((w) => /could not|malformed|only part/.test(w)) ? 'PARTIAL' : 'COMPLETED' };
  })
};

// ---------------- PPTX ----------------
export const pptxExtractor: ContentExtractor = {
  id: 'pptx',
  canHandle: (c) => fmt(c) === 'pptx',
  extract: (ctx) => withZip(ctx, async (h): Promise<ExtractOutput> => {
    const warnings: string[] = [];
    const names = h.entries.map((e) => e.name);
    let order: string[] = [];
    const pres = await xmlPart(h, 'ppt/presentation.xml', warnings);
    if (pres) { const prl = await rels(h, 'ppt/_rels/presentation.xml.rels'); order = findAll(pres, 'p:sldId').map((s) => prl.get(attr(s, 'r:id') ?? '')?.target).filter((t): t is string => !!t).map((t) => resolve('ppt/presentation.xml', t)); }
    if (!order.length) order = names.filter((n) => /^ppt\/slides\/slide\d+\.xml$/i.test(n)).sort((a, b) => parseInt(a.replace(/\D/g, '')) - parseInt(b.replace(/\D/g, '')));
    const slides: SlideData[] = []; const links: LinkInfo[] = [];
    if (order.length > LIMITS.MAX_SLIDES) warnings.push(`Presentation has ${order.length} slides; only the first ${LIMITS.MAX_SLIDES} were read.`);
    for (const [i, path] of order.slice(0, LIMITS.MAX_SLIDES).entries()) {
      const x = await xmlPart(h, path, warnings);
      if (!x) { slides.push({ number: i + 1, title: '', text: '' }); warnings.push(`Slide ${i + 1} could not be read.`); continue; }
      const rl = await rels(h, path.replace(/([^/]+)$/, '_rels/$1.rels'));
      let title = ''; const paras: string[] = [];
      for (const sp of findAll(x, 'p:sp')) {
        const ph = attr(findFirst(kids(sp), 'p:ph') ?? {}, 'type'); const isTitle = ph === 'title' || ph === 'ctrTitle';
        const t = findAll(kids(sp), 'a:p').map((p) => textOf(kids(p)).trim()).filter(Boolean);
        if (isTitle && !title) title = t.join(' '); else paras.push(...t);
      }
      for (const hl of findAll(x, 'a:hlinkClick')) { const r = rl.get(attr(hl, 'r:id') ?? ''); if (r?.external) addLink(links, r.target, undefined, `slide ${i + 1}`); }
      let notes: string | undefined;
      const nt = [...rl.values()].find((r) => /notesSlide/i.test(r.type));
      if (nt) { const nx = await xmlPart(h, resolve(path, nt.target), warnings); if (nx) { const t = findAll(nx, 'a:p').map((p) => textOf(kids(p)).trim()).filter(Boolean).join('\n'); if (t) notes = t; } }
      slides.push({ number: i + 1, title, text: paras.join('\n'), notes });
    }
    const text = slides.map((s) => `Slide ${s.number}: ${s.title}\n${s.text}`).join('\n\n');
    return { extractedText: text, slides, pageCount: order.length, links, properties: await coreProps(h), embeddedContentWarning: embeddedWarn(ctx), warnings, truncated: order.length > LIMITS.MAX_SLIDES, status: warnings.some((w) => /could not|malformed|only/.test(w)) ? 'PARTIAL' : 'COMPLETED' };
  })
};
