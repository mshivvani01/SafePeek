import type { OfficeInfo, EmbeddedObject } from './types';
import { DANGEROUS_EXTENSIONS, extOf } from './extensions';
import { ZipHandle, readEntryText } from './zip';

const attr = (tag: string, n: string) => new RegExp(`${n}="([^"]*)"`, 'i').exec(tag)?.[1] ?? '';
const unesc = (s: string) => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'");

/** Returns null if the package is not OOXML (no [Content_Types].xml). Reads XML parts in memory with caps; never opens Office. */
export async function inspectOffice(h: ZipHandle): Promise<OfficeInfo | null> {
  const names = h.entries.map((e) => e.name);
  const lower = names.map((n) => n.toLowerCase());
  const ct = h.entries.find((e) => e.name === '[Content_Types].xml');
  if (!ct) return null;
  const ctText = (await readEntryText(h, ct)) ?? '';
  const has = (p: string) => lower.some((n) => n.startsWith(p));
  let format: OfficeInfo['format'] = 'unknown-ooxml';
  if (has('word/')) format = 'docx'; else if (has('xl/')) format = 'xlsx'; else if (has('ppt/')) format = 'pptx';
  const label = { docx: 'Microsoft Word Document', xlsx: 'Microsoft Excel Workbook', pptx: 'Microsoft PowerPoint Presentation', 'unknown-ooxml': 'Office Open XML Package' }[format];
  const macroEnabledType = /macroEnabled/i.test(ctText);
  const hasMacros = lower.some((n) => n.endsWith('vbaproject.bin')) || macroEnabledType;
  const hasActiveX = lower.some((n) => /\/activex\//.test(n));

  const embeddedObjects: EmbeddedObject[] = h.entries
    .filter((e) => /\/(embeddings|activex)\/[^/]+$/i.test(e.name) || /\/media\/.+\.(exe|dll|bat|js|vbs|ps1|scr)$/i.test(e.name))
    .map((e) => { const base = e.name.split('/').pop() ?? e.name; const ext = extOf(base); return { name: e.name, kind: /activex/i.test(e.name) ? 'ActiveX control' : ext === 'bin' ? 'OLE object' : 'Embedded file', executable: DANGEROUS_EXTENSIONS.has(ext), source: 'office-package' }; });

  const externalRelationships: OfficeInfo['externalRelationships'] = [];
  let rels = 0;
  for (const e of h.entries) {
    if (!/\.rels$/i.test(e.name) || ++rels > 200) continue;
    const t = await readEntryText(h, e);
    if (!t) continue;
    for (const m of t.matchAll(/<Relationship\b[^>]*>/gi)) {
      if (/TargetMode="External"/i.test(m[0])) externalRelationships.push({ target: unesc(attr(m[0], 'Target')).slice(0, 2048), type: attr(m[0], 'Type').split('/').pop() ?? '' });
      if (externalRelationships.length >= 200) break;
    }
  }

  const metadata: Record<string, string> = {};
  const core = h.entries.find((e) => e.name === 'docProps/core.xml');
  if (core) {
    const t = (await readEntryText(h, core)) ?? '';
    for (const [k, tag] of [['Title', 'dc:title'], ['Author', 'dc:creator'], ['Last modified by', 'cp:lastModifiedBy'], ['Created', 'dcterms:created'], ['Modified', 'dcterms:modified']] as const) {
      const v = new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, 'i').exec(t)?.[1]; if (v) metadata[k] = unesc(v).slice(0, 200);
    }
  }
  const app = h.entries.find((e) => e.name === 'docProps/app.xml');
  if (app) { const v = /<Application>([^<]*)<\/Application>/i.exec((await readEntryText(h, app)) ?? '')?.[1]; if (v) metadata['Application'] = unesc(v).slice(0, 100); }
  return { format, label, macroEnabledType, hasMacros, hasActiveX, externalRelationships, embeddedObjects, metadata };
}
