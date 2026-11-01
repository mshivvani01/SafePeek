import { XMLParser } from 'fast-xml-parser';
/* eslint-disable @typescript-eslint/no-explicit-any */
export type N = Record<string, any>;
const parser = new XMLParser({ preserveOrder: true, ignoreAttributes: false, attributeNamePrefix: '@_', trimValues: false, parseTagValue: false, parseAttributeValue: false, processEntities: true, allowBooleanAttributes: true });

/** Parses an OOXML part. DOCTYPE declarations (entity-expansion / XXE vectors) are stripped before parsing; nothing external is ever resolved. */
export function parseXml(xml: string): N[] { return parser.parse(xml.replace(/<!DOCTYPE[^>[]*(\[[\s\S]*?\])?\s*>/gi, '')) as N[]; }
export const tagOf = (n: N): string => Object.keys(n).find((k) => k !== ':@') ?? '';
export const kids = (n: N): N[] => { const v = n[tagOf(n)]; return Array.isArray(v) ? v : []; };
export const attr = (n: N, a: string): string | undefined => n[':@']?.[`@_${a}`];
export function* descendants(nodes: N[]): Generator<N> { for (const n of nodes) { if (tagOf(n) === '#text') continue; yield n; yield* descendants(kids(n)); } }
export const findAll = (nodes: N[], tag: string): N[] => { const o: N[] = []; for (const n of descendants(nodes)) if (tagOf(n) === tag) o.push(n); return o; };
export const findFirst = (nodes: N[], tag: string): N | undefined => { for (const n of descendants(nodes)) if (tagOf(n) === tag) return n; return undefined; };
const directText = (n: N): string => kids(n).map((k) => (tagOf(k) === '#text' ? String(k['#text'] ?? '') : '')).join('');
const TEXT_TAGS = new Set(['w:t', 'a:t', 't']);
const BREAK_TAGS = new Set(['w:br', 'w:cr', 'a:br']);
const SKIP = new Set(['mc:Fallback', 'w:del', 'w:rPr', 'w:pPr', 'a:rPr', 'a:pPr', 'rPh', 'phoneticPr']);
/** Visible text of a paragraph-like node (deleted text and fallbacks excluded). */
export function textOf(nodes: N[]): string {
  let out = '';
  for (const n of nodes) {
    const t = tagOf(n);
    if (t === '#text' || SKIP.has(t)) continue;
    if (TEXT_TAGS.has(t)) out += directText(n);
    else if (t === 'w:tab') out += '\t';
    else if (BREAK_TAGS.has(t)) out += '\n';
    else out += textOf(kids(n));
  }
  return out;
}
export const rawText = directText;
