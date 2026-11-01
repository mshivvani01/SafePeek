import type { AnalysisResult } from '../analysis/types';
import type { ContentExtractor, ContentResult, ExtractBudget, ExtractContext, ExtractOutput, ExtractorType, LinkInfo } from './types';
import { ExtractionError } from './types';
import { LIMITS } from './limits';
import { cleanInline, safeLinkUrl, sanitizeText } from './sanitizer';
import { summarize } from './summarizer';
import { choosePreview, unsupportedMessage } from './previewService';
import { textExtractor } from './textExtractor';
import { pdfExtractor } from './pdfExtractor';
import { docxExtractor, pptxExtractor, xlsxExtractor } from './officeExtractor';
import { imageExtractor } from './imageExtractor';
import { archiveExtractor } from './archiveExtractor';
import { urlKey } from '../analysis/urls';

/** Registry order matters: first match wins. Executables are never handed to any extractor. */
export const EXTRACTORS: ContentExtractor[] = [pdfExtractor, docxExtractor, xlsxExtractor, pptxExtractor, imageExtractor, archiveExtractor, textExtractor];

export function pickExtractor(ctx: ExtractContext): ContentExtractor | null {
  const cat = ctx.analysis?.identity.category;
  if (cat === 'executable' && ctx.typeId !== 'jar') return null;
  return EXTRACTORS.find((e) => e.canHandle(ctx)) ?? null;
}

export function contextFor(path: string, name: string, size: number, analysis: AnalysisResult | undefined, opts: { visualCacheDir?: string } = {}): ExtractContext {
  return { path, name, size, analysis, typeId: analysis?.identity.detectedTypeId ?? 'unknown', officeFormat: analysis?.office?.format, visualCacheDir: opts.visualCacheDir };
}

/** Timeout whose deadline an extractor may extend (PDF OCR runs after text extraction under its own bounded budget). */
function withBudget<T>(run: (b: ExtractBudget) => Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout | undefined; let deadline = Date.now() + ms; let rej: (e: Error) => void = () => undefined;
  const arm = () => { if (t) clearTimeout(t); t = setTimeout(() => rej(new ExtractionError('Extraction timed out', 'limit')), Math.max(1, deadline - Date.now())); t.unref?.(); };
  const budget: ExtractBudget = { extend: (extra) => { deadline += extra; arm(); }, remaining: () => Math.max(0, deadline - Date.now()) };
  const guard = new Promise<T>((_, r) => { rej = r; arm(); });
  return Promise.race([run(budget), guard]).finally(() => { if (t) clearTimeout(t); });
}
const deepClean = <T>(v: T): T => {
  if (typeof v === 'string') return sanitizeText(v, 60_000).text as unknown as T;
  if (Array.isArray(v)) return v.map(deepClean) as unknown as T;
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, deepClean(x)])) as T;
  return v;
};
const empty = (name: string, ext: ExtractorType, now: string): ContentResult => ({
  version: 1, status: 'UNSUPPORTED', extractorType: ext, fileName: name, textLength: 0, links: [], summary: { documentType: 'Unknown', title: null, description: '', pageCount: null, textLength: 0, entities: { organizations: [], people: [], amounts: [], dates: [], emails: [], phones: [] }, keySections: [] },
  previewType: 'unsupported', previewAvailable: false, embeddedContentWarning: false, extractionWarnings: [], truncated: false, startedAt: now, analyzedAt: now, executionPerformed: false, uploaded: false
});

/**
 * Content extraction for ONE file. Never opens the file in another application and never executes it.
 * Parser failures become PARTIAL/FAILED results, never exceptions.
 */
export async function extractContent(ctx: ExtractContext): Promise<ContentResult> {
  const started = new Date().toISOString();
  const r = empty(ctx.name, 'none', started);
  const finish = (): ContentResult => { r.analyzedAt = new Date().toISOString(); return r; };

  if (!ctx.analysis || ctx.analysis.status === 'failed') { r.status = 'FAILED'; r.extractionWarnings.push('Content analysis needs a successful static analysis first.'); r.technicalDetails = ctx.analysis?.partialReasons.join(' '); return finish(); }
  const ex = pickExtractor(ctx);
  if (!ex) { r.status = 'UNSUPPORTED'; r.unsupportedReason = unsupportedMessage(ctx); return finish(); }
  r.extractorType = ex.id;

  let out: ExtractOutput = {};
  try { out = await withBudget((budget) => ex.extract({ ...ctx, budget }), ex.id === 'image' ? LIMITS.OCR_TIMEOUT_MS : LIMITS.TIMEOUT_MS); }
  catch (e) {
    const kind = e instanceof ExtractionError ? e.kind : 'corrupt';
    r.status = kind === 'encrypted' || kind === 'limit' ? 'PARTIAL' : kind === 'unsupported' ? 'UNSUPPORTED' : 'FAILED';
    r.technicalDetails = cleanInline(String((e as Error)?.message ?? e), 300);
    r.extractionWarnings.push(kind === 'encrypted' ? 'This file is encrypted, so its content could not be extracted.' : kind === 'limit' ? 'Extraction stopped because the file exceeded a safety limit.' : 'SafePeek could not extract the content of this file. It may be corrupted or malformed.');
    if (ctx.analysis.identity.category === 'archive' || ex.id === 'archive') r.unsupportedReason = unsupportedMessage(ctx);
    return finish();
  }

  const { warnings, ...rest } = out;
  Object.assign(r, deepClean({ ...rest, image: undefined }));
  if (out.image) r.image = out.image; // data URI is generated by us, not extracted text
  if (out.visual) r.visual = deepClean(out.visual); // OCR/QR strings are untrusted text: sanitized like everything else
  r.extractionWarnings = [...(warnings ?? [])].map((w) => cleanInline(w, 300));
  r.status = out.status ?? 'COMPLETED';
  if (r.status === 'UNSUPPORTED') { r.unsupportedReason ??= unsupportedMessage(ctx); r.extractorType = ex.id; }

  // Text: join pages if the extractor did not, cap, count.
  if (r.extractedText === undefined && r.pages) r.extractedText = r.pages.map((p) => p.text).join('\n\n');
  const capped = sanitizeText(r.extractedText ?? '', LIMITS.MAX_TEXT_LENGTH);
  r.extractedText = capped.text; r.textLength = capped.text.length;
  if (capped.truncated) { r.truncated = true; r.extractionWarnings.push(`Extracted text was cut at ${LIMITS.MAX_TEXT_LENGTH.toLocaleString()} characters.`); }
  r.truncated = !!r.truncated;

  // Links: merge, drop anything that is not a plain http(s)/mailto/ftp URL, never visit.
  const seen = new Set<string>(); const links: LinkInfo[] = [];
  for (const l of r.links ?? []) { const u = safeLinkUrl(l.url); const k = u ? urlKey(u) : ''; if (u && !seen.has(k) && links.length < LIMITS.MAX_LINKS) { seen.add(k); links.push({ ...l, url: u }); } }
  r.links = links;

  const text = [r.extractedText, r.ocrText && r.ocrText !== r.extractedText ? r.ocrText : ''].filter(Boolean).join('\n\n');
  const extra = r.extractorType === 'archive' ? `${r.archiveEntries?.length ?? 0} entries are listed; nothing was extracted or run.` : undefined;
  r.summary = summarize({ text, extractor: r.extractorType, pageCount: r.pageCount ?? r.sheets?.length ?? null, sections: r.sections, titleHint: r.properties?.Title && r.extractorType !== 'text' ? r.properties.Title : (r.slides?.[0]?.title || null), extra });
  if (r.extractorType === 'archive') {
    const n = r.archiveEntries ?? []; const files = n.filter((e) => !e.isDirectory).length; const exe = n.filter((e) => e.dangerous).length;
    r.summary.documentType = `${r.archiveFormat ?? 'ZIP'} archive`;
    r.summary.description = `This archive lists ${files} file${files === 1 ? '' : 's'}${exe ? `, including ${exe} executable or script file${exe === 1 ? '' : 's'}` : ''}. Nothing was extracted or run.`;
  }
  if (r.extractorType === 'image' && r.image && !text) r.summary.description = `This image (${r.image.width ?? '?'}×${r.image.height ?? '?'}) contains no text that OCR could read.`;
  if (r.extractorType === 'image' && text) r.summary.description = r.summary.description.replace(/^This image/, 'This image');
  if (r.extractorType === 'xlsx') r.summary.keySections = (r.sheets ?? []).map((s) => s.name).slice(0, 8);
  if (r.extractorType === 'pptx') r.summary.keySections = (r.slides ?? []).map((s) => s.title).filter(Boolean).slice(0, 8);
  if (r.embeddedContentWarning) r.extractionWarnings.push('Embedded content detected. SafePeek has not executed this content.');

  const pv = choosePreview(ctx, r.extractorType, r);
  r.previewType = pv.previewType; r.previewAvailable = pv.previewAvailable;
  if (!pv.previewAvailable && r.status === 'COMPLETED') r.status = 'PARTIAL';
  return finish();
}
