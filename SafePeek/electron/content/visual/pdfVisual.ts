import { LIMITS } from '../limits';
import type { PdfVisualKind, QrCodeInfo, VisualAnalysis } from '../types';
import { analyzeOneImage } from './imageAnalyzer';
import type { RawPixels } from './imagePipeline';
import { readOcrCache, writeOcrCache } from './ocrCache';
import { emptyVisual } from './visualResult';
import type { ExtractBudget } from '../types';

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface PdfOcrPage { page: number; text: string; confidence: number | null }
export interface PdfVisualResult {
  visual: VisualAnalysis; ocrPages: PdfOcrPage[]; qr: QrCodeInfo[]; warnings: string[];
  /** Pages with no meaningful text AND no image SafePeek could read (blank, vector-drawn, or an image above the size limit). */
  unreadablePages: number[]; incomplete: boolean;
}
interface PdfCache { ocrPages: PdfOcrPage[]; qr: QrCodeInfo[]; imagesAnalyzed: number; ocrImageCount: number; downscaled: boolean; pdfKind: PdfVisualKind; unreadablePages: number[]; ocrMs: number }

export const alnumCount = (t: string): number => (t.match(/[\p{L}\p{N}]/gu) ?? []).length;
interface PageImage { id: string; width: number; height: number; kind: number; data: Uint8Array | Uint8ClampedArray }

/**
 * Collects the raster images a page paints, straight from its operator list. This is DATA extraction: nothing is rendered, no scripts or
 * actions run, no annotation URL is opened (the same safe pdf.js usage as the text path; enableScripting is never set).
 */
async function pageImages(page: any, OPS: any): Promise<PageImage[]> {
  const ol = await page.getOperatorList(); const out: PageImage[] = []; const seen = new Set<string>();
  for (let i = 0; i < ol.fnArray.length; i++) {
    const fn = ol.fnArray[i]; const a = ol.argsArray[i];
    if (fn !== OPS.paintImageXObject && fn !== OPS.paintInlineImageXObject) continue;
    let o: any = null;
    try {
      if (fn === OPS.paintInlineImageXObject) o = a?.[0];
      else { const id = String(a?.[0]); if (seen.has(id)) continue; seen.add(id); o = page.objs.has(id) ? page.objs.get(id) : page.commonObjs.has(id) ? page.commonObjs.get(id) : null; }
    } catch { o = null; }
    if (o && o.data && o.width > 0 && o.height > 0) out.push({ id: String(a?.[0]).slice(0, 40), width: o.width, height: o.height, kind: o.kind, data: o.data });
  }
  return out.sort((x, y) => y.width * y.height - x.width * x.height);
}

/** pdf.js image kinds: 1 = 1-bit gray (bit-packed rows), 2 = RGB 24 bpp, 3 = RGBA 32 bpp. */
function toRaw(im: PageImage): RawPixels | null {
  const { width: w, height: h } = im; const d = im.data; const buf = Buffer.from(d.buffer, d.byteOffset, d.byteLength);
  if (im.kind === 2 && buf.length >= w * h * 3) return { data: buf.subarray(0, w * h * 3), width: w, height: h, channels: 3 };
  if (im.kind === 3 && buf.length >= w * h * 4) return { data: buf.subarray(0, w * h * 4), width: w, height: h, channels: 4 };
  if (im.kind === 1) {
    const stride = (w + 7) >> 3; if (buf.length < stride * h) return null;
    const g = Buffer.allocUnsafe(w * h);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) g[y * w + x] = (buf[y * stride + (x >> 3)] >> (7 - (x & 7))) & 1 ? 255 : 0;
    return { data: g, width: w, height: h, channels: 1 };
  }
  return null;
}

export function classifyPdf(pages: { text: string }[], ocrPageCount: number, imagePages: number): PdfVisualKind {
  const meaningful = pages.filter((p) => alnumCount(p.text) >= LIMITS.PDF_PAGE_TEXT_MIN_ALNUM).length;
  if (meaningful === 0) return ocrPageCount > 0 || imagePages > 0 ? 'IMAGE_ONLY' : 'EMPTY';
  return ocrPageCount > 0 ? 'MIXED' : 'TEXT';
}

/**
 * Visual analysis of a PDF whose direct text has already been extracted:
 *   - pages WITHOUT a meaningful text layer (or only a little text next to a large image) are OCR'd from their embedded images;
 *   - every page that paints a usable image is searched for QR codes;
 *   - pages with real text are NOT OCR'd (the text layer is authoritative and cheaper).
 * All of it is bounded by page, pixel and time limits; hitting any limit marks the result incomplete (never "safe").
 */
export async function analyzePdfVisual(doc: any, OPS: any, pages: { number: number; text: string }[], o: { sha: string; cacheDir?: string; budget?: ExtractBudget }): Promise<PdfVisualResult> {
  const v = emptyVisual(); const warnings: string[] = []; const unreadable: number[] = []; let incomplete = false;

  const cached = await readOcrCache<PdfCache>(o.cacheDir, o.sha, 'pdf');
  if (cached) {
    v.cacheHit = true; v.ocrStatus = cached.ocrImageCount ? 'COMPLETED' : 'NOT_ATTEMPTED'; v.imagesAnalyzed = cached.imagesAnalyzed; v.ocrImageCount = cached.ocrImageCount; v.ocrPages = cached.ocrPages.map((p) => p.page);
    v.qrCodes = cached.qr; v.downscaled = cached.downscaled; v.pdfKind = cached.pdfKind; v.ocrDurationMs = 0;
    return { visual: v, ocrPages: cached.ocrPages, qr: cached.qr, warnings, unreadablePages: cached.unreadablePages, incomplete: false };
  }

  const ocrPages: PdfOcrPage[] = []; const qr: QrCodeInfo[] = []; let imagesAnalyzed = 0; let ocrImageCount = 0; let failures = 0; let totalPx = 0; let ocrMs = 0; let imagePages = 0; let downscaled = false; let ocrAttempted = 0;
  const confs: number[] = []; const skippedOcr: number[] = []; let stopped = false;
  const base = o.budget ? Math.max(0, o.budget.remaining() - 3_000) : 12_000;
  let deadline = Date.now() + Math.min(12_000, base); let extended = false;
  const scanPages = pages.slice(0, LIMITS.MAX_PDF_VISUAL_PAGES);
  if (pages.length > scanPages.length) { v.limitsHit.push(`Only the first ${scanPages.length} pages were inspected for images and QR codes`); incomplete = true; }

  for (const pg of scanPages) {
    if (stopped) break;
    if (Date.now() > deadline) { v.limitsHit.push('Visual analysis time limit reached'); incomplete = true; stopped = true; break; }
    let imgs: PageImage[] = [];
    try { const page = await doc.getPage(pg.number); imgs = await pageImages(page, OPS); try { page.cleanup(); } catch { /* ignore */ } } catch { warnings.push(`Page ${pg.number}: its images could not be read.`); incomplete = true; continue; }
    const usable = imgs.filter((im) => Math.min(im.width, im.height) >= LIMITS.MIN_QR_IMAGE_SIDE).slice(0, LIMITS.MAX_PDF_IMAGES_PER_PAGE);
    const alnum = alnumCount(pg.text); const hasLarge = usable.some((im) => Math.max(im.width, im.height) >= LIMITS.PDF_LARGE_IMAGE_SIDE && im.width * im.height >= 200_000);
    const needsOcr = usable.length > 0 && (alnum < LIMITS.PDF_PAGE_TEXT_MIN_ALNUM || (hasLarge && alnum < LIMITS.PDF_PAGE_TEXT_WITH_IMAGE_ALNUM));
    if (usable.length) imagePages++;
    if (alnum < LIMITS.PDF_PAGE_TEXT_MIN_ALNUM && usable.length === 0) { unreadable.push(pg.number); continue; }
    if (usable.length === 0) continue;
    let doOcr = needsOcr;
    if (doOcr && ocrAttempted >= LIMITS.MAX_PDF_OCR_PAGES) { skippedOcr.push(pg.number); doOcr = false; }
    if (doOcr) ocrAttempted++;
    if (doOcr && !extended) { o.budget?.extend(LIMITS.PDF_OCR_TOTAL_MS + 15_000); deadline = Date.now() + LIMITS.PDF_OCR_TOTAL_MS; extended = true; }

    const pageText: string[] = []; let pageConf: number[] = []; let pageOk = false;
    for (const im of usable.slice(0, doOcr ? 2 : LIMITS.MAX_PDF_IMAGES_PER_PAGE)) {
      if (Date.now() > deadline) { v.limitsHit.push('Visual analysis time limit reached'); incomplete = true; stopped = true; break; }
      totalPx += im.width * im.height;
      if (totalPx > LIMITS.MAX_PDF_VISUAL_TOTAL_PIXELS) { v.limitsHit.push('PDF image pixel budget reached'); incomplete = true; stopped = true; break; }
      const raw = toRaw(im); if (!raw) { warnings.push(`Page ${pg.number}: an image in an unsupported pixel format was skipped.`); if (doOcr) failures++; continue; }
      imagesAnalyzed++;
      const r = await analyzeOneImage(raw, { location: `page ${pg.number}`, ocr: doOcr, qr: qr.length < LIMITS.MAX_QR_CODES_TOTAL, qrFirstIndex: qr.length + 1, deadline });
      for (const q of r.qr) if (qr.length < LIMITS.MAX_QR_CODES_TOTAL && !qr.some((x) => x.payload === q.payload && x.location === q.location)) qr.push({ ...q, index: qr.length + 1 });
      downscaled ||= r.downscaled; ocrMs += r.ocrMs;
      if (doOcr) {
        if (r.state === 'ok') { ocrImageCount++; pageOk = true; if (r.text) pageText.push(r.text); if (r.confidence !== null) { pageConf.push(r.confidence); confs.push(r.confidence); } }
        else { failures++; incomplete = true; v.ocrWarnings.push(`Page ${pg.number}: ${r.state === 'timeout' ? 'OCR took too long' : r.state === 'limit' ? 'image too large for OCR' : 'OCR could not be completed'}.`); if (r.state === 'limit') v.limitsHit.push('Image size limit'); }
      } else if (r.state !== 'ok' && r.state !== 'skipped') { v.ocrWarnings.push(`Page ${pg.number}: an image could not be searched for QR codes.`); }
    }
    if (doOcr && (pageOk || pageText.length)) ocrPages.push({ page: pg.number, text: pageText.join('\n\n'), confidence: pageConf.length ? pageConf.reduce((a, b) => a + b, 0) / pageConf.length : null });
    else if (doOcr && !pageOk) { /* counted as failure above */ }
    pageConf = [];
  }
  if (skippedOcr.length) { v.limitsHit.push(`${skippedOcr.length} more page(s) needed OCR than the limit of ${LIMITS.MAX_PDF_OCR_PAGES} pages`); incomplete = true; }
  const kind = classifyPdf(pages, ocrPages.length, imagePages); v.pdfKind = kind;
  v.imagesAnalyzed = imagesAnalyzed; v.ocrImageCount = ocrImageCount; v.ocrPages = ocrPages.map((p) => p.page); v.qrCodes = qr; v.downscaled = downscaled; v.ocrDurationMs = ocrMs;
  v.ocrConfidence = confs.length ? Math.round(confs.reduce((a, b) => a + b, 0) / confs.length) : null;
  if (ocrImageCount === 0 && failures === 0 && skippedOcr.length === 0) v.ocrStatus = 'NOT_ATTEMPTED';
  else if (failures === 0 && skippedOcr.length === 0 && !stopped) v.ocrStatus = 'COMPLETED';
  else v.ocrStatus = ocrImageCount > 0 ? 'PARTIAL' : 'FAILED';
  if (!incomplete && (v.ocrStatus === 'COMPLETED' || v.ocrStatus === 'NOT_ATTEMPTED')) await writeOcrCache(o.cacheDir, o.sha, 'pdf', { ocrPages, qr, imagesAnalyzed, ocrImageCount, downscaled, pdfKind: kind, unreadablePages: unreadable, ocrMs } satisfies PdfCache);
  return { visual: v, ocrPages, qr, warnings, unreadablePages: unreadable, incomplete };
}
