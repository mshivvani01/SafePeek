import fs from 'node:fs';
import type { ContentExtractor, ExtractOutput, ImageInfo, QrCodeInfo, VisualAnalysis } from './types';
import { ExtractionError } from './types';
import { LIMITS } from './limits';
import { ocrImage } from './ocr';
import { analyzeOneImage, cleanOcrText, type ImageVisualOutput } from './visual/imageAnalyzer';
import { makeThumbnailDataUrl } from './visual/imagePipeline';
import { readOcrCache, sha256Hex, writeOcrCache } from './visual/ocrCache';
import { countVisualUrls, emptyVisual, visualLinks } from './visual/visualResult';

/** Reads width/height from the file header only (no decoding). */
export function imageDimensions(b: Buffer, typeId: string): { width: number; height: number } | null {
  try {
    if (typeId === 'png' && b.length >= 24) return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
    if (typeId === 'gif' && b.length >= 10) return { width: b.readUInt16LE(6), height: b.readUInt16LE(8) };
    if (typeId === 'jpeg') {
      let i = 2;
      while (i + 9 < b.length) {
        if (b[i] !== 0xff) { i++; continue; }
        const m = b[i + 1];
        if (m >= 0xc0 && m <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(m)) return { height: b.readUInt16BE(i + 5), width: b.readUInt16BE(i + 7) };
        if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
        i += 2 + b.readUInt16BE(i + 2);
      }
    }
    if (typeId === 'webp' && b.length >= 30) {
      const f = b.toString('ascii', 12, 16);
      if (f === 'VP8X') return { width: 1 + b.readUIntLE(24, 3), height: 1 + b.readUIntLE(27, 3) };
      if (f === 'VP8L') { const v = b.readUInt32LE(21); return { width: 1 + (v & 0x3fff), height: 1 + ((v >> 14) & 0x3fff) }; }
      if (f === 'VP8 ') return { width: b.readUInt16LE(26) & 0x3fff, height: b.readUInt16LE(28) & 0x3fff };
    }
  } catch { /* fall through */ }
  return null;
}

interface ImageCache { text: string; confidence: number | null; qr: QrCodeInfo[]; downscaled: boolean; ocrMs: number }

/** User-facing reasons (no internals). The technical message goes to technicalDetails only. */
const REASON: Record<string, string> = {
  timeout: 'OCR took too long on this image and was stopped, so some visual content could not be fully analyzed.',
  engine: 'OCR could not be completed for this image, so some visual content could not be fully analyzed.',
  corrupt: 'The image could not be decoded (it may be damaged), so its visual content could not be analyzed.',
  unavailable: 'Local image analysis is not available on this system, so the visual content of this image was not analyzed.'
};

export const imageExtractor: ContentExtractor = {
  id: 'image',
  canHandle: (c) => ['png', 'jpeg', 'gif', 'webp'].includes(c.typeId),
  async extract(ctx): Promise<ExtractOutput> {
    if (ctx.size > LIMITS.MAX_FILE_SIZE) throw new ExtractionError('Image larger than 50 MB; not processed.', 'limit');
    const buf = await fs.promises.readFile(ctx.path);
    const sha = sha256Hex(buf);
    const dim = imageDimensions(buf, ctx.typeId);
    const mime = { png: 'image/png', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' }[ctx.typeId]!;
    const info: ImageInfo = { width: dim?.width ?? null, height: dim?.height ?? null, size: ctx.size, format: ctx.typeId.toUpperCase() };
    const warnings: string[] = []; const v: VisualAnalysis = emptyVisual(); v.imagesAnalyzed = 1;
    const out: ExtractOutput = { image: info, warnings, status: 'COMPLETED', visual: v };
    // File changed between static analysis and now (or while it was being read): never present stale results as current.
    if (buf.length !== ctx.size || (ctx.analysis?.sha256 && ctx.analysis.sha256 !== sha)) { warnings.push('The file changed after it was first analyzed, so these results may be out of date. Re-run the analysis.'); out.status = 'PARTIAL'; }
    // Inert preview: the original bytes when small, otherwise a small re-encoded thumbnail (decoded by the browser engine only; no metadata is interpreted).
    if (ctx.size <= LIMITS.MAX_IMAGE_PREVIEW_BYTES) info.dataUrl = `data:${mime};base64,${buf.toString('base64')}`;
    else { info.dataUrl = await makeThumbnailDataUrl(buf); if (!info.dataUrl) info.previewOmittedReason = 'Image is larger than 4 MB; inline preview omitted.'; }
    if (!dim) warnings.push('Image dimensions could not be read from the header.');
    if (dim && (dim.width * dim.height > LIMITS.MAX_IMAGE_PIXELS || Math.max(dim.width, dim.height) > LIMITS.MAX_IMAGE_SIDE)) {
      warnings.push(`Image has ${(dim.width * dim.height / 1e6).toFixed(0)} megapixels (limit ${LIMITS.MAX_IMAGE_PIXELS / 1e6}); OCR skipped. Some visual content could not be fully analyzed.`);
      v.ocrStatus = 'PARTIAL'; v.ocrWarnings.push('Image exceeds the pixel safety limit.'); v.limitsHit.push('Image pixel limit'); out.status = 'PARTIAL'; return out;
    }

    let r: ImageVisualOutput | null = null; const cached = await readOcrCache<ImageCache>(ctx.visualCacheDir, sha, 'image');
    if (cached) v.cacheHit = true;
    else {
      r = await analyzeOneImage(buf, { location: 'image', ocr: true, qr: true, qrFirstIndex: 1, deadline: Date.now() + LIMITS.IMAGE_VISUAL_TOTAL_MS });
      if (r.state === 'unavailable' && dim && dim.width * dim.height <= 2_000_000) { // the image engine is missing: legacy direct OCR is still safe for small images
        try { const o = await ocrImage(buf); r = { ...r, state: 'ok', text: cleanOcrText(o.text), confidence: o.confidence, ocrRan: true }; } catch { /* stays unavailable */ }
      }
    }
    const text = cached ? cached.text : r!.text; const conf = cached ? cached.confidence : r!.confidence; const qr = cached ? cached.qr : r!.qr;
    const downscaled = cached ? cached.downscaled : r!.downscaled; let state: string = cached ? 'ok' : r!.state;
    if (!cached && r!.partialBands && r!.text) state = 'partial';
    v.ocrDurationMs = cached ? 0 : r!.ocrMs; v.downscaled = downscaled; v.ocrConfidence = conf; v.qrCodes = qr; v.ocrImageCount = state === 'ok' ? 1 : 0;
    if (downscaled) { warnings.push(`Large image (${dim?.width ?? '?'}×${dim?.height ?? '?'}) was reduced in size before OCR so it could be read quickly and safely.`); }

    if (state === 'partial') { out.ocrText = text; out.ocrConfidence = conf; out.extractedText = text; out.status = 'PARTIAL'; v.ocrStatus = 'PARTIAL'; v.ocrImageCount = 1; v.limitsHit.push('OCR time limit reached on a dense image'); warnings.push('This image has a lot of fine text; part of it was read before the OCR time limit was reached. Some visual content could not be fully analyzed.'); v.ocrWarnings.push('Only part of the image text was read.'); }
    else if (state === 'ok') {
      v.ocrStatus = 'COMPLETED';
      out.ocrText = text; out.ocrConfidence = conf; out.extractedText = text;
      if (!text) warnings.push('OCR found no readable text in this image.');
      else if (conf !== null && conf < 50) { warnings.push('OCR confidence is low; the extracted text may contain mistakes.'); v.ocrWarnings.push('Low OCR confidence.'); }
      if (!cached && r!.ocrRan === false) v.ocrStatus = 'COMPLETED';
      if (!cached && out.status === 'COMPLETED') await writeOcrCache(ctx.visualCacheDir, sha, 'image', { text, confidence: conf, qr, downscaled, ocrMs: r!.ocrMs } satisfies ImageCache);
    } else {
      out.status = 'PARTIAL';
      v.ocrStatus = state === 'limit' ? 'PARTIAL' : state === 'unavailable' ? 'UNSUPPORTED' : 'FAILED';
      if (state === 'limit') { warnings.push(`${r!.message ?? 'Image exceeds a safety limit.'} Some visual content could not be fully analyzed.`); v.limitsHit.push('Image size limit'); }
      else warnings.push(REASON[state] ?? REASON.engine);
      v.ocrWarnings.push(REASON[state] ?? REASON.engine);
      out.technicalDetails = `OCR error: ${String(r!.message ?? state).slice(0, 200)}`;
    }
    out.links = visualLinks([{ text: out.ocrText ?? '' }], qr);
    v.urlsDetected = countVisualUrls(out.links);
    v.sources = { directText: false, ocrText: !!out.ocrText, qr: qr.length > 0 };
    if (qr.some((q) => q.kind !== 'url')) warnings.push('A QR code with non-web content was found; its content is shown as text only and was not opened.');
    return out;
  }
};
