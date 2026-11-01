import { LIMITS } from '../limits';
import { ExtractionError, type QrCodeInfo } from '../types';
import { OcrError, ocrImage } from '../ocr';
import { sanitizeText } from '../sanitizer';
import { prepareImage, type RawPixels } from './imagePipeline';
import { decodeQrCodes } from './qr';

export type ImageState = 'ok' | 'timeout' | 'engine' | 'limit' | 'corrupt' | 'unavailable' | 'skipped';
export interface ImageVisualOutput {
  state: ImageState; message?: string; text: string; confidence: number | null; qr: QrCodeInfo[]; downscaled: boolean; upscaled: boolean; ocrMs: number; ocrRan: boolean; /** Some (not all) bands were read. */ partialBands?: boolean;
  sourceWidth: number; sourceHeight: number;
}
export interface AnalyzeOpts { location: string; ocr: boolean; qr: boolean; qrFirstIndex: number; deadline: number; ocrTimeoutMs?: number }

/** Bands overlap by a few lines, so the same line can be read twice: drop immediate repeats (harmless for detection, but noisy to read). */
export function dedupeOverlap(t: string): string {
  const out: string[] = []; const recent: string[] = [];
  for (const line of t.split('\n')) { const k = line.trim().toLowerCase(); if (k.length >= 8 && recent.includes(k)) continue; out.push(line); if (k) { recent.push(k); if (recent.length > 8) recent.shift(); } }
  return out.join('\n');
}
/** Cleans OCR output: strips control/bidi characters, trims, collapses runs of blank lines. */
export function cleanOcrText(t: string, max: number = LIMITS.MAX_OCR_TEXT): string {
  return sanitizeText(t, max).text.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

/**
 * Prepares ONE image safely, looks for QR codes, then (optionally) runs local OCR. Never throws: every failure is reported as a state so the
 * caller can degrade to PARTIAL/FAILED without crashing and without ever concluding SAFE from a failed read.
 */
export async function analyzeOneImage(src: Buffer | RawPixels, o: AnalyzeOpts): Promise<ImageVisualOutput> {
  const out: ImageVisualOutput = { state: 'ok', text: '', confidence: null, qr: [], downscaled: false, upscaled: false, ocrMs: 0, ocrRan: false, sourceWidth: 0, sourceHeight: 0 };
  let prep;
  try { prep = await prepareImage(src, { needOcr: o.ocr }); }
  catch (e) {
    const k = e instanceof ExtractionError ? e.kind : 'corrupt';
    out.state = k === 'limit' ? 'limit' : k === 'unsupported' ? 'unavailable' : 'corrupt'; out.message = (e as Error).message; return out;
  }
  out.downscaled = prep.downscaled; out.upscaled = prep.upscaled; out.sourceWidth = prep.sourceWidth; out.sourceHeight = prep.sourceHeight;
  if (o.qr) { try { out.qr = await decodeQrCodes(prep.qr, o.location, o.qrFirstIndex, LIMITS.MAX_QR_CODES, o.deadline); } catch { /* QR failure is not fatal */ } }
  if (o.ocr && prep.ocrBands.length) {
    const t0 = Date.now(); const parts: string[] = []; const confs: number[] = []; let done = 0;
    for (const band of prep.ocrBands) {
      const left = o.deadline - Date.now();
      if (left < 2_000) { out.state = 'timeout'; out.message = 'The OCR time budget was used up.'; break; }
      try {
        const r = await ocrImage(band, { timeoutMs: Math.min(o.ocrTimeoutMs ?? LIMITS.OCR_CALL_TIMEOUT_MS, left) });
        done++; if (r.text.trim()) parts.push(r.text); if (r.confidence !== null) confs.push(r.confidence);
      } catch (e) {
        out.state = e instanceof OcrError ? (e.kind === 'timeout' ? 'timeout' : e.kind === 'unavailable' ? 'unavailable' : 'engine') : 'engine';
        out.message = (e as Error).message; if (out.state === 'unavailable') break; // later bands are still tried after a timeout: partial text is better than none
      }
    }
    out.ocrRan = done > 0; out.partialBands = done > 0 && done < prep.ocrBands.length;
    out.text = dedupeOverlap(cleanOcrText(parts.join('\n')));
    out.confidence = confs.length ? confs.reduce((a, b) => a + b, 0) / confs.length : null;
    // A QR graphic read as "text" produces noise; drop it when a code was decoded and the text is short and unconfident.
    if (out.qr.length) {
      out.text = out.text.split('\n').filter((l) => l.trim().length >= 14 ? true : (l.replace(/[^\p{L}\p{N} ]/gu, '').length / Math.max(1, l.length)) >= 0.75 || l.trim() === '').join('\n').replace(/\n{3,}/g, '\n\n').trim();
      if ((out.confidence ?? 100) < 50 && (out.text.match(/[\p{L}\p{N}]/gu) ?? []).length < 60) out.text = '';
    }
    out.ocrMs = Date.now() - t0;
  }
  return out;
}
