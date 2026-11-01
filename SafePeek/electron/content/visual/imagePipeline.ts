import { LIMITS } from '../limits';
import { ExtractionError } from '../types';

/* eslint-disable @typescript-eslint/no-explicit-any */
let sharpMod: any | null | undefined;
/** Lazy: if the native image engine cannot load (e.g. a damaged install), visual analysis degrades to UNSUPPORTED instead of breaking the app. */
export function getSharp(): any | null {
  if (sharpMod !== undefined) return sharpMod;
  try {
    const m = require('sharp'); const s = m.default ?? m;
    try { s.cache({ memory: 64, files: 0, items: 24 }); s.concurrency(2); } catch { /* tuning is optional */ }
    sharpMod = s;
  } catch { sharpMod = null; }
  return sharpMod;
}

export interface RawPixels { data: Buffer; width: number; height: number; channels: 1 | 2 | 3 | 4 }
export interface PreparedImage {
  /** Grayscale, contrast-normalized PNG at a bounded size: the only thing the OCR engine ever sees. null when OCR was not requested. */
  ocrPng: Buffer | null;
  /** The OCR image cut into horizontal bands (a single element for small images). Dense pages are read band by band so one slow band cannot cost the whole page. */
  ocrBands: Buffer[];
  /** RGBA pixels at a bounded size for QR search. */
  qr: { data: Uint8ClampedArray; width: number; height: number };
  sourceWidth: number; sourceHeight: number; workWidth: number; workHeight: number; downscaled: boolean; upscaled: boolean; inverted: boolean;
}

const clampDim = (n: number) => Math.max(1, Math.round(n));

/**
 * Safe preprocessing for ONE image (a file, or an image embedded in a PDF page):
 *   decode once (bounded pixels) -> apply EXIF orientation -> flatten transparency -> downsample (or enlarge tiny images)
 *   -> grayscale + contrast normalize (+ invert light-on-dark) -> PNG for OCR; RGBA copy for QR search.
 * Nothing in the image is interpreted beyond its pixels (no metadata is executed, no external references are followed).
 */
export async function prepareImage(src: Buffer | RawPixels, opts: { needOcr: boolean }): Promise<PreparedImage> {
  const sharp = getSharp();
  if (!sharp) throw new ExtractionError('The local image engine is not available.', 'unsupported');
  const isRaw = !Buffer.isBuffer(src);
  const input = (): any => isRaw
    ? sharp((src as RawPixels).data, { raw: { width: (src as RawPixels).width, height: (src as RawPixels).height, channels: (src as RawPixels).channels }, limitInputPixels: LIMITS.MAX_IMAGE_PIXELS })
    : sharp(src as Buffer, { limitInputPixels: LIMITS.MAX_IMAGE_PIXELS, failOn: 'error', animated: false });
  try {
    const meta = await input().metadata();
    let w: number = meta.width ?? 0; let h: number = meta.height ?? 0;
    if (!w || !h) throw new ExtractionError('Image dimensions could not be read.', 'corrupt');
    if (meta.orientation && meta.orientation >= 5) [w, h] = [h, w];
    if (w * h > LIMITS.MAX_IMAGE_PIXELS || Math.max(w, h) > LIMITS.MAX_IMAGE_SIDE) throw new ExtractionError(`Image has ${(w * h / 1e6).toFixed(0)} megapixels (limit ${LIMITS.MAX_IMAGE_PIXELS / 1e6}); OCR skipped.`, 'limit');

    const longest = Math.max(w, h);
    let scale = Math.min(1, LIMITS.OCR_WORK_MAX_SIDE / longest, Math.sqrt(LIMITS.OCR_WORK_MAX_PIXELS / (w * h)));
    let upscaled = false;
    if (longest < LIMITS.OCR_MIN_SIDE_UPSCALE) { scale = Math.min(3, LIMITS.OCR_MIN_SIDE_UPSCALE * 2 / longest); upscaled = scale > 1; }
    const downscaled = scale < 1;
    const tw = clampDim(w * scale), th = clampDim(h * scale);

    // Stage 1: the ONLY full-size decode. Output is already bounded, so everything after this is cheap.
    const base = await input().rotate().flatten({ background: '#ffffff' }).removeAlpha().resize({ width: tw, height: th, fit: 'fill', kernel: 'lanczos3' }).raw().toBuffer({ resolveWithObject: true });
    const baseRaw = { raw: { width: base.info.width, height: base.info.height, channels: base.info.channels as 3 } };

    // QR copy (RGBA, possibly smaller than the OCR copy).
    const qrScale = Math.min(1, LIMITS.QR_WORK_MAX_SIDE / Math.max(base.info.width, base.info.height));
    let qrPipe = sharp(base.data, baseRaw);
    if (qrScale < 1) qrPipe = qrPipe.resize({ width: clampDim(base.info.width * qrScale), height: clampDim(base.info.height * qrScale), fit: 'fill', kernel: 'lanczos3' });
    const qrOut = await qrPipe.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    const qr = { data: new Uint8ClampedArray(qrOut.data.buffer, qrOut.data.byteOffset, qrOut.data.byteLength), width: qrOut.info.width, height: qrOut.info.height };

    let ocrPng: Buffer | null = null; let inverted = false; let ocrBands: Buffer[] = [];
    if (opts.needOcr) {
      const gray = await sharp(base.data, baseRaw).grayscale().raw().toBuffer({ resolveWithObject: true });
      let sum = 0; for (let i = 0; i < gray.data.length; i += 7) sum += gray.data[i]; // sampled mean luminance
      inverted = sum / Math.ceil(gray.data.length / 7) < 100;
      let p = sharp(gray.data, { raw: { width: gray.info.width, height: gray.info.height, channels: 1 } });
      if (inverted) p = p.negate({ alpha: false });
      const full: Buffer = await p.normalise().png({ compressionLevel: 1 }).toBuffer(); ocrPng = full;
      const gw = gray.info.width, gh = gray.info.height;
      if (gw * gh <= LIMITS.OCR_BAND_MIN_PIXELS) ocrBands = [full];
      else {
        const bandH = Math.max(400, Math.min(LIMITS.OCR_BAND_HEIGHT, gh)); const overlap = 70;
        for (let top = 0; top < gh && ocrBands.length < LIMITS.OCR_MAX_BANDS; top += bandH - overlap) {
          const height = Math.min(bandH, gh - top); if (height < 60) break;
          ocrBands.push(await sharp(full).extract({ left: 0, top, width: gw, height }).png({ compressionLevel: 1 }).toBuffer());
          if (top + height >= gh) break;
        }
      }
    }
    return { ocrPng, ocrBands, qr, sourceWidth: w, sourceHeight: h, workWidth: base.info.width, workHeight: base.info.height, downscaled, upscaled, inverted };
  } catch (e) {
    if (e instanceof ExtractionError) throw e;
    const m = String((e as Error)?.message ?? e);
    if (/pixel limit|exceeds/i.test(m)) throw new ExtractionError(`Image is larger than the safety limit (${LIMITS.MAX_IMAGE_PIXELS / 1e6} megapixels); OCR skipped.`, 'limit');
    throw new ExtractionError(`Image could not be decoded: ${m.slice(0, 120)}`, 'corrupt');
  }
}

/** Inert preview: a small re-encoded JPEG. Used when the original is too big to embed. Re-encoding also drops all metadata. */
export async function makeThumbnailDataUrl(buf: Buffer, maxSide = 1280): Promise<string | undefined> {
  const sharp = getSharp(); if (!sharp) return undefined;
  try {
    const out: Buffer = await sharp(buf, { limitInputPixels: LIMITS.MAX_IMAGE_PIXELS, failOn: 'error' }).rotate().flatten({ background: '#ffffff' }).resize({ width: maxSide, height: maxSide, fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 72 }).toBuffer();
    return `data:image/jpeg;base64,${out.toString('base64')}`;
  } catch { return undefined; }
}
