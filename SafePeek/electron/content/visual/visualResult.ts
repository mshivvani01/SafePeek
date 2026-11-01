import { extractVisualUrls } from '../../analysis/urls';
import { LIMITS } from '../limits';
import { OCR_LANGUAGE } from '../ocr';
import type { LinkInfo, QrCodeInfo, VisualAnalysis } from '../types';
import { urlKey } from '../../analysis/urls';

export const emptyVisual = (): VisualAnalysis => ({
  version: 1, ocrStatus: 'NOT_ATTEMPTED', ocrLanguage: OCR_LANGUAGE, ocrDurationMs: 0, ocrConfidence: null, ocrWarnings: [], imagesAnalyzed: 0, ocrImageCount: 0, ocrPages: [],
  qrCodes: [], urlsDetected: 0, downscaled: false, limitsHit: [], cacheHit: false, sources: { directText: false, ocrText: false, qr: false }
});

/** Links derived from the visual channels. QR links come first so that, if the same address appears twice, it is attributed to the QR code. */
export function visualLinks(ocrChunks: { text: string; where?: string }[], qr: QrCodeInfo[]): LinkInfo[] {
  const out: LinkInfo[] = []; const seen = new Set<string>();
  const push = (url: string, source: string) => { const k = urlKey(url); if (seen.has(k) || out.length >= LIMITS.MAX_LINKS) return; seen.add(k); out.push({ url, source }); };
  for (const q of qr) if (q.kind === 'url' && q.url) push(q.url, `QR code${q.location !== 'image' ? ` (${q.location})` : ''}${q.schemeAssumed ? ', scheme assumed' : ''}`);
  for (const c of ocrChunks) for (const u of extractVisualUrls(c.text, LIMITS.MAX_LINKS)) push(u.url, `OCR text${c.where ? ` (${c.where})` : ''}${u.assumed ? ', scheme assumed' : ''}`);
  return out;
}
export const countVisualUrls = (links: LinkInfo[]) => links.filter((l) => /^(QR code|OCR text)/.test(l.source)).length;
