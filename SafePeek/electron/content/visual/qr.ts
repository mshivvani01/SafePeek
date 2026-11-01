import { LIMITS } from '../limits';
import type { QrCodeInfo, QrKind } from '../types';

/* eslint-disable @typescript-eslint/no-explicit-any */
let jsQRfn: ((d: Uint8ClampedArray, w: number, h: number, o?: any) => any) | null | undefined;
function jsqr() { if (jsQRfn === undefined) { try { const m = require('jsqr'); jsQRfn = m.default ?? m; } catch { jsQRfn = null; } } return jsQRfn; }
export const qrAvailable = () => jsqr() !== null;

const CTRL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g;
const DANGEROUS_SCHEMES = new Set(['javascript', 'vbscript', 'data', 'file', 'ms-msdt', 'search-ms', 'ms-officecmd', 'smb']);
export { DANGEROUS_SCHEMES };

/** Classifies a decoded payload. Nothing here opens, resolves or launches anything: the payload is only text. */
export function classifyPayload(raw: string, index: number, location: string): QrCodeInfo {
  const cleaned = raw.replace(CTRL, ' ').trim();
  const truncated = cleaned.length > LIMITS.MAX_QR_PAYLOAD_CHARS;
  const payload = cleaned.slice(0, LIMITS.MAX_QR_PAYLOAD_CHARS);
  const base = { index, payload, location, truncated };
  const scheme = /^([a-z][a-z0-9+.-]{1,24}):(?=\S)/i.exec(payload)?.[1].toLowerCase();
  if (scheme === 'http' || scheme === 'https') return { ...base, kind: 'url', scheme, url: payload.split(/\s/)[0] };
  if (scheme === 'mailto') return { ...base, kind: 'email', scheme };
  if (scheme === 'tel') return { ...base, kind: 'phone', scheme };
  if (scheme === 'sms' || scheme === 'smsto' || scheme === 'mms') return { ...base, kind: 'sms', scheme };
  if (scheme === 'wifi') return { ...base, kind: 'wifi', scheme };
  if (scheme) return { ...base, kind: 'other-scheme', scheme };
  // "example.com/verify" (no scheme): treat as a web address, flagged so the UI/engine know the scheme was assumed.
  if (/^(?:www\.)?[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+(?::\d{1,5})?(?:[/?#]\S*)?$/i.test(payload) && /\.[a-z]{2,24}(?::\d+)?(?:[/?#]|$)/i.test(payload)) return { ...base, kind: 'url', url: `https://${payload}`, schemeAssumed: true };
  return { ...base, kind: 'text' };
}
export const isWebKind = (k: QrKind) => k === 'url';

const yieldLoop = () => new Promise<void>((r) => setImmediate(r));

/**
 * Finds up to `max` QR codes in one RGBA bitmap. jsQR returns one code per call, so each found code is painted white and the search repeats.
 * Pure computation on pixels; a failed or garbled code is simply not reported.
 */
export async function decodeQrCodes(px: { data: Uint8ClampedArray; width: number; height: number }, location: string, firstIndex: number, max = LIMITS.MAX_QR_CODES, deadline = Infinity): Promise<QrCodeInfo[]> {
  const fn = jsqr(); if (!fn) return [];
  const out: QrCodeInfo[] = []; const seen = new Set<string>();
  const add = (text: string) => { if (!text.trim() || seen.has(text) || out.length >= max) return; seen.add(text); out.push(classifyPayload(text, firstIndex + out.length, location)); };

  /** Repeatedly decodes one window of the bitmap, painting each decoded code white so the next call finds the next one. */
  const scan = async (x0w: number, y0w: number, w: number, h: number) => {
    const win = new Uint8ClampedArray(w * h * 4);
    for (let y = 0; y < h; y++) win.set(px.data.subarray(((y0w + y) * px.width + x0w) * 4, ((y0w + y) * px.width + x0w + w) * 4), y * w * 4);
    let found = 0;
    while (out.length < max && Date.now() < deadline) {
      let r: any;
      try { r = fn(win, w, h, { inversionAttempts: 'attemptBoth' }); } catch { break; }
      if (!r) break;
      const L = r.location; const xs = [L.topLeftCorner.x, L.topRightCorner.x, L.bottomLeftCorner.x, L.bottomRightCorner.x]; const ys = [L.topLeftCorner.y, L.topRightCorner.y, L.bottomLeftCorner.y, L.bottomRightCorner.y];
      const pad = 6; const bx0 = Math.max(0, Math.floor(Math.min(...xs)) - pad), bx1 = Math.min(w - 1, Math.ceil(Math.max(...xs)) + pad), by0 = Math.max(0, Math.floor(Math.min(...ys)) - pad), by1 = Math.min(h - 1, Math.ceil(Math.max(...ys)) + pad);
      for (let y = by0; y <= by1; y++) { const row = y * w * 4; for (let x = bx0; x <= bx1; x++) { const i = row + x * 4; win[i] = win[i + 1] = win[i + 2] = 255; win[i + 3] = 255; } }
      found++; add(typeof r.data === 'string' ? r.data : ''); await yieldLoop();
    }
    return found;
  };

  const full = await scan(0, 0, px.width, px.height);
  // jsQR gets confused when finder patterns of several codes are in view and then returns nothing: look at overlapping tiles instead.
  if (full === 0 && out.length < max && Date.now() < deadline && Math.min(px.width, px.height) >= 240) {
    const grids: [number, number, number, number][] = [[0.65, 0.65, 2, 2], [0.45, 0.8, 3, 2]]; // [tile w, tile h, columns, rows] as fractions of the bitmap
    for (const [fw, fh, cols, rows] of grids) {
      const tw = Math.ceil(px.width * fw), th = Math.ceil(px.height * fh);
      for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
        if (Date.now() >= deadline || out.length >= max) break;
        await scan(cols === 1 ? 0 : Math.round(c * (px.width - tw) / (cols - 1)), rows === 1 ? 0 : Math.round(r * (px.height - th) / (rows - 1)), tw, th);
      }
    }
  }
  return out;
}
