import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { LIMITS } from './limits';

/* eslint-disable @typescript-eslint/no-explicit-any */
export type OcrFailure = 'timeout' | 'engine' | 'unavailable';
/** Thrown by ocrImage. `kind` lets callers report a precise, non-technical reason. */
export class OcrError extends Error { constructor(msg: string, readonly kind: OcrFailure) { super(msg); this.name = 'OcrError'; } }

export const OCR_LANGUAGE = 'eng';
let modelDir = path.join(os.tmpdir(), 'safepeek-ocr-model');
/** Where the bundled language model is staged for the OCR engine (the main process points this at the app's user-data folder). */
export function configureOcr(o: { modelDir?: string }) { if (o.modelDir) modelDir = o.modelDir; }
/** Stages the bundled model (a verified copy of the file shipped inside the app) in a plain directory the engine can read with ordinary file access. */
function stageModel(): string {
  const src = path.join(langDir(), `${OCR_LANGUAGE}.traineddata.gz`);
  const dst = path.join(modelDir, `${OCR_LANGUAGE}.traineddata`); // gzip content is detected and unpacked by the engine
  const want = fs.statSync(src).size;
  try { if (fs.statSync(dst).size === want) return modelDir; } catch { /* stage below */ }
  fs.mkdirSync(modelDir, { recursive: true });
  const tmp = `${dst}.${process.pid}.tmp`; fs.copyFileSync(src, tmp); fs.renameSync(tmp, dst);
  return modelDir;
}
interface Live { w: any; dead: boolean }
let workerP: Promise<Live> | null = null;
let idle: NodeJS.Timeout | null = null;
let current: { reject: (e: Error) => void } | null = null;
let chain: Promise<unknown> = Promise.resolve();

function langDir(): string {
  const base = path.join(path.dirname(require.resolve('@tesseract.js-data/eng/package.json')), '4.0.0_best_int');
  return base.replace('app.asar' + path.sep, 'app.asar.unpacked' + path.sep); // packaged builds unpack OCR assets
}

function onWorkerDead(live: Live, why: string) {
  live.dead = true;
  const c = current; current = null; c?.reject(new OcrError(`OCR worker stopped (${why})`, 'engine'));
}

function startWorker(): Promise<Live> {
  return (async () => {
    let createWorker: any;
    try { ({ createWorker } = require('tesseract.js')); } catch (e) { throw new OcrError(`OCR engine could not be loaded: ${(e as Error).message}`, 'unavailable'); }
    // Local OCR only: the English model ships inside the app (@tesseract.js-data/eng); nothing is downloaded and the image is never uploaded.
    // The model is staged in a plain directory and read through the engine's read-only cache, NOT through langPath. Inside Electron,
    // tesseract.js misdetects its environment and treats a local langPath as a web address to download; that fails ("Only absolute URLs are
    // supported") and the worker never finishes starting, which surfaced as "Extraction timed out" for every image in the installed app.
    let cacheDir: string;
    try { cacheDir = stageModel(); } catch (e) { throw new OcrError(`OCR language data could not be prepared: ${(e as Error).message}`, 'unavailable'); }
    let fail: (e: Error) => void = () => undefined;
    const startupError = new Promise<never>((_, rej) => { fail = rej; });
    const guardTimer = setTimeout(() => fail(new OcrError('OCR engine did not start in time', 'engine')), LIMITS.OCR_START_TIMEOUT_MS); guardTimer.unref?.();
    let w: any;
    try {
      w = await Promise.race([
        createWorker(OCR_LANGUAGE, 1, { cachePath: cacheDir, cacheMethod: 'readOnly', gzip: false, logger: () => undefined, errorHandler: (e: unknown) => fail(new OcrError(`OCR engine error: ${String(e).slice(0, 160)}`, 'engine')) }),
        startupError
      ]);
    } catch (e) { clearTimeout(guardTimer); throw e instanceof OcrError ? e : new OcrError(String((e as Error)?.message ?? e), 'engine'); }
    clearTimeout(guardTimer);
    try { await w.setParameters({ user_defined_dpi: '300' }); } catch { /* optional tuning */ }
    const live: Live = { w, dead: false };
    // A crashed/killed worker thread never answers: without these listeners the pending recognize() would hang until a timeout.
    try { w.worker?.on?.('error', (e: Error) => onWorkerDead(live, e?.message ?? 'error')); w.worker?.on?.('exit', (code: number) => { if (!live.dead && code !== 0) onWorkerDead(live, `exit ${code}`); }); } catch { /* listener support is best-effort */ }
    return live;
  })();
}

async function recognizeOnce(buf: Buffer, timeoutMs: number): Promise<{ text: string; confidence: number | null }> {
  if (idle) { clearTimeout(idle); idle = null; }
  workerP ??= startWorker();
  let live: Live;
  try { live = await workerP; } catch (e) { workerP = null; throw e instanceof OcrError ? e : new OcrError(String((e as Error)?.message ?? e), 'engine'); }
  let timer: NodeJS.Timeout | undefined;
  try {
    const guard = new Promise<never>((_, rej) => {
      current = { reject: rej };
      timer = setTimeout(() => rej(new OcrError(`OCR exceeded ${Math.round(timeoutMs / 1000)} s`, 'timeout')), timeoutMs);
      timer.unref?.();
    });
    // Only the text is requested: hOCR/TSV/block output is never used and is expensive on large pages.
    const r: any = await Promise.race([live.w.recognize(buf, {}, { text: true }), guard]);
    return { text: String(r.data?.text ?? ''), confidence: typeof r.data?.confidence === 'number' ? r.data.confidence : null };
  } catch (e) {
    // After a timeout or crash the worker may still be busy: terminate it so the NEXT image starts clean instead of queueing behind this one.
    await shutdownOcr();
    if (e instanceof OcrError) throw e;
    throw new OcrError(String((e as Error)?.message ?? e), 'engine');
  } finally {
    if (timer) clearTimeout(timer); current = null;
    if (workerP !== null) { idle = setTimeout(() => { shutdownOcr().catch(() => undefined); }, 60_000); idle.unref?.(); }
  }
}

/** Serialized, bounded local OCR. The caller should already have downscaled the image (see visual/imagePipeline). */
export function ocrImage(buf: Buffer, opts: { timeoutMs?: number } = {}): Promise<{ text: string; confidence: number | null }> {
  const timeoutMs = Math.max(1_000, opts.timeoutMs ?? LIMITS.OCR_CALL_TIMEOUT_MS);
  const run = chain.then(() => recognizeOnce(buf, timeoutMs));
  chain = run.catch(() => undefined);
  return run;
}

export async function shutdownOcr(): Promise<void> {
  if (idle) { clearTimeout(idle); idle = null; }
  const p = workerP; workerP = null;
  if (p) { try { const l = await p; l.dead = true; await l.w.terminate(); } catch { /* ignore */ } }
}
