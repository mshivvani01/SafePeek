import fs from 'node:fs';
import type { ContentExtractor, ExtractOutput, LinkInfo } from './types';
import { ExtractionError } from './types';
import { LIMITS } from './limits';
import { cleanInline, safeLinkUrl } from './sanitizer';
import { extractUrls } from '../analysis/urls';
import { alnumCount, analyzePdfVisual } from './visual/pdfVisual';
import { sha256Hex } from './visual/ocrCache';
import { cleanOcrText } from './visual/imageAnalyzer';
import { countVisualUrls, visualLinks } from './visual/visualResult';

/* eslint-disable @typescript-eslint/no-explicit-any */
let pdfjsCache: any;
function pdfjs(): any {
  // Legacy CommonJS build of pdf.js (3.x). Used ONLY for text/annotation/metadata parsing: no canvas rendering, no scripting (enableScripting is never set), no external navigation.
  return (pdfjsCache ??= require('pdfjs-dist/legacy/build/pdf.js'));
}

export const pdfExtractor: ContentExtractor = {
  id: 'pdf',
  canHandle: (c) => c.typeId === 'pdf',
  async extract(ctx): Promise<ExtractOutput> {
    if (ctx.size > LIMITS.MAX_FILE_SIZE) throw new ExtractionError(`PDF larger than ${LIMITS.MAX_FILE_SIZE / 1048576} MB; content not extracted.`, 'limit');
    const fileBuf = await fs.promises.readFile(ctx.path);
    const sha = sha256Hex(fileBuf);
    const data = new Uint8Array(fileBuf);
    let doc: any;
    try {
      doc = await pdfjs().getDocument({ data, isEvalSupported: false, disableFontFace: true, useSystemFonts: false, enableXfa: false, verbosity: 0, disableAutoFetch: true, disableStream: true, maxImageSize: LIMITS.PDF_MAX_IMAGE_PIXELS }).promise;
    } catch (e) {
      const n = (e as Error).name;
      if (n === 'PasswordException') throw new ExtractionError('Encrypted document (password required)', 'encrypted');
      throw new ExtractionError(`PDF could not be parsed (${n || 'error'}): ${cleanInline((e as Error).message, 120)}`, 'corrupt');
    }
    const warnings: string[] = [];
    try {
      const total: number = doc.numPages;
      const limit = Math.min(total, LIMITS.MAX_PDF_PAGES);
      const pages: { number: number; text: string }[] = [];
      const links: LinkInfo[] = [];
      let failedPages = 0;
      for (let i = 1; i <= limit; i++) {
        try {
          const page = await doc.getPage(i);
          const tc = await page.getTextContent();
          let t = '';
          for (const it of tc.items as any[]) { t += it.str ?? ''; if (it.hasEOL) t += '\n'; }
          pages.push({ number: i, text: t.slice(0, LIMITS.MAX_PDF_PAGE_CHARS).trim() });
          for (const a of (await page.getAnnotations()) as any[]) {
            const u = a.subtype === 'Link' ? safeLinkUrl(String(a.url ?? a.unsafeUrl ?? '')) : null;
            if (u && links.length < LIMITS.MAX_LINKS) links.push({ url: u, source: `page ${i} link` });
          }
          page.cleanup();
        } catch { failedPages++; pages.push({ number: i, text: '' }); }
      }
      if (failedPages) warnings.push(`${failedPages} page(s) could not be read.`);
      const props: Record<string, string> = {};
      try {
        const md = await doc.getMetadata();
        for (const k of ['Title', 'Author', 'Subject', 'Creator', 'Producer', 'CreationDate']) { const v = md?.info?.[k]; if (typeof v === 'string' && v.trim()) props[k] = cleanInline(v, 200); }
      } catch { /* metadata is optional */ }
      const text = pages.map((p) => p.text).join('\n\n');
      for (const u of extractUrls(text, LIMITS.MAX_LINKS)) if (!links.some((l) => l.url === u)) links.push({ url: u, source: 'text' });
      const truncated = total > limit;
      if (truncated) warnings.push(`PDF has ${total} pages; only the first ${limit} were extracted.`);
      if (fileBuf.length !== ctx.size || (ctx.analysis?.sha256 && ctx.analysis.sha256 !== sha)) { warnings.push('The file changed after it was first analyzed, so these results may be out of date. Re-run the analysis.'); failedPages++; }

      // ---- Phase 8: visual content. Direct text stays authoritative; OCR is added only for pages that have no usable text layer. ----
      let vr: Awaited<ReturnType<typeof analyzePdfVisual>> | null = null; let visualFailed = false;
      try { vr = await analyzePdfVisual(doc, pdfjs().OPS, pages.map((p) => ({ number: p.number, text: p.text })), { sha, cacheDir: ctx.visualCacheDir, budget: ctx.budget }); }
      catch (e) { visualFailed = true; warnings.push('Images in this PDF could not be analyzed, so some visual content may be missing.'); void e; }
      const ocrByPage = new Map((vr?.ocrPages ?? []).map((p) => [p.page, cleanOcrText(p.text, LIMITS.MAX_PDF_PAGE_CHARS)]));
      const outPages = pages.map((p) => { const o = ocrByPage.get(p.number); return o ? { number: p.number, text: p.text ? `${p.text}\n\n${o}` : o, source: (p.text ? 'text+ocr' : 'ocr') as 'text+ocr' | 'ocr' } : { ...p, source: 'text' as const }; });
      const ocrText = [...ocrByPage.entries()].sort((a, b) => a[0] - b[0]).map(([, t]) => t).filter(Boolean).join('\n\n').slice(0, LIMITS.MAX_OCR_TEXT);
      const visual = vr?.visual;
      if (visual) {
        visual.sources = { directText: alnumCount(text) >= LIMITS.PDF_PAGE_TEXT_MIN_ALNUM, ocrText: !!ocrText, qr: visual.qrCodes.length > 0 };
        for (const l of visualLinks([...ocrByPage.entries()].map(([n, t]) => ({ text: t, where: `page ${n}` })), visual.qrCodes)) if (!links.some((x) => x.url === l.url)) links.push(l);
        visual.urlsDetected = countVisualUrls(links);
        if (visual.ocrPages.length) warnings.push(`${visual.ocrPages.length} page${visual.ocrPages.length === 1 ? '' : 's'} had no readable text layer and ${visual.ocrPages.length === 1 ? 'was' : 'were'} read with local OCR (page${visual.ocrPages.length === 1 ? '' : 's'} ${visual.ocrPages.join(', ')}).`);
        if (visual.limitsHit.length) warnings.push(`Some visual content could not be fully analyzed: ${[...new Set(visual.limitsHit)].join('; ')}.`);
        for (const w of vr!.warnings.slice(0, 4)) warnings.push(w);
        if (visual.qrCodes.some((q) => q.kind !== 'url')) warnings.push('A QR code with non-web content was found; its content is shown as text only and was not opened.');
        if (visual.downscaled) warnings.push('Large scanned images were reduced in size before OCR.');
        if (visual.ocrStatus === 'FAILED' || visual.ocrStatus === 'PARTIAL') warnings.push('Some visual content could not be fully analyzed.');
      }
      const anyText = !!text.trim() || !!ocrText.trim();
      if (!anyText && !(visual?.qrCodes.length)) warnings.push(visual && visual.imagesAnalyzed > 0 ? 'OCR found no readable text in the images of this PDF.' : `No text layer was found and SafePeek found no readable page images${vr?.unreadablePages.length ? ` on ${vr.unreadablePages.length} page(s)` : ''}. The pages may be blank or drawn as vector graphics, which SafePeek cannot read.`);
      const a = ctx.analysis?.pdf;
      const ocrOk = !vr || (!vr.incomplete && visual?.ocrStatus !== 'FAILED' && visual?.ocrStatus !== 'PARTIAL');
      return {
        extractedText: text, pages: outPages, pageCount: total, links, properties: props, truncated, warnings, visual,
        ...(ocrText ? { ocrText, ocrConfidence: visual?.ocrConfidence ?? null } : {}),
        truncationNote: truncated ? `Showing first ${limit} of ${total} pages` : undefined,
        embeddedContentWarning: !!a && (a.hasJavaScript || a.hasLaunchAction || a.hasOpenAction || a.embeddedFileCount > 0),
        status: failedPages || truncated || !anyText && !(visual?.qrCodes.length) || visualFailed || !ocrOk ? 'PARTIAL' : 'COMPLETED'
      };
    } finally { try { await doc.destroy(); } catch { /* ignore */ } }
  }
};
