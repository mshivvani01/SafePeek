import type { ContentResult, ExtractContext, ExtractorType, PreviewType } from './types';

const BY_EXTRACTOR: Record<ExtractorType, PreviewType> = { pdf: 'pdf', docx: 'document', xlsx: 'spreadsheet', pptx: 'presentation', image: 'image', text: 'text', archive: 'archive', none: 'unsupported' };

/** Picks the safe preview mode. Previews are always data (text, tables, <img> of the image bytes, an entry list): never rendered active content. */
export function choosePreview(ctx: ExtractContext, extractor: ExtractorType, r: Partial<ContentResult>): { previewType: PreviewType; previewAvailable: boolean } {
  const cat = ctx.analysis?.identity.category;
  if (extractor === 'none' || cat === 'executable') return { previewType: 'unsupported', previewAvailable: false };
  const type = BY_EXTRACTOR[extractor];
  const has = (type === 'pdf' && !!r.pages?.length) || (type === 'document' && !!(r.sections?.length)) || (type === 'spreadsheet' && !!r.sheets?.length) ||
    (type === 'presentation' && !!r.slides?.length) || (type === 'image' && !!r.image) || (type === 'text' && !!r.extractedText?.length) || (type === 'archive' && !!r.archiveEntries);
  return { previewType: has ? type : 'unsupported', previewAvailable: has };
}

export function unsupportedMessage(ctx: ExtractContext): string {
  const a = ctx.analysis; const t = a?.identity.detectedType ?? 'unknown file';
  switch (a?.identity.category) {
    case 'executable': return `This is an executable file (${t}). SafePeek will not execute this file and does not render it as a document. Static file information is shown instead.`;
    case 'archive': return `Archive type detected (${t}). Content preview unavailable: SafePeek only lists ZIP archives.`;
    default: return a?.identity.detectedTypeId === 'ole2' ? 'Legacy Office (OLE2) and encrypted Office files are identified but their content is not extracted in this version.' : `Safe Preview is not available for this file type (${t}).`;
  }
}
