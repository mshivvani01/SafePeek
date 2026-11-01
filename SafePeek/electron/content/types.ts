import type { AnalysisResult } from '../analysis/types';
// NOTE: mirrored by src/types/content.ts (renderer cannot import from electron/).
export type ContentStatus = 'NOT_STARTED' | 'QUEUED' | 'ANALYZING' | 'COMPLETED' | 'PARTIAL' | 'UNSUPPORTED' | 'FAILED';
export type ExtractorType = 'pdf' | 'docx' | 'xlsx' | 'pptx' | 'image' | 'text' | 'archive' | 'none';
export type PreviewType = 'pdf' | 'document' | 'spreadsheet' | 'presentation' | 'image' | 'text' | 'archive' | 'unsupported';

export interface PageText { number: number; text: string; /** Where this page's text came from (Phase 8). Absent = direct text. */ source?: 'text' | 'ocr' | 'text+ocr' }
export interface Section { level: number; kind: 'heading' | 'paragraph' | 'table'; text: string; tableIndex?: number }
export interface TableData { name?: string; rows: string[][]; truncated: boolean }
export interface SheetData { name: string; range: string; rows: string[][]; rowCount: number; truncated: boolean }
export interface SlideData { number: number; title: string; text: string; notes?: string }
export interface LinkInfo { url: string; text?: string; source: string }
/** Phase 8. OCR_STATUS semantics: COMPLETED = every attempted OCR finished; PARTIAL = some visual content was skipped or hit a limit; FAILED = OCR was attempted and did not work; UNSUPPORTED = it cannot be done for this file/engine; NOT_ATTEMPTED = nothing needed OCR. */
export type OcrStatus = 'NOT_ATTEMPTED' | 'COMPLETED' | 'PARTIAL' | 'FAILED' | 'UNSUPPORTED';
export type QrKind = 'url' | 'email' | 'phone' | 'sms' | 'wifi' | 'text' | 'other-scheme';
/** A decoded QR payload. UNTRUSTED text: only ever displayed or analyzed, never opened, executed or launched. */
export interface QrCodeInfo { index: number; payload: string; kind: QrKind; scheme?: string; location: string; /** http(s) URL to analyze, when the payload is (or looks like) a web address. */ url?: string; schemeAssumed?: boolean; truncated: boolean }
export type PdfVisualKind = 'TEXT' | 'IMAGE_ONLY' | 'MIXED' | 'EMPTY';
export interface VisualAnalysis {
  version: 1; ocrStatus: OcrStatus; ocrLanguage: string; ocrDurationMs: number; ocrConfidence: number | null; ocrWarnings: string[];
  imagesAnalyzed: number; ocrImageCount: number; /** PDF page numbers that were read with OCR. */ ocrPages: number[]; pdfKind?: PdfVisualKind;
  qrCodes: QrCodeInfo[]; /** URLs that came from OCR text or QR codes. */ urlsDetected: number;
  downscaled: boolean; /** Human-readable limits that were reached (empty = none). */ limitsHit: string[]; cacheHit: boolean;
  sources: { directText: boolean; ocrText: boolean; qr: boolean };
}
export interface ImageInfo { width: number | null; height: number | null; size: number; format: string; dataUrl?: string; previewOmittedReason?: string }
export interface ArchiveViewEntry { path: string; name: string; depth: number; isDirectory: boolean; size: number; encrypted: boolean; dangerous: boolean; unsafePath: boolean; inspectable: boolean }
export interface Entities { organizations: string[]; people: string[]; amounts: string[]; dates: string[]; emails: string[]; phones: string[] }
export interface ContentSummary {
  documentType: string; title: string | null; description: string; pageCount: number | null; textLength: number; entities: Entities; keySections: string[];
}
export interface ContentResult {
  version: 1; status: ContentStatus; extractorType: ExtractorType; fileName: string;
  extractedText?: string; textLength: number; pageCount?: number; pages?: PageText[]; sections?: Section[]; tables?: TableData[]; sheets?: SheetData[]; slides?: SlideData[];
  links: LinkInfo[]; images?: { name: string; size: number }[]; image?: ImageInfo; archiveEntries?: ArchiveViewEntry[]; archiveFormat?: string;
  ocrText?: string; ocrConfidence?: number | null; /** Phase 8: OCR / QR / visual-content details. */ visual?: VisualAnalysis; properties?: Record<string, string>;
  summary: ContentSummary; previewType: PreviewType; previewAvailable: boolean; unsupportedReason?: string;
  embeddedContentWarning: boolean; extractionWarnings: string[]; technicalDetails?: string; truncated: boolean; truncationNote?: string;
  startedAt: string; analyzedAt: string; executionPerformed: false; uploaded: false;
}
export interface ExtractBudget { /** Extends the extraction timeout (used by PDF OCR, which runs after text extraction under its own bounded budget). */ extend(ms: number): void; /** Milliseconds left before the extraction timeout fires. */ remaining(): number }
export interface ExtractContext { path: string; name: string; size: number; typeId: string; officeFormat?: string; analysis: AnalysisResult | undefined; /** Phase 8: directory for the SHA-256-keyed OCR cache (omit to disable caching). */ visualCacheDir?: string; budget?: ExtractBudget }
/** A partial result an extractor returns; the pipeline fills defaults, sanitizes, summarizes and picks the preview. */
export type ExtractOutput = Partial<ContentResult> & { warnings?: string[] };
export interface ContentExtractor { readonly id: ExtractorType; canHandle(ctx: ExtractContext): boolean; extract(ctx: ExtractContext): Promise<ExtractOutput> }
export class ExtractionError extends Error { constructor(msg: string, readonly kind: 'encrypted' | 'corrupt' | 'unsupported' | 'limit' = 'corrupt') { super(msg); } }
