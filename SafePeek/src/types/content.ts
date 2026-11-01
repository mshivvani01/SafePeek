// Mirrors the renderer-facing part of electron/content/types.ts (renderer cannot import from electron/).
export type ContentStatus = 'NOT_STARTED' | 'QUEUED' | 'ANALYZING' | 'COMPLETED' | 'PARTIAL' | 'UNSUPPORTED' | 'FAILED';
export type ExtractorType = 'pdf' | 'docx' | 'xlsx' | 'pptx' | 'image' | 'text' | 'archive' | 'none';
export type PreviewType = 'pdf' | 'document' | 'spreadsheet' | 'presentation' | 'image' | 'text' | 'archive' | 'unsupported';

export interface PageText { number: number; text: string; source?: 'text' | 'ocr' | 'text+ocr' }
export interface Section { level: number; kind: 'heading' | 'paragraph' | 'table'; text: string; tableIndex?: number }
export interface TableData { name?: string; rows: string[][]; truncated: boolean }
export interface SheetData { name: string; range: string; rows: string[][]; rowCount: number; truncated: boolean }
export interface SlideData { number: number; title: string; text: string; notes?: string }
export interface LinkInfo { url: string; text?: string; source: string }
export type OcrStatus = 'NOT_ATTEMPTED' | 'COMPLETED' | 'PARTIAL' | 'FAILED' | 'UNSUPPORTED';
export type QrKind = 'url' | 'email' | 'phone' | 'sms' | 'wifi' | 'text' | 'other-scheme';
export interface QrCodeInfo { index: number; payload: string; kind: QrKind; scheme?: string; location: string; url?: string; schemeAssumed?: boolean; truncated: boolean }
export type PdfVisualKind = 'TEXT' | 'IMAGE_ONLY' | 'MIXED' | 'EMPTY';
export interface VisualAnalysis {
  version: 1; ocrStatus: OcrStatus; ocrLanguage: string; ocrDurationMs: number; ocrConfidence: number | null; ocrWarnings: string[];
  imagesAnalyzed: number; ocrImageCount: number; ocrPages: number[]; pdfKind?: PdfVisualKind;
  qrCodes: QrCodeInfo[]; urlsDetected: number; downscaled: boolean; limitsHit: string[]; cacheHit: boolean;
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
  ocrText?: string; ocrConfidence?: number | null; visual?: VisualAnalysis; properties?: Record<string, string>;
  summary: ContentSummary; previewType: PreviewType; previewAvailable: boolean; unsupportedReason?: string;
  embeddedContentWarning: boolean; extractionWarnings: string[]; technicalDetails?: string; truncated: boolean; truncationNote?: string;
  startedAt: string; analyzedAt: string; executionPerformed: false; uploaded: false;
}
