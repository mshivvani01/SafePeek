// NOTE: mirrored by src/types/analysis.ts (renderer cannot import from electron/).
export type IndicatorCode =
  | 'TYPE_MISMATCH' | 'DOUBLE_EXTENSION' | 'EXECUTABLE_FILE' | 'SCRIPT_FILE' | 'MACRO_DETECTED' | 'EMBEDDED_EXECUTABLE'
  | 'SUSPICIOUS_PDF_ACTION' | 'EXTERNAL_URL' | 'EMPTY_FILE' | 'ARCHIVE_EXECUTABLE' | 'ARCHIVE_PATH_TRAVERSAL' | 'ENCRYPTED_CONTENT' | 'EXTERNAL_RELATIONSHIP';
export type IndicatorSeverity = 'info' | 'warning' | 'high';
/** Static, factual indicator. NOT a verdict: Phase 5 decides weight. */
export interface StaticIndicator {
  code: IndicatorCode; type: string; severity: IndicatorSeverity; title: string; description: string; evidence?: string;
}
export type FileCategory = 'document' | 'image' | 'archive' | 'executable' | 'script' | 'text' | 'other' | 'unknown';
export interface FileIdentity {
  name: string; path: string; extension: string;
  declaredType: string | null; detectedType: string; detectedTypeId: string; mimeType: string | null;
  category: FileCategory; typeMismatch: boolean; executionPerformed: false;
}
export interface FileMetadataInfo {
  size: number; createdAt: string; modifiedAt: string; accessedAt: string | null; sizeClass: 'empty' | 'tiny' | 'normal' | 'large';
}
export interface EmbeddedObject { name: string; kind: string; executable: boolean; source: string }
export interface ArchiveEntry { name: string; size: number; isDirectory: boolean; encrypted: boolean; dangerous: boolean; unsafePath: boolean }
export interface ArchiveInfo { format: string; entryCount: number; entries: ArchiveEntry[]; truncated: boolean; encryptedEntries: number; totalUncompressed: number; extracted: false }
export interface ScriptInfo { language: string; lineCount: number; bytesRead: number; truncated: boolean; hasEmbeddedScriptTags: boolean; executionPerformed: false; contentAvailable: boolean }
export interface PEInfo {
  architecture: string; kind: 'EXE' | 'DLL' | 'Other'; subsystem: string | null; entryPointRva: number | null; sections: string[];
  imports: string[]; importsTruncated: boolean; hasSignatureBlock: boolean; signatureVerified: false; isDotNet: boolean; parseComplete: boolean;
}
export interface PDFInfo {
  version: string | null; pageCount: number | null; encrypted: boolean; hasJavaScript: boolean; hasOpenAction: boolean; hasLaunchAction: boolean;
  embeddedFileCount: number; annotationCount: number; urls: string[]; suspiciousActions: string[]; metadata: Record<string, string>;
  scannedBytes: number; truncated: boolean; objectStreamsScanned: number; method: 'raw-token-scan';
}
export interface OfficeInfo {
  format: 'docx' | 'xlsx' | 'pptx' | 'unknown-ooxml'; label: string; macroEnabledType: boolean; hasMacros: boolean; hasActiveX: boolean;
  externalRelationships: { target: string; type: string }[]; embeddedObjects: EmbeddedObject[]; metadata: Record<string, string>;
}
export interface AnalysisResult {
  version: 1;
  status: 'complete' | 'partial' | 'failed';
  partialReasons: string[];
  startedAt: string; completedAt: string; analysisTimestamp: string;
  identity: FileIdentity; metadata: FileMetadataInfo; sha256: string | null;
  urls: string[]; embeddedObjects: EmbeddedObject[];
  archive?: ArchiveInfo; script?: ScriptInfo; pe?: PEInfo; pdf?: PDFInfo; office?: OfficeInfo;
  indicators: StaticIndicator[];
}
