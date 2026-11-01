import type { RiskLevel, ThreatAnalysisStatus, ThreatIndicator, ThreatStatus } from './threat';
import type { AnalysisResult } from './analysis';

import type { ContentStatus, PreviewType } from './content';
export type AnalysisStatus = 'pending' | 'analyzing' | 'complete' | 'failed' | 'not-started';
export type FileStatus = 'new' | 'detected' | 'analyzed' | 'quarantined' | 'released';

export interface FileRecord {
  id: string;
  name: string;
  path: string;
  extension: string;
  mimeType: string;
  size: number;
  createdAt: string; // ISO
  modifiedAt: string; // ISO
  sha256: string | null; // Phase 3
  status: FileStatus;
  riskLevel: RiskLevel;
  analysisStatus: AnalysisStatus;
  contentSummary: string | null; // Phase 4
  detectedUrls: string[];
  indicators: ThreatIndicator[];
  previewAvailable: boolean; // Phase 4
  // Phase 2 (set by the monitoring agent)
  // Phase 3 (static analysis; facts only, no verdict)
  detectedType?: string;
  analysis?: AnalysisResult;
  // Phase 4 (the full ContentResult is loaded on demand with getContent)
  contentStatus?: ContentStatus;
  contentType?: string;
  documentType?: string;
  previewType?: PreviewType;
  contentTruncated?: boolean;
  // Phase 5 (the full ThreatAssessment is loaded on demand with getThreat)
  threatAnalysisStatus?: ThreatAnalysisStatus;
  threatStatus?: ThreatStatus;
  threatScore?: number;
  threatConfidence?: number;
  threatCategories?: string[];
  threatIndicatorCount?: number;
  threatAnalyzedAt?: string;
  threatHeadline?: string;
  threatTopReason?: string;
  threatRecommendation?: string;
  threatAnalysisComplete?: boolean;
  // Phase 6
  quarantineState?: 'QUARANTINED' | 'RESTORED' | 'DELETED';
  quarantineId?: string;
  quarantinedAt?: string;
  detectedAt?: string;
  sourceFolder?: string;
  sourceFolderPath?: string;
}

export type ActivityEvent = {
  id: string;
  timestamp: string;
  fileName: string;
  event: string;
  riskLevel: RiskLevel | null; // null for non-file events (e.g. monitoring started)
  status: string;
};

export interface QuarantineItem {
  id: string;
  originalName: string;
  originalPath: string;
  quarantinedAt: string;
  riskLevel: RiskLevel;
  reason: string;
  status: 'quarantined' | 'restored' | 'deleted';
}
