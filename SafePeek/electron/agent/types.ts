import type { AnalysisResult } from '../analysis/types';
// NOTE: mirrored by src/types/monitoring.ts and src/types/file.ts (renderer cannot import from electron/).
export interface MonitoredFolder { id: string; path: string; label: string; enabled: boolean; isDefault: boolean; addedAt: string }

export interface StaticIndicatorLite { type: string; severity: string; title: string; description: string; evidence?: string; code?: string }

export interface DetectedFile {
  id: string; name: string; path: string; extension: string; mimeType: string; size: number;
  createdAt: string; modifiedAt: string; detectedAt: string;
  sourceFolder: string; sourceFolderPath: string; signature: string;
  sha256: string | null; status: 'detected' | 'analyzed'; riskLevel: 'unknown' | 'safe' | 'low' | 'suspicious' | 'high' | 'critical'; analysisStatus: 'pending' | 'analyzing' | 'complete' | 'failed';
  contentSummary: string | null; detectedUrls: string[]; indicators: (Omit<StaticIndicatorLite, never>)[]; previewAvailable: boolean;
  // Phase 3
  detectedType?: string; analysis?: AnalysisResult;
  // Phase 4 (the full ContentResult lives in userData/content/<id>.json; only light fields are kept here)
  contentStatus?: 'NOT_STARTED' | 'QUEUED' | 'ANALYZING' | 'COMPLETED' | 'PARTIAL' | 'UNSUPPORTED' | 'FAILED';
  contentType?: string; documentType?: string; previewType?: string; contentTruncated?: boolean;
  // Phase 5 (the full ThreatAssessment lives in userData/threat/<id>.json; only summary fields are kept here)
  threatAnalysisStatus?: 'NOT_STARTED' | 'QUEUED' | 'ANALYZING' | 'COMPLETED' | 'INCOMPLETE' | 'FAILED';
  threatStatus?: 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL' | 'UNKNOWN';
  threatScore?: number; threatConfidence?: number; threatCategories?: string[]; threatIndicatorCount?: number; threatAnalyzedAt?: string;
  threatHeadline?: string; threatTopReason?: string; threatRecommendation?: string; threatAnalysisComplete?: boolean;
  // Phase 6 (the QuarantinedFile metadata lives in userData/quarantine.json)
  quarantineState?: 'QUARANTINED' | 'RESTORED' | 'DELETED'; quarantineId?: string; quarantinedAt?: string;
}

export type AgentEventType = 'monitoring-started' | 'monitoring-stopped' | 'file-detected' | 'file-modified' | 'folder-added' | 'folder-removed' | 'watcher-error' | 'analysis-started' | 'analysis-completed' | 'analysis-failed' | 'content-started' | 'content-completed' | 'content-failed' | 'preview-generated' | 'threat-started' | 'threat-completed' | 'threat-failed' | 'suspicious-file-detected' | 'high-risk-file-detected'
  // Phase 6
  | 'explanation-generated' | 'alert-created' | 'alert-shown' | 'file-reviewed' | 'file-quarantined' | 'quarantine-failed' | 'file-restored' | 'file-deleted' | 'file-opened' | 'file-opened-anyway' | 'file-rescanned' | 'location-opened';
export interface AgentEvent { id: string; timestamp: string; type: AgentEventType; fileName?: string; folder?: string; message: string; /** Phase 5 events only */ riskLevel?: string; score?: number }

export interface MonitoringStatus {
  enabled: boolean; active: boolean; folders: MonitoredFolder[]; folderErrors: Record<string, string>;
  lastError: string | null; lastDetection: { fileName: string; at: string } | null; filesDetected: number;
}

export interface AgentState { version: 1; monitoringEnabled: boolean; folders: MonitoredFolder[]; files: DetectedFile[]; events: AgentEvent[] }
