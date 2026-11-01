import type { RiskLevel, ThreatIndicator } from './threat';
import type { FileRecord } from './file';

export interface ScanResult {
  fileId: string;
  startedAt: string;
  completedAt: string | null;
  riskLevel: RiskLevel;
  score: number; // 0-100, never implies "100% safe"
  indicators: ThreatIndicator[];
  metadata: Record<string, string | number | boolean | null>;
  contentSummary: string | null;
}

/** Phase 3/4/5 analyzers plug in here. Analyzers must treat the file as untrusted and never execute it. */
export interface Analyzer {
  readonly id: string;
  canAnalyze(file: FileRecord): boolean;
  analyze(file: FileRecord): Promise<Partial<ScanResult>>;
}

/** Phase 4: produces sanitized representations; the original file is never modified or opened by the preview. */
export interface PreviewService {
  isSupported(file: FileRecord): boolean;
  render(file: FileRecord): Promise<{ kind: 'text' | 'image' | 'html-sanitized'; content: string }>;
}

export interface AppSettings {
  startWithWindows: boolean;
  minimizeToTray: boolean;
  notifications: boolean;
  downloadsFolder: string;
  customFolders: string[];
}
