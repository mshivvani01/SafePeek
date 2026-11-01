import type { AppSettings } from './scan';
import type { FileRecord } from './file';
import type { ContentResult } from './content';
import type { ThreatAssessment } from './threat';
import type { AgentEvent, MonitoringStatus } from './monitoring';
import type { ActionResult, AiDisclosure, AiSettingsView, AlertSeverity, ExplanationBundle, OpenInfo, ProtectionStatus, QuarantinedFile, SecurityAlert, SecuritySettings, ThreatHistoryEntry } from './phase6';

export interface SafePeekBridge {
  getAppInfo(): Promise<{ name: string; version: string; platform: string; downloadsPath: string }>;
  getSettings(): Promise<AppSettings | null>;
  saveSettings(s: AppSettings): Promise<boolean>;
  getMonitoringStatus(): Promise<MonitoringStatus>;
  setMonitoringEnabled(v: boolean): Promise<void>;
  addMonitoredFolder(): Promise<{ ok: boolean; error: string | null }>;
  removeMonitoredFolder(id: string): Promise<void>;
  setFolderEnabled(id: string, v: boolean): Promise<void>;
  getDetectedFiles(): Promise<FileRecord[]>;
  getRecentFileEvents(): Promise<AgentEvent[]>;
  reanalyzeFile(id: string): Promise<void>;
  getContent(id: string): Promise<ContentResult | null>;
  rerunContent(id: string): Promise<void>;
  getThreat(id: string): Promise<ThreatAssessment | null>;
  rerunThreat(id: string): Promise<void>;
  // Phase 6 (ids and booleans only; no paths cross the bridge)
  getProtectionStatus(): Promise<ProtectionStatus>;
  getSecuritySettings(): Promise<SecuritySettings>;
  saveSecuritySettings(p: Partial<SecuritySettings>): Promise<SecuritySettings>;
  getExplanation(id: string): Promise<ExplanationBundle | null>;
  getAiSettings(): Promise<AiSettingsView>;
  saveAiSettings(p: Partial<AiSettingsView>): Promise<AiSettingsView>;
  setAiApiKey(k: string): Promise<{ ok: boolean; error?: string }>;
  clearAiApiKey(): Promise<{ ok: boolean }>;
  getAiDisclosure(id: string): Promise<AiDisclosure | null>;
  requestAiExplanation(id: string, confirmed: boolean): Promise<ExplanationBundle | null>;
  listAlerts(f?: { severity?: AlertSeverity; state?: 'active' | 'unread' | 'dismissed' | 'all' }): Promise<SecurityAlert[]>;
  markAlertRead(id: string): Promise<boolean>;
  markAllAlertsRead(): Promise<number>;
  dismissAlert(id: string): Promise<boolean>;
  getThreatHistory(limit?: number): Promise<ThreatHistoryEntry[]>;
  listQuarantine(): Promise<QuarantinedFile[]>;
  quarantineFile(fileId: string): Promise<ActionResult<QuarantinedFile>>;
  restoreQuarantined(id: string, confirmed: boolean, useFallback?: boolean): Promise<ActionResult<QuarantinedFile>>;
  deleteQuarantined(id: string, confirmed: boolean): Promise<ActionResult<QuarantinedFile>>;
  getOpenInfo(id: string): Promise<OpenInfo | null>;
  openFile(id: string, confirmed: boolean): Promise<ActionResult>;
  openFileLocation(id: string): Promise<ActionResult>;
  copyFilePath(id: string): Promise<ActionResult>;
  rescanFile(id: string): Promise<ActionResult>;
  markFileReviewed(id: string): Promise<ActionResult>;
  onNavigate(cb: (t: { page: string; fileId?: string; alertId?: string }) => void): () => void;
  createTestFile(): Promise<{ ok: boolean; name?: string; error?: string }>;
  onChange(cb: () => void): () => void;
}
declare global { interface Window { safepeek?: SafePeekBridge } }
