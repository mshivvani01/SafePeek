import type { ActivityEvent, FileRecord, QuarantineItem } from '../types/file';
import type { AppSettings } from '../types/scan';
import { mockActivity, mockFiles, mockQuarantine } from '../data/mockData';
import type { QuarantinedFile } from '../types/phase6';
import { riskFromStatus } from '../utils/format';

/** Data access boundary. Phase 2+ swaps MockRepository for a real (JSON/SQLite) implementation. */
export interface Repository {
  readonly isDemo: boolean;
  listFiles(): Promise<FileRecord[]>;
  getFile(id: string): Promise<FileRecord | undefined>;
  listActivity(): Promise<ActivityEvent[]>;
  listQuarantine(): Promise<QuarantineItem[]>;
}

export class MockRepository implements Repository {
  readonly isDemo = true;
  listFiles = async () => mockFiles;
  getFile = async (id: string) => mockFiles.find((f) => f.id === id);
  listActivity = async () => mockActivity;
  listQuarantine = async () => mockQuarantine;
}

const EVENT_LABELS: Record<string, string> = {
  'file-detected': 'New file detected', 'file-modified': 'File changed', 'monitoring-started': 'Monitoring started',
  'monitoring-stopped': 'Monitoring paused', 'folder-added': 'Folder added', 'folder-removed': 'Folder removed', 'watcher-error': 'Watcher problem',
  'analysis-started': 'Static analysis started', 'analysis-completed': 'Static analysis completed', 'analysis-failed': 'Static analysis failed',
  'content-started': 'Content analysis started', 'content-completed': 'Content extracted', 'content-failed': 'Content analysis failed', 'preview-generated': 'Safe preview generated',
  'threat-started': 'Threat analysis started', 'threat-completed': 'Threat analysis completed', 'threat-failed': 'Threat analysis failed',
  'suspicious-file-detected': 'Suspicious file detected', 'high-risk-file-detected': 'High-risk file detected',
  'explanation-generated': 'Explanation generated', 'alert-created': 'Security alert created', 'alert-shown': 'Alert notification shown', 'file-reviewed': 'Reviewed by user',
  'file-quarantined': 'File quarantined', 'quarantine-failed': 'Quarantine failed', 'file-restored': 'Restored from quarantine', 'file-deleted': 'Quarantined file deleted',
  'file-opened': 'File opened', 'file-opened-anyway': 'Opened anyway (confirmed)', 'file-rescanned': 'Rescan requested', 'location-opened': 'Containing folder opened'
};
const toItem = (q: QuarantinedFile): QuarantineItem => ({ id: q.id, originalName: q.originalName, originalPath: q.originalPath, quarantinedAt: q.quarantinedAt, riskLevel: riskFromStatus(q.riskStatus), reason: q.reason, status: q.state === 'QUARANTINED' ? 'quarantined' : q.state === 'RESTORED' ? 'restored' : 'deleted' });

/** Real repository backed by the Electron monitoring agent (Phase 2) and, since Phase 6, the real quarantine. */
export class IpcRepository implements Repository {
  readonly isDemo = false;
  listFiles = async () => (await window.safepeek!.getDetectedFiles()) as FileRecord[];
  getFile = async (id: string) => (await this.listFiles()).find((f) => f.id === id);
  listQuarantine = async (): Promise<QuarantineItem[]> => (window.safepeek?.listQuarantine ? (await window.safepeek.listQuarantine()).map(toItem) : []);
  listActivity = async (): Promise<ActivityEvent[]> =>
    (await window.safepeek!.getRecentFileEvents()).map((e) => ({
      id: e.id, timestamp: e.timestamp, fileName: e.fileName ?? e.folder ?? '—', event: EVENT_LABELS[e.type] ?? e.message,
      riskLevel: (e.riskLevel as ActivityEvent['riskLevel']) ?? (e.type === 'file-detected' || e.type === 'file-modified' ? 'unknown' : null),
      status: e.type.startsWith('threat-') || e.type.startsWith('file-') || e.type.startsWith('alert-') || e.type.startsWith('quarantine-') || e.type === 'explanation-generated' || e.type === 'location-opened' || e.type.endsWith('-file-detected') && e.type !== 'file-detected' ? e.message : e.type === 'file-detected' || e.type === 'file-modified' ? 'Analysis pending' : e.type.startsWith('content-') || e.type === 'preview-generated' ? 'Local content analysis' : e.message
    }));
}

export const defaultSettings: AppSettings = {
  startWithWindows: false, minimizeToTray: true, notifications: true, downloadsFolder: '', customFolders: []
};

export const storageService = {
  // Real data inside Electron; demo data only when the bridge is missing (plain browser dev).
  repository: (typeof window !== 'undefined' && window.safepeek?.getDetectedFiles ? new IpcRepository() : new MockRepository()) as Repository,
  async loadSettings(): Promise<AppSettings> {
    const saved = await window.safepeek?.getSettings();
    return { ...defaultSettings, ...(saved ?? {}) };
  },
  async saveSettings(s: AppSettings): Promise<void> {
    await window.safepeek?.saveSettings(s);
  }
};
