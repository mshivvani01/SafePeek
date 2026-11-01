// Mirrors electron/agent/types.ts (renderer cannot import from electron/).
export interface MonitoredFolder { id: string; path: string; label: string; enabled: boolean; isDefault: boolean; addedAt: string }
export interface AgentEvent { id: string; timestamp: string; type: string; fileName?: string; folder?: string; message: string; riskLevel?: string; score?: number }
export interface MonitoringStatus {
  enabled: boolean; active: boolean; folders: MonitoredFolder[]; folderErrors: Record<string, string>;
  lastError: string | null; lastDetection: { fileName: string; at: string } | null; filesDetected: number;
}
