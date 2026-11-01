import type { MonitoringStatus } from '../types/monitoring';

/** Thin wrapper over the preload bridge. Returns null outside Electron (e.g. plain browser dev). */
export const monitoringService = {
  available: () => !!window.safepeek?.getMonitoringStatus,
  status: async (): Promise<MonitoringStatus | null> => (window.safepeek ? window.safepeek.getMonitoringStatus() : null),
  setEnabled: (v: boolean) => window.safepeek?.setMonitoringEnabled(v),
  addFolder: () => window.safepeek?.addMonitoredFolder(),
  removeFolder: (id: string) => window.safepeek?.removeMonitoredFolder(id),
  setFolderEnabled: (id: string, v: boolean) => window.safepeek?.setFolderEnabled(id, v),
  createTestFile: () => window.safepeek?.createTestFile()
};
