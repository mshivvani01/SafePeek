import type { ActionResult, AiDisclosure, AiSettingsView, AlertSeverity, ExplanationBundle, OpenInfo, ProtectionStatus, QuarantinedFile, SecurityAlert, SecuritySettings, ThreatHistoryEntry } from '../types/phase6';

const b = () => window.safepeek;
const text = (e: unknown) => (e instanceof Error ? e.message : String(e)).replace(/^Error invoking remote method '[^']*': (Error: )?/, '');
/** A rejected IPC call (invalid id, untrusted sender, main-process failure) becomes a normal failed ActionResult so the UI shows a message instead of an unhandled rejection. */
const guard = async <T,>(fn: () => Promise<ActionResult<T>>): Promise<ActionResult<T>> => { try { return await fn(); } catch (e) { return { ok: false, code: 'IPC_ERROR', error: `SafePeek could not complete this action. ${text(e)}` }; } };
const NA: ActionResult = { ok: false, code: 'UNAVAILABLE', error: 'This action is only available in the SafePeek desktop app.' };
export const defaultSecurity: SecuritySettings = { notifyCritical: true, notifyHigh: true, notifySuspicious: true, notifyInformational: false, autoQuarantineCritical: false, requireConfirmHighRisk: true, explanationLevel: 'simple' };

/** Thin wrapper over the Phase 6 preload bridge. Outside Electron every call degrades to an empty/unavailable result. */
export const protectionService = {
  available: () => !!b()?.getProtectionStatus,
  status: async (): Promise<ProtectionStatus | null> => (b()?.getProtectionStatus ? b()!.getProtectionStatus() : null),
  settings: async (): Promise<SecuritySettings> => (b()?.getSecuritySettings ? b()!.getSecuritySettings() : defaultSecurity),
  saveSettings: async (p: Partial<SecuritySettings>) => (b()?.saveSecuritySettings ? b()!.saveSecuritySettings(p) : defaultSecurity),
  explanation: async (id: string): Promise<ExplanationBundle | null> => (b()?.getExplanation ? b()!.getExplanation(id) : null),
  aiSettings: async (): Promise<AiSettingsView | null> => (b()?.getAiSettings ? b()!.getAiSettings() : null),
  saveAiSettings: async (p: Partial<AiSettingsView>) => (b()?.saveAiSettings ? b()!.saveAiSettings(p) : null),
  setApiKey: async (k: string) => (b()?.setAiApiKey ? b()!.setAiApiKey(k) : { ok: false, error: 'Unavailable' }),
  clearApiKey: async () => (b()?.clearAiApiKey ? b()!.clearAiApiKey() : { ok: false }),
  disclosure: async (id: string): Promise<AiDisclosure | null> => (b()?.getAiDisclosure ? b()!.getAiDisclosure(id) : null),
  requestAi: async (id: string, confirmed: boolean): Promise<ExplanationBundle | null> => (b()?.requestAiExplanation ? b()!.requestAiExplanation(id, confirmed) : null),
  alerts: async (state: 'active' | 'unread' | 'dismissed' | 'all' = 'active', severity?: AlertSeverity): Promise<SecurityAlert[]> => (b()?.listAlerts ? b()!.listAlerts({ state, severity }) : []),
  markRead: async (id: string) => b()?.markAlertRead?.(id),
  markAllRead: async () => b()?.markAllAlertsRead?.(),
  dismiss: async (id: string) => b()?.dismissAlert?.(id),
  history: async (): Promise<ThreatHistoryEntry[]> => (b()?.getThreatHistory ? b()!.getThreatHistory(500) : []),
  quarantine: async (): Promise<QuarantinedFile[]> => (b()?.listQuarantine ? b()!.listQuarantine() : []),
  quarantineFile: async (fileId: string): Promise<ActionResult<QuarantinedFile>> => guard(async () => (b()?.quarantineFile ? b()!.quarantineFile(fileId) : NA)),
  restore: async (id: string, confirmed: boolean, fallback = false): Promise<ActionResult<QuarantinedFile>> => guard(async () => (b()?.restoreQuarantined ? b()!.restoreQuarantined(id, confirmed, fallback) : NA)),
  remove: async (id: string, confirmed: boolean): Promise<ActionResult<QuarantinedFile>> => guard(async () => (b()?.deleteQuarantined ? b()!.deleteQuarantined(id, confirmed) : NA)),
  openInfo: async (id: string): Promise<OpenInfo | null> => (b()?.getOpenInfo ? b()!.getOpenInfo(id) : null),
  open: async (id: string, confirmed: boolean): Promise<ActionResult> => guard(async () => (b()?.openFile ? b()!.openFile(id, confirmed) : NA)),
  reveal: async (id: string): Promise<ActionResult> => guard(async () => (b()?.openFileLocation ? b()!.openFileLocation(id) : NA)),
  copyPath: async (id: string): Promise<ActionResult> => guard(async () => (b()?.copyFilePath ? b()!.copyFilePath(id) : NA)),
  rescan: async (id: string): Promise<ActionResult> => guard(async () => (b()?.rescanFile ? b()!.rescanFile(id) : NA)),
  review: async (id: string): Promise<ActionResult> => guard(async () => (b()?.markFileReviewed ? b()!.markFileReviewed(id) : NA))
};
