import { app, BrowserWindow, dialog, ipcMain, type IpcMainInvokeEvent } from 'electron';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { MonitoringAgent } from '../agent/agent';
import type { AnalysisService } from '../analysis/service';
import type { ContentService } from '../content/contentService';
import type { ThreatService } from '../threat/threatService';
import { atomicWriteFile } from '../util/atomicWrite';
import { folderIdOf, idOf, isTrustedUrl, limitOf, normalizeAppSettings } from './validate';
import { AI_SECRET, type ExplanationService, type SecretStore } from '../ai';
import type { AlertService, HistoryService, ProtectionService, QuarantineService, QuarantinedFile, SecuritySettingsStore } from '../protection';

/** Start-with-Windows only applies to the installed app (a dev build would register the bare Electron binary). Failure is non-fatal. */
function applyLoginItem(enabled: boolean) {
  if (process.platform !== 'win32' || !app.isPackaged) return;
  try { app.setLoginItemSettings({ openAtLogin: enabled, args: ['--hidden'] }); } catch (e) { console.log(`[SafePeek] Could not update start-with-Windows (${(e as Error).message})`); }
}

const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');

export async function readSettings(): Promise<Record<string, unknown> | null> {
  try { return normalizeAppSettings(JSON.parse(await fs.readFile(settingsFile(), 'utf8'))) as unknown as Record<string, unknown>; }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') console.log(`[SafePeek] settings.json unreadable (${(e as Error).message}); using defaults`); return null; }
}

const TEST_FILE_BODY = 'SafePeek self-test file. Harmless text, safe to delete.\n';

/** Every channel validates input; the renderer never supplies arbitrary paths for watching (the folder picker runs in main). */
export interface Phase6Services { protection: ProtectionService; explanations: ExplanationService; alerts: AlertService; history: HistoryService; quarantine: QuarantineService; settings: SecuritySettingsStore; secrets: SecretStore }
const publicQ = (q: QuarantinedFile) => { const { quarantinePath: _p, ...rest } = q; return rest; }; // the internal vault path is never sent to the renderer
const refresh = () => BrowserWindow.getAllWindows().forEach((w) => { if (!w.isDestroyed()) w.webContents.send('agent:changed'); });

export function registerIpc(agent: MonitoringAgent, analysis?: AnalysisService, content?: ContentService, threat?: ThreatService, p6?: Phase6Services, opts: { dev?: boolean } = {}) {
  // Every handler goes through one gate: the caller must be SafePeek's own top-level page, and failures are logged (channel + message only, never payloads).
  const raw = ipcMain.handle.bind(ipcMain);
  const handle = (channel: string, fn: (e: IpcMainInvokeEvent, ...args: any[]) => unknown) => raw(channel, async (e: IpcMainInvokeEvent, ...args: unknown[]) => {
    const frame = e.senderFrame; const url = frame?.url ?? '';
    if (!frame || frame !== e.sender.mainFrame || !isTrustedUrl(url, opts.dev === true)) { console.log(`[SafePeek] IPC ${channel} rejected: untrusted sender`); throw new Error('Untrusted sender'); }
    try { return await fn(e, ...args); } catch (err) { console.log(`[SafePeek] IPC ${channel} failed: ${(err as Error).message}`); throw err; }
  });
  handle('app:info', () => ({ name: 'SafePeek', version: app.getVersion(), platform: process.platform, downloadsPath: app.getPath('downloads') }));
  handle('settings:get', () => readSettings());
  handle('settings:set', async (_e, s: unknown) => {
    const norm = normalizeAppSettings(s);
    await atomicWriteFile(settingsFile(), JSON.stringify(norm, null, 2));
    applyLoginItem(norm.startWithWindows);
    return true;
  });

  handle('monitor:status', () => agent.getStatus());
  handle('monitor:setEnabled', (_e, v: unknown) => agent.setMonitoringEnabled(v === true));
  handle('monitor:addFolder', async () => {
    const r = await dialog.showOpenDialog({ properties: ['openDirectory'], title: 'Choose a folder for SafePeek to monitor' });
    if (r.canceled || !r.filePaths[0]) return { ok: false as const, error: null };
    try { await agent.addFolder(r.filePaths[0]); return { ok: true as const }; } catch (e) { return { ok: false as const, error: (e as Error).message }; }
  });
  handle('monitor:removeFolder', async (_e, id: unknown) => { await agent.removeFolder(folderIdOf(id)); });
  handle('monitor:setFolderEnabled', async (_e, id: unknown, v: unknown) => { await agent.setFolderEnabled(folderIdOf(id), v === true); });
  handle('analysis:rerun', (_e, id: unknown) => { const fid = idOf(id); if (p6?.protection.isQuarantined(fid)) return; analysis?.reanalyze(fid); });
  // Phase 4: read-only. The id is validated; the renderer never supplies a path.
  handle('content:get', async (_e, id: unknown) => { return (await content?.get(idOf(id))) ?? null; });
  handle('content:rerun', (_e, id: unknown) => { const fid = idOf(id); if (p6?.protection.isQuarantined(fid)) return; content?.rerun(fid); });
  // Phase 5: read-only / re-run by id. The renderer never supplies paths or rules.
  handle('threat:get', async (_e, id: unknown) => { return (await threat?.get(idOf(id))) ?? null; });
  handle('threat:rerun', (_e, id: unknown) => { const fid = idOf(id); if (p6?.protection.isQuarantined(fid)) return; threat?.rerun(fid); });
  handle('monitor:files', () => agent.getFiles());
  handle('monitor:events', () => agent.getEvents());
  // Developer helper: writes a fixed harmless text file (name/content not caller-controlled) into the first active folder.
  handle('monitor:createTestFile', async () => {
    const f = agent.getStatus().folders.find((x) => x.enabled);
    if (!f) return { ok: false as const, error: 'No enabled folder' };
    const target = path.join(f.path, `safepeek-test-${Date.now()}.txt`);
    try { await fs.writeFile(target, TEST_FILE_BODY, { flag: 'wx' }); return { ok: true as const, name: path.basename(target) }; } catch (e) { return { ok: false as const, error: (e as Error).message }; }
  });

  if (!p6) return;
  const { protection, explanations, alerts, history, quarantine, settings, secrets } = p6;
  // Phase 6. Every handler takes ids and booleans only: the renderer never supplies a path, destination, rule or command. Confirmation flags must be exactly `true`.
  handle('protection:status', () => protection.status());
  handle('security:getSettings', () => settings.security());
  handle('security:setSettings', (_e, patch: unknown) => { const r = settings.setSecurity(patch); refresh(); return r; });
  handle('explanation:get', (_e, id: unknown) => explanations.get(idOf(id)));
  handle('ai:getSettings', () => ({ ...settings.ai(), keyConfigured: secrets.has(AI_SECRET), secureStorageAvailable: secrets.available() }));
  handle('ai:setSettings', (_e, patch: unknown) => ({ ...settings.setAi(patch), keyConfigured: secrets.has(AI_SECRET), secureStorageAvailable: secrets.available() }));
  handle('ai:setApiKey', (_e, key: unknown) => { try { if (typeof key !== 'string') throw new Error('Invalid API key format'); secrets.set(AI_SECRET, key.trim()); return { ok: true as const }; } catch (e) { return { ok: false as const, error: (e as Error).message }; } });
  handle('ai:clearApiKey', () => { secrets.delete(AI_SECRET); settings.setAi({ enabled: false }); return { ok: true as const }; });
  handle('ai:disclosure', (_e, id: unknown) => explanations.disclosure(idOf(id)));
  handle('ai:request', async (_e, id: unknown, confirmed: unknown) => { const r = await explanations.requestAi(idOf(id), confirmed === true); refresh(); return r; });
  handle('alerts:list', (_e, f: unknown) => { const o = (typeof f === 'object' && f ? f : {}) as { severity?: unknown; state?: unknown }; const sev = ['INFO', 'WARNING', 'HIGH', 'CRITICAL'].includes(o.severity as string) ? (o.severity as 'INFO') : undefined; const st = ['active', 'unread', 'dismissed', 'all'].includes(o.state as string) ? (o.state as 'active') : 'active'; return alerts.list({ severity: sev, state: st }); });
  handle('alerts:markRead', (_e, id: unknown) => { const r = alerts.markRead(idOf(id)); refresh(); return r; });
  handle('alerts:markAllRead', () => { const r = alerts.markAllRead(); refresh(); return r; });
  handle('alerts:dismiss', (_e, id: unknown) => { const r = alerts.dismiss(idOf(id)); refresh(); return r; });
  handle('history:threats', (_e, limit: unknown) => history.list(limitOf(limit)));
  handle('quarantine:list', () => quarantine.list().map(publicQ));
  handle('quarantine:add', async (_e, fileId: unknown) => protection.quarantineFile(idOf(fileId)));
  handle('quarantine:restore', async (_e, qid: unknown, confirmed: unknown, useFallback: unknown) => protection.restoreFile(idOf(qid), { confirmed: confirmed === true, useFallbackFolder: useFallback === true }));
  handle('quarantine:delete', async (_e, qid: unknown, confirmed: unknown) => protection.deleteQuarantined(idOf(qid), { confirmed: confirmed === true }));
  handle('files:openInfo', (_e, id: unknown) => protection.openInfo(idOf(id)));
  handle('files:open', (_e, id: unknown, confirmed: unknown) => protection.openFile(idOf(id), confirmed === true));
  handle('files:reveal', (_e, id: unknown) => protection.openLocation(idOf(id)));
  handle('files:copyPath', (_e, id: unknown) => protection.copyPath(idOf(id)));
  handle('files:rescan', (_e, id: unknown) => protection.rescan(idOf(id)));
  handle('files:review', (_e, id: unknown) => protection.markReviewed(idOf(id)));
}
