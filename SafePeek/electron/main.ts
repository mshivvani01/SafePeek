import { app, BrowserWindow, clipboard, Notification, safeStorage, session, shell } from 'electron';
import path from 'node:path';
import { MonitoringAgent } from './agent/agent';
import { StateStore } from './agent/store';
import { AnalysisService } from './analysis/service';
import { configureOcr } from './content/ocr';
import { ContentService } from './content/contentService';
import { ThreatService } from './threat/threatService';
import { ExplanationService, SecretStore } from './ai';
import { AlertService, HistoryService, ProtectionService, QuarantineService, SecuritySettingsStore } from './protection';
import type { SecurityAlert } from './protection';
import { readSettings, registerIpc } from './ipc';
import { isTrustedUrl } from './ipc/validate';
import { cleanDisplayName } from './util/displayName';
import { alertNotificationText, detectionNotificationText } from './util/notificationText';

const isDev = process.env.NODE_ENV === 'development';
let win: BrowserWindow | null = null;
let agent: MonitoringAgent;
let agentStore: StateStore | null = null;
let analysis: AnalysisService | null = null;
let content: ContentService | null = null;
let threat: ThreatService | null = null;
let protection: ProtectionService | null = null;
let explanations: ExplanationService | null = null;
const log = (m: string) => console.log(m);
let quarantineDirOf: ((p: string) => boolean) | null = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1280, height: 820, minWidth: 980, minHeight: 640, backgroundColor: '#0B0F14', title: 'SafePeek', autoHideMenuBar: true, show: false, icon: path.join(__dirname, '../build/icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true }
  });
  // Started at Windows sign-in (--hidden): appear minimized in the taskbar instead of taking over the screen.
  win.once('ready-to-show', () => { if (!win) return; if (process.argv.includes('--hidden')) { win.showInactive(); win.minimize(); } else win.show(); });
  // SafePeek never opens windows or follows links on behalf of file content. External links are not supported at all (document content is data, never navigation).
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e, url) => { if (!isTrustedUrl(url, isDev)) { e.preventDefault(); log(`[SafePeek] Blocked navigation to ${url.slice(0, 80)}`); } });
  win.webContents.on('will-attach-webview', (e) => e.preventDefault());
  win.webContents.on('render-process-gone', (_e, d) => { log(`[SafePeek] Renderer process gone (${d.reason}); reloading`); if (d.reason !== 'clean-exit' && win && !win.isDestroyed()) win.reload(); });
  win.webContents.on('did-fail-load', (_e, code, desc) => log(`[SafePeek] Window failed to load (${code} ${desc})`));
  win.on('closed', () => { win = null; });
  if (isDev) win.loadURL('http://localhost:5173'); else win.loadFile(path.join(__dirname, '../dist/index.html'));
}

async function notify(id: string, name: string, kind: 'new' | 'modified') {
  const s = await readSettings();
  if (s && s.notifications === false) return;
  if (!Notification.isSupported()) return;
  const n = new Notification({ ...detectionNotificationText(name, kind) });
  // Clicking only brings SafePeek forward and shows the file's detail page. It never opens the file.
  n.on('click', () => navigateTo(id));
  n.show();
}

function showWindow() { if (win) { if (win.isMinimized()) win.restore(); win.show(); win.focus(); } else createWindow(); }
function navigateTo(fileId: string, alertId?: string) {
  showWindow();
  const send = () => win?.webContents.send('app:navigate', { page: 'files', fileId, alertId });
  if (!win || win.webContents.isLoading()) win?.webContents.once('did-finish-load', send); else send();
}
/** Security alert notification. Never opens the file; clicking only brings SafePeek forward and navigates to the File Detail screen. */
function notifyAlert(a: SecurityAlert) {
  if (!Notification.isSupported()) return;
  const n = new Notification({ ...alertNotificationText(a), urgency: a.severity === 'CRITICAL' ? 'critical' : 'normal' });
  n.on('click', () => navigateTo(a.fileId, a.id));
  n.show();
}

// Windows toasts are attributed to (and clickable through) the app's AppUserModelID; it must match the installer's appId (package.json build.appId).
if (process.platform === 'win32') app.setAppUserModelId('com.safepeek.app');
// Nothing may fail silently: log (message only, never file contents) instead of dying or swallowing.
process.on('uncaughtException', (e) => log(`[SafePeek] Uncaught exception: ${e?.message ?? e}`));
process.on('unhandledRejection', (e) => log(`[SafePeek] Unhandled rejection: ${(e as Error)?.message ?? e}`));

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(async () => {
    // No renderer permission (camera, geolocation, notifications API, ...) is ever granted; native notifications come from the main process.
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    const store = agentStore = new StateStore(path.join(app.getPath('userData'), 'safepeek-state.json'), app.getPath('downloads'), log);
    agent = new MonitoringAgent(store, {
      log,
      onFileRecorded: (f) => analysis?.enqueue(f),
      isExcluded: (p) => (quarantineDirOf ? quarantineDirOf(p) : false),
      emitChange: () => { if (win && !win.isDestroyed()) win.webContents.send('agent:changed'); },
      notify: (f, kind) => { notify(f.id, cleanDisplayName(f.name), kind).catch((e) => log(`[SafePeek] Notification failed: ${(e as Error).message}`)); }
    });
    const emitChange = () => { if (win && !win.isDestroyed()) win.webContents.send('agent:changed'); };
    // Pipeline: watcher -> static analysis -> content analysis -> threat engine (each stage reuses the previous stage's stored result).
    const ud = app.getPath('userData');
    // Phase 6 services (all local; stored under userData/security and userData/quarantine)
    const settings = new SecuritySettingsStore(path.join(ud, 'security', 'settings.json'), log);
    const secrets = new SecretStore(path.join(ud, 'security', 'secrets.json'), { isAvailable: () => safeStorage.isEncryptionAvailable(), encrypt: (p) => safeStorage.encryptString(p), decrypt: (b) => safeStorage.decryptString(b) });
    const quarantine = new QuarantineService({ dir: path.join(ud, 'quarantine', 'files'), log, fallbackRestoreDir: app.getPath('downloads') });
    const alerts = new AlertService(path.join(ud, 'security', 'alerts.json'), log);
    const history = new HistoryService(path.join(ud, 'security', 'history.json'), log);
    explanations = new ExplanationService({ dir: path.join(ud, 'explanations'), log, getAssessment: (id) => (threat ? threat.get(id) : Promise.resolve(null)), getAiSettings: () => settings.ai(), secrets });
    threat = new ThreatService(store, agent.events, { log, emitChange, dir: path.join(ud, 'threat'), getContent: (id) => (content ? content.get(id) : Promise.resolve(null)), onAssessed: (id) => protection?.handleAssessment(id), isSkipped: (id) => protection?.isQuarantined(id) === true });
    configureOcr({ modelDir: path.join(app.getPath('userData'), 'ocr-model') });
    content = new ContentService(store, agent.events, { log, emitChange, dir: path.join(app.getPath('userData'), 'content'), visualCacheDir: path.join(app.getPath('userData'), 'ocr-cache'), onFinished: (f) => threat?.enqueue(f), isSkipped: (id) => protection?.isQuarantined(id) === true });
    analysis = new AnalysisService(store, agent.events, { log, emitChange, onAnalyzed: (f) => content?.enqueue(f), onFailed: (f) => threat?.enqueue(f), isSkipped: (id) => protection?.isQuarantined(id) === true });
    protection = new ProtectionService({
      store, events: agent.events, alerts, history, quarantine, settings, getAssessment: (id) => (threat ? threat.get(id) : Promise.resolve(null)), explain: (id) => explanations!.get(id),
      notify: notifyAlert, rescan: (id) => analysis?.reanalyze(id), monitoringActive: () => agent.getStatus().active, log, emitChange,
      system: { openPath: (p) => shell.openPath(p), showItemInFolder: (p) => shell.showItemInFolder(p), writeClipboard: (t) => clipboard.writeText(t) }
    });
    quarantineDirOf = (p) => quarantine.isQuarantinePath(p);
    registerIpc(agent, analysis, content, threat, { protection, explanations, alerts, history, quarantine, settings, secrets }, { dev: isDev });
    createWindow();
    await agent.start();
    analysis.resume();
    content.resume();
    threat.resume();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
  let quitting = false;
  app.on('before-quit', (e) => {
    if (quitting) return;
    quitting = true; e.preventDefault();
    analysis?.stop(); content?.stop(); threat?.stop();
    // Stop watchers and make sure state files are fully written before exiting, but never hang the quit.
    const done = Promise.allSettled([agent?.stopAll(), agentStore?.flush()]).then((r) => r.forEach((x) => { if (x.status === 'rejected') log(`[SafePeek] Shutdown step failed: ${(x.reason as Error)?.message}`); }));
    Promise.race([done, new Promise((r) => setTimeout(r, 3000))]).finally(() => app.quit());
  });
  app.on('window-all-closed', () => app.quit());
}
