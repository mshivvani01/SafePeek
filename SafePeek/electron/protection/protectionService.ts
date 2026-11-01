import fs from 'node:fs';
import { describeFsError, fsCode, isLockedOrDenied } from '../util/fsErrors';
import type { StateStore } from '../agent/store';
import type { FileEventService } from '../agent/fileEventService';
import type { AgentEventType, DetectedFile } from '../agent/types';
import type { ExplanationBundle } from '../ai/types';
import type { ThreatAssessment, ThreatStatus } from '../threat/types';
import { RISK_LEVEL } from '../threat/threatService';
import { AlertService, alertEligible, notificationAllowed } from './alertService';
import { HistoryService } from './historyService';
import { decideOpen } from './openSafety';
import { validatePath } from '../agent/paths';
import { DANGEROUS_EXTENSIONS } from '../analysis/extensions';
import { sha256File } from '../analysis/hash';
import type { QuarantineService } from './quarantineService';
import type { SecuritySettingsStore } from './settings';
import type { ActionResult, OpenDecision, ProtectionStatus, QuarantinedFile, SecurityAlert } from './types';

export interface SystemActions { openPath(p: string): Promise<string>; showItemInFolder(p: string): void; writeClipboard(text: string): void }
export interface ProtectionDeps {
  store: StateStore; events: FileEventService; alerts: AlertService; history: HistoryService; quarantine: QuarantineService; settings: SecuritySettingsStore;
  getAssessment(id: string): Promise<ThreatAssessment | null>; explain(id: string): Promise<ExplanationBundle | null>;
  /** Called with a desktop-notification request. Only invoked when the user's notification settings allow it. */
  notify(alert: SecurityAlert): void; rescan(id: string): void; system: SystemActions; monitoringActive(): boolean; log(m: string): void; emitChange(): void;
}
const HASH_CHECK_MAX_BYTES = 512 * 1024 * 1024;
const fail = (code: string, error: string): { ok: false; code: string; error: string } => ({ ok: false, code, error });
const ev = (type: AgentEventType, message: string, f: DetectedFile, extra: { riskLevel?: string; score?: number } = {}) => ({ type, message, extra: { fileName: f.name, folder: f.sourceFolder, riskLevel: f.riskLevel, score: f.threatScore, ...extra } });

/**
 * Phase 6 orchestrator. Consumes the AUTHORITATIVE Phase 5 assessment and produces: history entry -> local explanation -> (optional) automatic quarantine -> alert -> notification.
 * It never changes the risk score or status, never opens/executes files by itself, and never deletes anything automatically.
 */
export class ProtectionService {
  constructor(private d: ProtectionDeps) {}
  private find(id: string) { return this.d.store.state.files.find((f) => f.id === id); }
  private event(type: AgentEventType, message: string, f: DetectedFile, extra: { riskLevel?: string; score?: number } = {}) { const e = ev(type, message, f, extra); this.d.events.addEvent(e.type, e.message, e.extra); }
  /** Executable/script by extension or by detected content: opening it through the shell would RUN it. */
  private isExecutableLike(f: DetectedFile): boolean { const cat = f.analysis?.identity.category; return DANGEROUS_EXTENSIONS.has(f.extension) || cat === 'executable' || cat === 'script'; }
  /** True while any pipeline stage is (re)running for this file, so the stored verdict may describe an older version. */
  private pipelineBusy(f: DetectedFile): boolean {
    return f.analysisStatus === 'pending' || f.analysisStatus === 'analyzing' || (f.analysisStatus === 'complete' && (!f.contentStatus || ['NOT_STARTED', 'QUEUED', 'ANALYZING'].includes(f.contentStatus)))
      || (f.analysisStatus !== 'failed' && (!f.threatAnalysisStatus || ['NOT_STARTED', 'QUEUED', 'ANALYZING'].includes(f.threatAnalysisStatus)) && f.analysisStatus === 'complete')
      || (f.analysisStatus === 'failed' && (f.threatAnalysisStatus === 'QUEUED' || f.threatAnalysisStatus === 'ANALYZING'));
  }
  private decide(f: DetectedFile) { return decideOpen(f.threatStatus, this.isQuarantined(f.id), this.d.settings.security(), { executable: this.isExecutableLike(f), pipelineBusy: this.pipelineBusy(f) }); }
  isQuarantined(id: string): boolean { return this.find(id)?.quarantineState === 'QUARANTINED' || !!this.d.quarantine.activeByFile(id); }

  /** Pipeline step after Phase 5: called by ThreatService.onAssessed. */
  async handleAssessment(id: string): Promise<void> {
    const f = this.find(id); if (!f) return;
    if (this.isQuarantined(id)) return; // an assessment for a file that has already been isolated needs no action
    const a = await this.d.getAssessment(id); if (!a) return;
    const settings = this.d.settings.security();
    this.d.history.record({ id, name: f.name, sha256: f.sha256 }, a);
    if (a.status !== 'SAFE' && a.status !== 'UNKNOWN') { const b = await this.d.explain(id); if (b) this.event('explanation-generated', 'Explanation generated (local rule engine)', f); }

    let suffix: string | undefined; let actionTaken: string | undefined;
    if (a.status === 'CRITICAL' && settings.autoQuarantineCritical) {
      if (this.d.quarantine.wasRestored(f.sha256)) { suffix = 'You previously restored this file, so SafePeek did not quarantine it again automatically. Open SafePeek to review.'; }
      else {
        const r = await this.quarantineFile(id, { automatic: true, reason: `Automatically quarantined: CRITICAL risk (${a.score}/100) and automatic quarantine is enabled.` });
        if (r.ok) { suffix = 'SafePeek moved it to quarantine because automatic quarantine is on. It was not opened or deleted.'; actionTaken = 'Auto-quarantined'; }
        else suffix = `Automatic quarantine did not succeed (${r.error}). The file was left in place; do not open it. Open SafePeek to review.`;
      }
    }
    if (!alertEligible(a.status, settings)) { this.d.emitChange(); return; }
    const cur = this.find(id) ?? f;
    const created = this.d.alerts.create({ id, name: f.name, sha256: cur.sha256 }, a, { messageSuffix: suffix, actionTaken });
    if (!created || created.duplicate) { this.d.emitChange(); return; }
    this.event('alert-created', `Alert created — ${created.alert.title}`, cur, { riskLevel: RISK_LEVEL[a.status], score: a.score });
    if (notificationAllowed(a.status, settings)) {
      try { this.d.notify(created.alert); this.d.alerts.markNotified(created.alert.id); this.event('alert-shown', 'Desktop notification shown', cur, { riskLevel: RISK_LEVEL[a.status], score: a.score }); }
      catch (e) { this.d.log(`[SafePeek] Notification failed: ${(e as Error).message}`); }
    }
    this.d.emitChange();
  }

  async quarantineFile(id: string, o: { automatic?: boolean; reason?: string } = {}): Promise<ActionResult<QuarantinedFile>> {
    const f = this.find(id); if (!f) return fail('NOT_FOUND', 'File not found.');
    if (this.isQuarantined(id)) return fail('ALREADY_QUARANTINED', 'This file is already in quarantine.');
    const status: ThreatStatus = f.threatStatus ?? 'UNKNOWN';
    const r = await this.d.quarantine.quarantine({ fileId: id, path: f.path, sha256: f.sha256, detectedType: f.detectedType ?? f.analysis?.identity.detectedType ?? 'Unknown', status, score: f.threatScore ?? 0, automatic: !!o.automatic,
      reason: o.reason ?? (status === 'UNKNOWN' ? 'Quarantined by the user.' : `Quarantined by the user (${status.replace('_', ' ').toLowerCase()}, ${f.threatScore ?? 0}/100).`) });
    if (!r.ok) { this.event('quarantine-failed', `Quarantine failed: ${r.error}`, f); this.d.emitChange(); return r; }
    const q = r.value!; f.quarantineState = 'QUARANTINED'; f.quarantineId = q.id; f.quarantinedAt = q.quarantinedAt; this.d.store.save();
    this.event('file-quarantined', o.automatic ? 'File automatically quarantined' : 'File quarantined by user', f);
    this.d.history.setAction(id, o.automatic ? 'Auto-quarantined' : 'Quarantined'); this.d.alerts.recordAction(id, o.automatic ? 'Auto-quarantined' : 'Quarantined', { overwrite: true });
    this.d.emitChange(); return r;
  }
  async restoreFile(qid: string, o: { confirmed: boolean; useFallbackFolder?: boolean }): Promise<ActionResult<QuarantinedFile>> {
    const r = await this.d.quarantine.restore(qid, o); const q = this.d.quarantine.get(qid);
    const f = q ? this.find(q.fileId) : undefined;
    if (!r.ok && q?.state !== 'RESTORED') { this.d.emitChange(); return r; } // a failed hash verification after the move still moved the file: metadata must reflect reality
    if (f && q) {
      f.quarantineState = 'RESTORED'; f.path = q.restoredPath ?? f.path; f.name = (q.restoredPath ?? f.path).split(/[\\/]/).pop() ?? f.name;
      try { const st = await fs.promises.lstat(f.path); f.signature = `${st.size}:${st.mtimeMs}`; } catch (e) { this.d.log(`[SafePeek] Restored file could not be re-checked (${(e as Error).message}); the rescan will report it`); }
      this.d.store.save();
      this.event('file-restored', 'File restored from quarantine (not opened)', f); this.d.history.setAction(f.id, 'Restored'); this.d.alerts.recordAction(f.id, 'Restored', { overwrite: true });
      this.d.rescan(f.id); // re-analysis through Phase 3 -> 4 -> 5 -> 6; the file is not executed
    }
    this.d.emitChange(); return r;
  }
  async deleteQuarantined(qid: string, o: { confirmed: boolean }): Promise<ActionResult<QuarantinedFile>> {
    const r = await this.d.quarantine.remove(qid, o); const q = this.d.quarantine.get(qid); const f = q ? this.find(q.fileId) : undefined;
    if (r.ok && q) { if (f) { f.quarantineState = 'DELETED'; this.d.store.save(); this.event('file-deleted', 'Quarantined file permanently deleted', f); this.d.history.setAction(f.id, 'Deleted'); this.d.alerts.recordAction(f.id, 'Deleted', { overwrite: true }); } }
    this.d.emitChange(); return r;
  }

  /** Everything the confirmation dialog needs (decision + the top reasons) without exposing paths. */
  async openInfo(id: string): Promise<(OpenDecision & { fileName: string }) | null> {
    const f = this.find(id); if (!f) return null;
    const dec = this.decide(f);
    const a = dec.requiresConfirmation ? await this.d.getAssessment(id) : null;
    return { ...dec, fileName: f.name, reasons: a ? a.reasons.slice(0, 5).map((r) => r.text) : [] };
  }
  async openFile(id: string, confirmed: boolean): Promise<ActionResult> {
    const f = this.find(id); if (!f) return fail('NOT_FOUND', 'File not found.');
    const dec = this.decide(f);
    if (!dec.allowed) return fail('QUARANTINED', dec.blocked!);
    if (dec.requiresConfirmation && confirmed !== true) return fail('CONFIRMATION_REQUIRED', `This file is classified as ${(dec.level ?? 'UNKNOWN').replace('_', ' ')}.${dec.executable ? ' It is a program or script, so opening it would run it.' : ''} Opening it requires explicit confirmation (Open Anyway).`);
    // The path comes from SafePeek's own record, but it is still re-validated (stored data is not trusted blindly).
    let target: string; try { target = validatePath(f.path); } catch { return fail('INVALID_PATH', 'The stored file path is not valid.'); }
    // The file must still be what was analyzed: size + modified time, and (when known) the SHA-256, otherwise the assessment no longer describes it.
    const outdated = () => fail('FILE_CHANGED', 'Analysis is outdated. The file has changed since SafePeek analyzed it. Rescan before continuing.');
    try {
      const st = await fs.promises.lstat(target); if (st.isSymbolicLink() || !st.isFile()) return fail('NOT_A_FILE', 'Only regular files can be opened.');
      if (f.signature && `${st.size}:${st.mtimeMs}` !== f.signature) return outdated();
      if (f.sha256 && st.size <= HASH_CHECK_MAX_BYTES && (await sha256File(target)) !== f.sha256) return outdated();
    } catch (e) { const c = fsCode(e); return c === 'ENOENT' ? fail('FILE_MISSING', 'The file no longer exists at its original location.') : fail('FILE_UNREADABLE', isLockedOrDenied(e) ? describeFsError(e) : 'The file could not be checked before opening. Try again in a moment.'); }
    const err = await this.d.system.openPath(target);
    if (err) return fail('OPEN_FAILED', err);
    this.event(dec.requiresConfirmation ? 'file-opened-anyway' : 'file-opened', dec.requiresConfirmation ? 'File opened after explicit confirmation (Open Anyway)' : 'File opened by user', f);
    this.d.history.setAction(id, dec.requiresConfirmation ? 'Opened anyway' : 'Opened'); this.d.alerts.recordAction(id, dec.requiresConfirmation ? 'Opened anyway' : 'Opened');
    this.d.emitChange(); return { ok: true };
  }
  async openLocation(id: string): Promise<ActionResult> {
    const f = this.find(id); if (!f) return fail('NOT_FOUND', 'File not found.');
    if (this.isQuarantined(id)) return fail('QUARANTINED', 'Quarantined files stay inside SafePeek\'s quarantine folder.');
    try { await fs.promises.lstat(f.path); } catch { return fail('FILE_MISSING', 'The file no longer exists at its original location.'); }
    this.d.system.showItemInFolder(f.path); this.event('location-opened', 'Containing folder opened', f); return { ok: true };
  }
  copyPath(id: string): ActionResult { const f = this.find(id); if (!f) return fail('NOT_FOUND', 'File not found.'); this.d.system.writeClipboard(f.path); return { ok: true }; }
  rescan(id: string): ActionResult {
    const f = this.find(id); if (!f) return fail('NOT_FOUND', 'File not found.');
    if (this.isQuarantined(id)) return fail('QUARANTINED', 'Quarantined files are not rescanned. Restore the file first.');
    this.event('file-rescanned', 'Rescan requested', f); this.d.history.setAction(id, 'Rescanned', { onlyIfEmpty: true }); this.d.rescan(id); return { ok: true };
  }
  markReviewed(id: string): ActionResult {
    const f = this.find(id); if (!f) return fail('NOT_FOUND', 'File not found.');
    this.event('file-reviewed', 'File reviewed by user', f); this.d.history.setAction(id, 'Reviewed', { onlyIfEmpty: true }); this.d.alerts.recordAction(id, 'Reviewed'); this.d.emitChange(); return { ok: true };
  }
  status(): ProtectionStatus {
    const s = this.d.settings.security(); const active = this.d.monitoringActive();
    return { protectionOn: active, monitoringActive: active, autoQuarantineCritical: s.autoQuarantineCritical, requireConfirmHighRisk: s.requireConfirmHighRisk, quarantinedCount: this.d.quarantine.activeCount(), unreadAlerts: this.d.alerts.unreadCount() };
  }
}
