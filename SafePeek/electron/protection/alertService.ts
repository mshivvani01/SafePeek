import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { cleanInline } from '../content/sanitizer';
import type { ThreatAssessment, ThreatStatus } from '../threat/types';
import { JsonStore } from './jsonStore';
import type { AlertSeverity, SecurityAlert, SecuritySettings } from './types';

export const SEVERITY_OF: Partial<Record<ThreatStatus, AlertSeverity>> = { LOW_RISK: 'INFO', SUSPICIOUS: 'WARNING', HIGH_RISK: 'HIGH', CRITICAL: 'CRITICAL' };
const TITLE: Partial<Record<ThreatStatus, string>> = { LOW_RISK: 'SafePeek found minor warning signs in a file', SUSPICIOUS: 'SafePeek detected a suspicious file', HIGH_RISK: 'SafePeek detected a high-risk file', CRITICAL: 'SafePeek detected a critical-risk file' };
const MAX_ALERTS = 500;
const SEVERITY_BY_NAME: Record<string, true> = { INFO: true, WARNING: true, HIGH: true, CRITICAL: true };

/** Phase 5 status -> does a desktop notification fire? Uses the Phase 5 status directly; there is no second scoring system. */
export function notificationAllowed(status: ThreatStatus, s: SecuritySettings): boolean {
  return status === 'CRITICAL' ? s.notifyCritical : status === 'HIGH_RISK' ? s.notifyHigh : status === 'SUSPICIOUS' ? s.notifySuspicious : status === 'LOW_RISK' ? s.notifyInformational : false;
}
/** Alert RECORDS exist for SUSPICIOUS/HIGH_RISK/CRITICAL always (a security record cannot be silenced), and for LOW_RISK only when informational alerts are enabled. SAFE and UNKNOWN never alert. */
export function alertEligible(status: ThreatStatus, s: SecuritySettings): boolean {
  return status === 'SUSPICIOUS' || status === 'HIGH_RISK' || status === 'CRITICAL' || (status === 'LOW_RISK' && s.notifyInformational);
}
/** Identifies one distinct assessment outcome: same status + score + set of indicators = same fingerprint. */
export const assessmentFingerprint = (a: ThreatAssessment): string => createHash('sha1').update(`${a.status}|${a.score}|${a.indicators.filter((i) => i.severity !== 'INFO').map((i) => i.ruleId).sort().join(',')}`).digest('hex').slice(0, 16);
export const assessmentIdOf = (fileId: string, a: ThreatAssessment): string => createHash('sha1').update(`${fileId}|${a.analyzedAt}`).digest('hex').slice(0, 20);
const safeName = (n: string) => cleanInline(path.basename(String(n)), 120);

interface AFile { version: 1; alerts: SecurityAlert[] }
const isAFile = (x: unknown): x is AFile => typeof x === 'object' && x !== null && (x as AFile).version === 1 && Array.isArray((x as AFile).alerts);
export type AlertFilter = { severity?: AlertSeverity; state?: 'active' | 'unread' | 'dismissed' | 'all' };

export class AlertService {
  private store: JsonStore<AFile>;
  constructor(file: string, log: (m: string) => void = () => undefined, private now: () => string = () => new Date().toISOString()) {
    this.store = new JsonStore<AFile>(file, () => ({ version: 1, alerts: [] }), isAFile, log);
    const n = this.store.data.alerts.length;
    this.store.data.alerts = this.store.data.alerts.filter((a) => !!a && typeof a === 'object' && typeof a.id === 'string' && typeof a.fileId === 'string' && typeof a.dedupeKey === 'string' && typeof a.fileName === 'string' && typeof a.score === 'number' && !!SEVERITY_BY_NAME[a.severity]);
    if (this.store.data.alerts.length < n) log(`[SafePeek] Ignored ${n - this.store.data.alerts.length} malformed alert record(s)`);
  }
  flush() { return this.store.flush(); }

  /** Creates an alert unless an alert for the same file name + hash + assessment outcome already exists (read, unread or dismissed). */
  create(f: { id: string; name: string; sha256: string | null }, a: ThreatAssessment, extra: { messageSuffix?: string; actionTaken?: string } = {}): { alert: SecurityAlert; duplicate: boolean } | null {
    const severity = SEVERITY_OF[a.status]; if (!severity) return null;
    const dedupeKey = `${f.sha256 ?? `nohash:${f.id}`}|${safeName(f.name).toLowerCase()}|${a.status}|${assessmentFingerprint(a)}`;
    const dup = this.store.data.alerts.find((x) => x.dedupeKey === dedupeKey);
    if (dup) return { alert: dup, duplicate: true };
    const name = safeName(f.name);
    const alert: SecurityAlert = {
      id: randomUUID(), fileId: f.id, fileName: name, sha256: f.sha256, assessmentId: assessmentIdOf(f.id, a), dedupeKey, status: a.status, severity, score: a.score,
      title: TITLE[a.status]!, message: `${name} — risk score ${a.score}/100. ${extra.messageSuffix ?? 'Open SafePeek to review.'}`, createdAt: this.now(), notified: false, actionTaken: extra.actionTaken
    };
    this.store.data.alerts.unshift(alert);
    if (this.store.data.alerts.length > MAX_ALERTS) { const drop = this.store.data.alerts.filter((x) => x.dismissedAt).slice(-(this.store.data.alerts.length - MAX_ALERTS)); this.store.data.alerts = this.store.data.alerts.filter((x) => !drop.includes(x)).slice(0, MAX_ALERTS); }
    this.store.save();
    return { alert, duplicate: false };
  }
  markNotified(id: string) { const a = this.get(id); if (a) { a.notified = true; this.store.save(); } }
  get(id: string): SecurityAlert | undefined { return this.store.data.alerts.find((a) => a.id === id); }
  list(f: AlertFilter = {}): SecurityAlert[] {
    const state = f.state ?? 'active';
    return this.store.data.alerts.filter((a) => (f.severity ? a.severity === f.severity : true) && (state === 'all' ? true : state === 'dismissed' ? !!a.dismissedAt : state === 'unread' ? !a.dismissedAt && !a.readAt : !a.dismissedAt));
  }
  unreadCount(): number { return this.store.data.alerts.filter((a) => !a.readAt && !a.dismissedAt).length; }
  markRead(id: string): boolean { const a = this.get(id); if (!a) return false; if (!a.readAt) { a.readAt = this.now(); this.store.save(); } return true; }
  markAllRead(): number { let n = 0; for (const a of this.store.data.alerts) if (!a.readAt && !a.dismissedAt) { a.readAt = this.now(); n++; } if (n) this.store.save(); return n; }
  dismiss(id: string): boolean { const a = this.get(id); if (!a) return false; if (!a.dismissedAt) { a.dismissedAt = this.now(); a.readAt ??= a.dismissedAt; this.store.save(); } return true; }
  /** Records what happened to the file(s) behind an alert and marks them read. */
  recordAction(fileId: string, action: string, opts: { overwrite?: boolean } = {}) {
    let n = 0; for (const a of this.store.data.alerts) if (a.fileId === fileId && !a.dismissedAt) { if (opts.overwrite || !a.actionTaken) a.actionTaken = action; a.readAt ??= this.now(); n++; }
    if (n) this.store.save();
  }
}
