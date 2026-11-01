// NOTE: mirrored by src/types/phase6.ts (the renderer cannot import from electron/).
import type { ThreatStatus } from '../threat/types';

export type AlertSeverity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
export interface SecurityAlert {
  id: string; fileId: string; fileName: string; sha256: string | null; assessmentId: string; dedupeKey: string;
  status: ThreatStatus; severity: AlertSeverity; score: number; title: string; message: string; createdAt: string;
  notified: boolean; readAt?: string; dismissedAt?: string; actionTaken?: string;
}

export type QuarantineState = 'QUARANTINED' | 'RESTORED' | 'DELETED';
export interface QuarantinedFile {
  id: string; fileId: string; originalPath: string; quarantinePath: string; originalName: string; sha256: string; size: number; detectedType: string;
  riskStatus: ThreatStatus; riskScore: number; quarantinedAt: string; reason: string; automatic: boolean; state: QuarantineState;
  restoredAt?: string; restoredPath?: string; deletedAt?: string;
}

export type UserActionKind = 'ALERT_SHOWN' | 'REVIEWED' | 'QUARANTINED' | 'RESTORED' | 'DELETED' | 'OPENED_ANYWAY' | 'OPENED' | 'RESCANNED' | 'LOCATION_OPENED';
export interface ThreatHistoryEntry {
  id: string; fileId: string; fileName: string; sha256: string | null; status: ThreatStatus; score: number; assessedAt: string;
  /** Latest decision taken for this assessment ('—' until the user or protection mode acts). */
  action: string; actionAt?: string;
}

export interface SecuritySettings {
  notifyCritical: boolean; notifyHigh: boolean; notifySuspicious: boolean; notifyInformational: boolean;
  /** OFF by default. When ON, only CRITICAL files are moved to quarantine; nothing is ever deleted automatically. */
  autoQuarantineCritical: boolean;
  /** ON by default. CRITICAL files always require confirmation regardless of this setting. */
  requireConfirmHighRisk: boolean;
  explanationLevel: 'simple' | 'technical';
}
export const DEFAULT_SECURITY_SETTINGS: SecuritySettings = {
  notifyCritical: true, notifyHigh: true, notifySuspicious: true, notifyInformational: false,
  autoQuarantineCritical: false, requireConfirmHighRisk: true, explanationLevel: 'simple'
};

export interface ProtectionStatus {
  protectionOn: boolean; monitoringActive: boolean; autoQuarantineCritical: boolean; requireConfirmHighRisk: boolean; quarantinedCount: number; unreadAlerts: number;
}
export type OpenDecision = { allowed: boolean; requiresConfirmation: boolean; blocked?: string; level: ThreatStatus | 'QUARANTINED'; reasons: string[]; note?: string; executable?: boolean };
export type ActionResult<T = unknown> = { ok: true; value?: T; message?: string } | { ok: false; code: string; error: string };
