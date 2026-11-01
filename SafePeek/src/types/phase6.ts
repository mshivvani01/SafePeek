// Phase 6 renderer types. Mirror electron/ai/types.ts and electron/protection/types.ts (the renderer cannot import from electron/).
import type { ThreatStatus } from './threat';

export type AlertSeverity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
export interface SecurityAlert { id: string; fileId: string; fileName: string; sha256: string | null; assessmentId: string; status: ThreatStatus; severity: AlertSeverity; score: number; title: string; message: string; createdAt: string; notified: boolean; readAt?: string; dismissedAt?: string; actionTaken?: string }
export interface QuarantinedFile { id: string; fileId: string; originalPath: string; originalName: string; sha256: string; size: number; detectedType: string; riskStatus: ThreatStatus; riskScore: number; quarantinedAt: string; reason: string; automatic: boolean; state: 'QUARANTINED' | 'RESTORED' | 'DELETED'; restoredAt?: string; restoredPath?: string; deletedAt?: string }
export interface ThreatHistoryEntry { id: string; fileId: string; fileName: string; sha256: string | null; status: ThreatStatus; score: number; assessedAt: string; action: string; actionAt?: string }
export interface SecuritySettings { notifyCritical: boolean; notifyHigh: boolean; notifySuspicious: boolean; notifyInformational: boolean; autoQuarantineCritical: boolean; requireConfirmHighRisk: boolean; explanationLevel: 'simple' | 'technical' }
export interface ProtectionStatus { protectionOn: boolean; monitoringActive: boolean; autoQuarantineCritical: boolean; requireConfirmHighRisk: boolean; quarantinedCount: number; unreadAlerts: number }
export type ActionResult<T = unknown> = { ok: true; value?: T; message?: string } | { ok: false; code: string; error: string };
export interface OpenInfo { allowed: boolean; requiresConfirmation: boolean; blocked?: string; level: string; reasons: string[]; fileName: string }

export interface ThreatExplanation { summary: string; whatWasFound: string[]; whyItMatters: string[]; recommendedAction: string; technicalDetails?: string[]; confidenceExplanation?: string; generatedBy: 'LOCAL_RULE_ENGINE' | 'OPTIONAL_AI'; generatedAt: string; provider?: string; model?: string }
export interface ExplanationBundle { fileId: string; status: ThreatStatus; score: number; analyzedAt: string; local: ThreatExplanation; ai?: ThreatExplanation; aiOutcome: 'OFF' | 'NOT_REQUESTED' | 'USED' | 'REJECTED' | 'FAILED'; aiMessage?: string }
export interface AiSettingsView { enabled: boolean; provider: 'none' | 'anthropic' | 'openai'; model: string; shareFileName: boolean; shareEvidenceSnippets: boolean; keyConfigured: boolean; secureStorageAvailable: boolean }
export interface AiDisclosure { provider: string; model: string; endpointHost: string; includes: string[]; excludes: string[]; payloadPreview: string }
