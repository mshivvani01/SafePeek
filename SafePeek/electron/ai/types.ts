// NOTE: mirrored by src/types/phase6.ts (the renderer cannot import from electron/).
import type { ThreatStatus } from '../threat/types';

export type ExplanationLevel = 'simple' | 'technical';
export type ExplanationSource = 'LOCAL_RULE_ENGINE' | 'OPTIONAL_AI';

/** Human-readable explanation of a Phase 5 assessment. It never changes the assessment: Phase 5 stays authoritative. */
export interface ThreatExplanation {
  summary: string;
  whatWasFound: string[];
  whyItMatters: string[];
  recommendedAction: string;
  technicalDetails?: string[];
  confidenceExplanation?: string;
  generatedBy: ExplanationSource;
  generatedAt: string;
  /** Only for OPTIONAL_AI: provider id and model that wrote the text. */
  provider?: string; model?: string;
}

export type AiProviderId = 'none' | 'anthropic' | 'openai';
export interface AiSettings {
  /** Master switch. OFF by default. Nothing is ever sent while this is false. */
  enabled: boolean; provider: AiProviderId; model: string;
  /** What may be sent (all OFF by default). The original file is never sent in any configuration. */
  shareFileName: boolean; shareEvidenceSnippets: boolean;
}
export const DEFAULT_AI_SETTINGS: AiSettings = { enabled: false, provider: 'none', model: '', shareFileName: false, shareEvidenceSnippets: false };

export type AiOutcome = 'OFF' | 'NOT_REQUESTED' | 'USED' | 'REJECTED' | 'FAILED';
export interface ExplanationBundle {
  fileId: string; status: ThreatStatus; score: number; analyzedAt: string;
  /** Always present: generated offline from the Phase 5 evidence. */
  local: ThreatExplanation;
  /** Only present after the user explicitly asked for it with AI explanation enabled. */
  ai?: ThreatExplanation; aiOutcome: AiOutcome; aiMessage?: string;
}

/** What would be sent to the provider. Shown to the user before anything leaves the machine. */
export interface AiDisclosure {
  provider: AiProviderId; model: string; endpointHost: string;
  includes: string[]; excludes: string[]; payloadPreview: string;
}
