import type { AnalysisResult, FileCategory } from '../analysis/types';
import type { ContentResult, ContentStatus } from '../content/types';
// NOTE: mirrored by src/types/threat.ts (the renderer cannot import from electron/).

export const ENGINE_VERSION = '5.1.0';

export type ThreatStatus = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL' | 'UNKNOWN';
export type ThreatSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
/** Extensible: add a value here and use it from a rule. Nothing else needs to change. */
export const THREAT_CATEGORIES = [
  'MALWARE', 'PHISHING', 'SCAM', 'SOCIAL_ENGINEERING', 'SUSPICIOUS_DOCUMENT', 'SUSPICIOUS_EXECUTABLE', 'SUSPICIOUS_SCRIPT', 'MALICIOUS_URL',
  'ARCHIVE_RISK', 'MACRO_RISK', 'OBFUSCATION', 'FILE_TYPE_MISMATCH', 'EXECUTION_RISK', 'CREDENTIAL_THEFT', 'FINANCIAL_FRAUD', 'UNKNOWN'
] as const;
export type ThreatCategory = (typeof THREAT_CATEGORIES)[number];
export type IndicatorSource = 'STATIC_ANALYSIS' | 'CONTENT_ANALYSIS' | 'URL_ANALYSIS' | 'ARCHIVE_ANALYSIS' | 'METADATA' | 'CORRELATION';
/** Where a piece of evidence came from. Phase 8: lets the explanation say "OCR detected…" / "QR code points to…" instead of a vague "content". */
export type EvidenceOrigin = 'STATIC' | 'TEXT' | 'OCR' | 'QR' | 'ARCHIVE' | 'COMBINED';
export const ORIGIN_LABEL: Record<EvidenceOrigin, string> = { STATIC: 'Static analysis', TEXT: 'Document text', OCR: 'OCR (text read from an image)', QR: 'QR code', ARCHIVE: 'Archive analysis', COMBINED: 'Combined evidence' };
export type RecommendationAction = 'DO_NOT_OPEN' | 'QUARANTINE' | 'REVIEW_CONTENT' | 'OPEN_WITH_CAUTION' | 'NO_ACTION';

export interface ThreatIndicator {
  id: string; ruleId: string; category: ThreatCategory; severity: ThreatSeverity; title: string; description: string; evidence?: string;
  source: IndicatorSource;
  /** Points this indicator actually contributed to the score after de-duplication, caps and multipliers (0 for informational ones). */
  points: number;
  /** True for indicators created by correlating several independent pieces of evidence. */
  correlated: boolean;
  /** Extraction paths that produced the evidence (Phase 8). The same evidence seen through two paths is ONE indicator with two origins. */
  origins?: EvidenceOrigin[];
}
export interface ThreatReason { id: string; text: string; severity: ThreatSeverity; category: ThreatCategory; indicatorIds: string[] }
export interface ThreatEvidence { indicatorId: string; type: string; description: string; value?: string; source: string; origin?: EvidenceOrigin }
export interface ThreatRecommendation { action: RecommendationAction; title: string; description: string }

export type StaticCoverage = 'COMPLETE' | 'PARTIAL' | 'FAILED' | 'PENDING';
export type ContentCoverage = 'COMPLETE' | 'PARTIAL' | 'TRUNCATED' | 'UNSUPPORTED' | 'FAILED' | 'PENDING';
export interface ThreatCoverage { static: StaticCoverage; content: ContentCoverage; threat: 'COMPLETE' | 'INCOMPLETE'; notes: string[] }

export interface ScoreContribution { indicatorId: string; title: string; category: ThreatCategory; weight: number; applied: number; note?: string }
export interface ScoreBreakdown {
  contributions: ScoreContribution[]; correlationBonus: number; breadthBonus: number; rawScore: number; finalScore: number; notes: string[];
}

export interface ThreatAssessment {
  version: 1; fileName: string;
  status: ThreatStatus;
  /** 0-100 HEURISTIC risk score (how many / how severe the suspicious indicators are). NOT a probability of malware. */
  score: number;
  /** 0-100: how complete and reliable the available analysis was. Independent of the risk score. */
  confidence: number; confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  headline: string; analysisComplete: boolean;
  indicators: ThreatIndicator[]; reasons: ThreatReason[]; categories: ThreatCategory[]; evidence: ThreatEvidence[]; recommendations: ThreatRecommendation[];
  coverage: ThreatCoverage; breakdown: ScoreBreakdown; limitations: string[]; disclaimer: string;
  analyzedAt: string; engineVersion: string; scoreKind: 'heuristic'; executionPerformed: false; uploaded: false;
}

export interface ThreatInput {
  fileName: string; analysis?: AnalysisResult | null; content?: ContentResult | null;
  /** Content status as stored on the file record (used when the full ContentResult is not available). */
  contentStatus?: ContentStatus; now?: string;
}

/** Output of a single rule, before scoring. Rules never compute the final score. */
export interface RuleFinding {
  ruleId: string; category: ThreatCategory; severity: ThreatSeverity; title: string; description: string; evidence?: string; source: IndicatorSource;
  /** Raw points before de-duplication/caps. */
  weight: number;
  /** Short sentence used in the "Why?" list. Defaults to the title. */
  reason?: string;
  /** Findings sharing a key describe the same underlying evidence: the strongest counts fully, the others at 25%. */
  dedupeKey?: string;
  /** Findings sharing a cap group cannot together contribute more than the cap defined in scoring.ts. */
  capGroup?: string;
  /** Base-risk findings (e.g. "is an executable") are not multiplied by the executable multiplier. */
  base?: boolean;
  correlation?: boolean;
  /** Phase 8: extraction paths behind this finding. Defaults are derived from `source` by the engine. */
  origins?: EvidenceOrigin[];
  evidenceItems?: { type: string; description: string; value?: string; origin?: EvidenceOrigin }[];
}

export interface UrlIssue { kind: string; weight: number; detail: string }
export interface UrlResult { url: string; host: string; issues: UrlIssue[]; score: number; suspicious: boolean; linkText?: string; source: string; /** Phase 8: which extraction path produced this URL. */ origin?: EvidenceOrigin }

export interface PhraseHit { group: string; id: string; label: string; snippet: string; /** Which extraction paths contain this phrase (Phase 8). A phrase present in two paths is still ONE hit. */ origins?: EvidenceOrigin[] }

export interface RuleContext {
  fileName: string; ext: string; analysis: AnalysisResult | null; content: ContentResult | null;
  typeId: string; typeLabel: string; category: FileCategory;
  /** The file is (really) an executable. */
  isExecutable: boolean;
  /** The file is (really or by extension) a script. */
  isScript: boolean;
  /** Raw extracted text (OCR text for images), capped. Untrusted data. */
  rawText: string;
  urls: UrlResult[];
  /** Phase 8: the text segments the lure analysis ran over (document text, OCR text, QR text) and what the visual channels contained. */
  segments: { origin: EvidenceOrigin; text: string }[];
  visual: { ocrText: boolean; directText: boolean; qrCount: number; qrWebCount: number; ocrPages: number; imagesAnalyzed: number; pdfKind?: string; partial: boolean; qr: { payload: string; kind: string; scheme?: string; url?: string }[] };
  lure: { hits: PhraseHit[]; has(id: string): boolean; count(group: string): number; first(group: string): PhraseHit | undefined; ids(group: string): string[] };
  scriptKind: string | null;
}
export type Rule = (ctx: RuleContext) => RuleFinding[];
