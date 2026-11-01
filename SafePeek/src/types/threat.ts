// Phase 5 renderer types. Mirrors electron/threat/types.ts (the renderer cannot import from electron/).
export type RiskLevel = 'safe' | 'low' | 'suspicious' | 'high' | 'critical' | 'unknown';
export type Severity = 'info' | 'warning' | 'low' | 'medium' | 'high' | 'critical';

export type IndicatorType =
  | 'double-extension' | 'executable-content' | 'macro' | 'suspicious-url'
  | 'script' | 'archive' | 'mime-mismatch' | 'social-engineering' | 'external-url' | 'embedded-object' | 'pdf-action' | 'other';

/** Phase 3 static indicator as stored on the FileRecord (facts, not a verdict). */
export interface ThreatIndicator {
  type: IndicatorType; severity: Severity; title: string; description: string; evidence?: string; code?: string;
}

export type ThreatStatus = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL' | 'UNKNOWN';
export type ThreatSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatCategory = string; // extensible; see electron/threat/types.ts THREAT_CATEGORIES
export type RecommendationAction = 'DO_NOT_OPEN' | 'QUARANTINE' | 'REVIEW_CONTENT' | 'OPEN_WITH_CAUTION' | 'NO_ACTION';
export type ThreatAnalysisStatus = 'NOT_STARTED' | 'QUEUED' | 'ANALYZING' | 'COMPLETED' | 'INCOMPLETE' | 'FAILED';

/** Phase 5 indicator (electron `ThreatIndicator`). */
export interface AssessmentIndicator {
  id: string; ruleId: string; category: ThreatCategory; severity: ThreatSeverity; title: string; description: string; evidence?: string;
  source: string; points: number; correlated: boolean; /** Extraction paths behind the evidence (Phase 8): STATIC | TEXT | OCR | QR | ARCHIVE | COMBINED. */ origins?: string[];
}
export interface ThreatReason { id: string; text: string; severity: ThreatSeverity; category: ThreatCategory; indicatorIds: string[] }
export interface ThreatEvidence { indicatorId: string; type: string; description: string; value?: string; source: string; origin?: string }
export interface ThreatRecommendation { action: RecommendationAction; title: string; description: string }
export interface ThreatCoverage { static: string; content: string; threat: 'COMPLETE' | 'INCOMPLETE'; notes: string[] }
export interface ScoreBreakdown {
  contributions: { indicatorId: string; title: string; category: string; weight: number; applied: number; note?: string }[];
  correlationBonus: number; breadthBonus: number; rawScore: number; finalScore: number; notes: string[];
}
export interface ThreatAssessment {
  version: 1; fileName: string; status: ThreatStatus; score: number; confidence: number; confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW'; headline: string; analysisComplete: boolean;
  indicators: AssessmentIndicator[]; reasons: ThreatReason[]; categories: ThreatCategory[]; evidence: ThreatEvidence[]; recommendations: ThreatRecommendation[];
  coverage: ThreatCoverage; breakdown: ScoreBreakdown; limitations: string[]; disclaimer: string;
  analyzedAt: string; engineVersion: string; scoreKind: 'heuristic'; executionPerformed: false; uploaded: false;
}
