import type { RuleFinding, ScoreBreakdown, ScoreContribution, ThreatSeverity, ThreatStatus } from './types';

/**
 * Transparent scoring. All numbers live here.
 *   1. Each rule returns a raw weight.                                 (rules/*.ts)
 *   2. De-duplication: findings with the same dedupeKey describe the same evidence; the strongest counts 100%, the rest 25%.
 *   3. Caps: findings in one capGroup cannot exceed CAPS[group] together.
 *   4. Executable multiplier: non-base findings on a real executable/script are x1.15.
 *   5. Diminishing returns: the n-th largest remaining contribution is multiplied by 0.9^n.
 *   6. Correlation bonus: findings produced by combining independent evidence are added (total capped at CORRELATION_CAP).
 *   7. Breadth bonus: independent categories with real evidence add a small amount.
 *   8. Clamp to 0-100, then map to a status with severity guards (see statusFor).
 * The result is a heuristic risk score, NOT a probability of malware.
 */
export const THRESHOLDS = { LOW_RISK: 20, SUSPICIOUS: 40, HIGH_RISK: 60, CRITICAL: 80 } as const;
export const CAPS: Record<string, number> = { url: 38, 'content-lure': 60, pe: 30, 'script-content': 55, archive: 62 };
export const DUPLICATE_FACTOR = 0.25, DECAY = 0.9, EXEC_MULTIPLIER = 1.15, CORRELATION_CAP = 35;
export const BREADTH_BONUS: Record<number, number> = { 3: 8, 4: 14, 5: 18 };
const r1 = (n: number) => Math.round(n * 10) / 10;
const RANK: Record<ThreatSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export const severityRank = (s: ThreatSeverity) => RANK[s];

export interface Scored { finding: RuleFinding; points: number }

export function scoreFindings(findings: RuleFinding[], execLike: boolean): { scored: Scored[]; breakdown: ScoreBreakdown } {
  const notes: string[] = []; const applied = new Map<RuleFinding, { v: number; note: string[] }>();
  for (const f of findings) applied.set(f, { v: f.weight, note: [] });
  const regular = findings.filter((f) => !f.correlation && f.weight > 0);
  const corr = findings.filter((f) => f.correlation && f.weight > 0);

  const dedupe = (list: RuleFinding[]) => {
    const groups = new Map<string, RuleFinding[]>();
    for (const f of list) if (f.dedupeKey) groups.set(f.dedupeKey, [...(groups.get(f.dedupeKey) ?? []), f]);
    for (const [k, g] of groups) g.sort((a, b) => b.weight - a.weight).forEach((f, i) => { if (i > 0) { const a = applied.get(f)!; a.v *= DUPLICATE_FACTOR; a.note.push(`counted at ${DUPLICATE_FACTOR * 100}% (same evidence as "${g[0].title}", group ${k})`); } });
  };
  dedupe(regular); dedupe(corr);

  const capGroups = new Map<string, RuleFinding[]>();
  for (const f of regular) if (f.capGroup && CAPS[f.capGroup] !== undefined) capGroups.set(f.capGroup, [...(capGroups.get(f.capGroup) ?? []), f]);
  for (const [g, list] of capGroups) {
    let used = 0;
    for (const f of list.sort((a, b) => applied.get(b)!.v - applied.get(a)!.v)) {
      const a = applied.get(f)!; const room = Math.max(0, CAPS[g] - used);
      if (a.v > room) { a.note.push(`limited by the ${g} cap (${CAPS[g]})`); a.v = room; }
      used += a.v;
    }
  }
  if (execLike) for (const f of regular) if (!f.base) { const a = applied.get(f)!; if (a.v > 0) { a.v *= EXEC_MULTIPLIER; a.note.push(`x${EXEC_MULTIPLIER} (executable/script file)`); } }

  const ordered = regular.slice().sort((a, b) => applied.get(b)!.v - applied.get(a)!.v);
  let total = 0;
  const points = new Map<RuleFinding, number>();
  ordered.forEach((f, i) => { const a = applied.get(f)!; const p = a.v * Math.pow(DECAY, i); points.set(f, p); total += p; if (i > 0 && DECAY < 1) a.note.push(`diminishing returns x${r1(Math.pow(DECAY, i))}`); });

  let corrSum = corr.reduce((s, f) => s + applied.get(f)!.v, 0); let corrScale = 1;
  if (corrSum > CORRELATION_CAP) { corrScale = CORRELATION_CAP / corrSum; notes.push(`Correlation bonus limited to ${CORRELATION_CAP} points.`); corrSum = CORRELATION_CAP; }
  for (const f of corr) points.set(f, applied.get(f)!.v * corrScale);

  const cats = new Set(regular.filter((f) => !f.base && applied.get(f)!.v >= 5).map((f) => f.category));
  const breadth = cats.size >= 5 ? BREADTH_BONUS[5] : BREADTH_BONUS[cats.size] ?? 0;
  if (breadth) notes.push(`+${breadth}: independent evidence in ${cats.size} categories (${[...cats].join(', ')}).`);

  const raw = total + corrSum + breadth; const final = Math.max(0, Math.min(100, Math.round(raw)));
  if (raw > 100) notes.push('Raw total exceeded 100 and was capped.');
  const scored: Scored[] = findings.map((f) => ({ finding: f, points: r1(points.get(f) ?? 0) }));
  const contributions: ScoreContribution[] = findings.filter((f) => f.weight > 0).map((f) => ({ indicatorId: f.ruleId, title: f.title, category: f.category, weight: f.weight, applied: r1(points.get(f) ?? 0), note: applied.get(f)!.note.join('; ') || undefined }));
  return { scored, breakdown: { contributions, correlationBonus: r1(corrSum), breadthBonus: breadth, rawScore: r1(raw), finalScore: final, notes } };
}

export const scoreToStatus = (s: number): ThreatStatus => (s >= THRESHOLDS.CRITICAL ? 'CRITICAL' : s >= THRESHOLDS.HIGH_RISK ? 'HIGH_RISK' : s >= THRESHOLDS.SUSPICIOUS ? 'SUSPICIOUS' : s >= THRESHOLDS.LOW_RISK ? 'LOW_RISK' : 'SAFE');

/**
 * Severity guards stop accumulation of weak signals from producing alarming verdicts:
 * HIGH_RISK needs at least one HIGH indicator, CRITICAL needs two HIGH indicators (or one CRITICAL), otherwise the score is capped at the band below.
 */
export function applyGuards(score: number, severities: ThreatSeverity[], notes: string[]): number {
  const high = severities.filter((s) => RANK[s] >= RANK.HIGH).length; const crit = severities.filter((s) => s === 'CRITICAL').length;
  if (score >= THRESHOLDS.CRITICAL && high < 2 && crit < 1) { notes.push(`Score capped at ${THRESHOLDS.CRITICAL - 1}: CRITICAL requires at least two HIGH indicators.`); score = THRESHOLDS.CRITICAL - 1; }
  if (score >= THRESHOLDS.HIGH_RISK && high < 1) { notes.push(`Score capped at ${THRESHOLDS.HIGH_RISK - 1}: HIGH_RISK requires at least one HIGH indicator.`); score = THRESHOLDS.HIGH_RISK - 1; }
  return score;
}
