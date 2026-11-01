import type { ThreatStatus } from '../threat/types';
import type { OpenDecision, SecuritySettings } from './types';

/**
 * Whether a file may be opened and whether the user must confirm first.
 *  - quarantined: never opened (restore first)
 *  - CRITICAL: always requires "Open Anyway" confirmation (not configurable)
 *  - HIGH_RISK: requires confirmation unless the user turned that setting off
 *  - SUSPICIOUS / UNKNOWN (incomplete analysis): requires confirmation
 *  - SAFE / LOW_RISK: opens normally
 * The service additionally refuses to open a file that changed since it was analyzed.
 */
export function decideOpen(status: ThreatStatus | undefined, quarantined: boolean, s: Pick<SecuritySettings, 'requireConfirmHighRisk'>, o: { executable?: boolean; pipelineBusy?: boolean } = {}): OpenDecision {
  if (quarantined) return { allowed: false, requiresConfirmation: false, blocked: 'Quarantined files cannot be opened. Restore the file first, if you are sure.', level: 'QUARANTINED', reasons: [] };
  // While the pipeline is still (re)analyzing the file, any earlier verdict is stale: treat it as UNKNOWN.
  const st: ThreatStatus = o.pipelineBusy ? 'UNKNOWN' : status ?? 'UNKNOWN';
  // Opening an executable/script through the shell RUNS it, so it always needs explicit confirmation, whatever the verdict.
  const requires = !!o.executable || st === 'CRITICAL' || st === 'SUSPICIOUS' || st === 'UNKNOWN' || (st === 'HIGH_RISK' && s.requireConfirmHighRisk);
  return { allowed: true, requiresConfirmation: requires, level: st, reasons: [], ...(o.pipelineBusy ? { note: 'SafePeek is still analyzing this file.' } : {}), ...(o.executable ? { executable: true } : {}) };
}
