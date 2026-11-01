import type { RuleFinding, ThreatSeverity } from '../types';
import { EXECUTABLE_EXTENSIONS, SCRIPT_EXTENSIONS } from '../../analysis/extensions';

export const EXEC_EXT = new Set(EXECUTABLE_EXTENSIONS);
export const SCRIPT_EXT = new Set(SCRIPT_EXTENSIONS);
export const clip = (s: string, n = 140): string => s.replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
export const list = (xs: string[], n = 3): string => `${xs.slice(0, n).map((x) => clip(x, 80)).join(', ')}${xs.length > n ? `, … (+${xs.length - n} more)` : ''}`;
export const sevOf = (w: number): ThreatSeverity => (w >= 75 ? 'CRITICAL' : w >= 45 ? 'HIGH' : w >= 14 ? 'MEDIUM' : w >= 4 ? 'LOW' : 'INFO');
/** Builds a finding with sensible defaults. */
export const F = (f: Omit<RuleFinding, 'severity' | 'source'> & { severity?: ThreatSeverity; source?: RuleFinding['source'] }): RuleFinding => ({ severity: sevOf(f.weight), source: 'STATIC_ANALYSIS', ...f });
export const baseName = (p: string): string => p.split(/[\\/]/).pop() ?? p;
export const extOfName = (n: string): string => { const b = baseName(n); const i = b.lastIndexOf('.'); return i > 0 && i < b.length - 1 ? b.slice(i + 1).trim().toLowerCase() : ''; };
