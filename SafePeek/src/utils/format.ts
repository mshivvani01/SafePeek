import type { RiskLevel } from '../types/threat';

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i === 0 ? n : n.toFixed(1)} ${u[i]}`;
}
export function formatDate(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
/**
 * Single source of truth for how risk is presented. Color is never the only signal: every level has a text label, an icon and a plain-language explanation.
 * Wording never claims a file is guaranteed safe: "Safe" only ever means "no suspicious indicators detected".
 */
export const RISK_META: Record<RiskLevel, { icon: string; label: string; tagline: string }> = {
  safe: { icon: '🟢', label: 'Safe', tagline: 'No suspicious indicators detected' },
  low: { icon: '🟡', label: 'Low risk', tagline: 'Minor indicators detected' },
  suspicious: { icon: '🟠', label: 'Suspicious', tagline: 'Review recommended' },
  high: { icon: '🔴', label: 'High risk', tagline: 'Do not open without verification' },
  critical: { icon: '⛔', label: 'Critical', tagline: 'Strong protection recommended' },
  unknown: { icon: '❔', label: 'Unknown', tagline: 'Not fully assessed yet' }
};
export const RISK_ORDER: RiskLevel[] = ['safe', 'low', 'suspicious', 'high', 'critical', 'unknown'];
export const riskLabel: Record<RiskLevel, string> = { safe: RISK_META.safe.label, low: RISK_META.low.label, suspicious: RISK_META.suspicious.label, high: RISK_META.high.label, critical: RISK_META.critical.label, unknown: RISK_META.unknown.label };
export const threatStatusLabel: Record<string, string> = { SAFE: 'Safe', LOW_RISK: 'Low risk', SUSPICIOUS: 'Suspicious', HIGH_RISK: 'High risk', CRITICAL: 'Critical', UNKNOWN: 'Unknown' };
export const threatStatusToRisk: Record<string, RiskLevel> = { SAFE: 'safe', LOW_RISK: 'low', SUSPICIOUS: 'suspicious', HIGH_RISK: 'high', CRITICAL: 'critical', UNKNOWN: 'unknown' };
export const categoryLabel = (c: string) => c.toLowerCase().replace(/_/g, ' ').replace(/^./, (x) => x.toUpperCase());
export const severityTone: Record<string, string> = { INFO: 'unknown', LOW: 'low', MEDIUM: 'suspicious', HIGH: 'high', CRITICAL: 'critical' };
export const coverageLabel: Record<string, string> = { COMPLETE: 'Complete', PARTIAL: 'Partial', TRUNCATED: 'Truncated', UNSUPPORTED: 'Not supported', FAILED: 'Failed', PENDING: 'Pending', INCOMPLETE: 'Incomplete' };
export const recommendationLabel: Record<string, string> = { DO_NOT_OPEN: 'Do not open', QUARANTINE: 'Consider isolating', REVIEW_CONTENT: 'Review first', OPEN_WITH_CAUTION: 'Open with caution', NO_ACTION: 'No action suggested' };
export function summarizeCounts(files: { riskLevel: RiskLevel }[], quarantined: number) {
  return {
    analyzed: files.length,
    safe: files.filter((f) => f.riskLevel === 'safe').length,
    suspicious: files.filter((f) => f.riskLevel === 'suspicious').length,
    high: files.filter((f) => f.riskLevel === 'high' || f.riskLevel === 'critical').length,
    quarantined
  };
}

export function relativeTime(iso: string, now = Date.now()): string {
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '—';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 30) return 'Just now';
  if (s < 3600) { const m = Math.max(1, Math.round(s / 60)); return `${m} minute${m === 1 ? '' : 's'} ago`; }
  if (s < 86400) { const h = Math.round(s / 3600); return `${h} hour${h === 1 ? '' : 's'} ago`; }
  return formatDate(iso);
}
export const typeLabel = (ext: string) => (ext ? `${ext.toUpperCase()} (by extension)` : 'No extension');
export const analysisLabel: Record<string, string> = { pending: 'Queued', analyzing: 'Analyzing…', complete: 'Analyzed', failed: 'Failed', 'not-started': 'Not started' };

export const contentLabel: Record<string, string> = { NOT_STARTED: 'Not started', QUEUED: 'Queued', ANALYZING: 'Analyzing…', COMPLETED: '✓ Complete', PARTIAL: '⚠ Partial', UNSUPPORTED: 'Not supported', FAILED: 'Failed' };
export const previewTypeLabel: Record<string, string> = { pdf: 'PDF', document: 'Document', spreadsheet: 'Spreadsheet', presentation: 'Presentation', image: 'Image', text: 'Text', archive: 'Archive', unsupported: 'Unsupported' };
export const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;

export const riskFromStatus = (s: string): RiskLevel => threatStatusToRisk[s] ?? 'unknown';
export const severityLabel: Record<string, string> = { INFO: 'INFORMATIONAL', WARNING: 'SUSPICIOUS', HIGH: 'HIGH RISK', CRITICAL: 'CRITICAL' };
export const severityRisk: Record<string, RiskLevel> = { INFO: 'low', WARNING: 'suspicious', HIGH: 'high', CRITICAL: 'critical' };
/** Hidden direction-control / control characters are removed from any file name shown in the UI (they can spoof extensions). */
export const cleanName = (s: string): string => String(s ?? '').replace(/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '');

/** Phase 8: where a piece of evidence came from. */
export const originLabel: Record<string, string> = { STATIC: 'Static analysis', TEXT: 'Document text', OCR: 'OCR (text read from an image)', QR: 'QR code', ARCHIVE: 'Archive analysis', COMBINED: 'Combined evidence' };
export const originText = (o?: string[]): string => (o && o.length ? o.map((x) => originLabel[x] ?? x).join(' + ') : '');
