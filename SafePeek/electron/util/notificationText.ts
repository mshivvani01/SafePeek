import { cleanDisplayName } from './displayName';

/** Pure text builders for Windows notifications (kept free of the electron import so they are unit-testable). Title is always "SafePeek"; the body says what happened and which file. */
interface AlertLike { severity: string; fileName: string; score: number; actionTaken?: string | null }

const LEAD: Record<string, string> = { CRITICAL: 'Critical-risk file detected', HIGH: 'High-risk file detected', WARNING: 'Suspicious file detected', INFO: 'Minor warning signs in a file' };

export function alertNotificationText(a: AlertLike): { title: string; body: string } {
  const quarantined = typeof a.actionTaken === 'string' && a.actionTaken.startsWith('Auto');
  return { title: 'SafePeek', body: `${LEAD[a.severity] ?? LEAD.INFO}\n${cleanDisplayName(a.fileName)}\nRisk score ${a.score}/100 · ${quarantined ? 'Moved to quarantine.' : 'Open SafePeek to review.'}` };
}
export function detectionNotificationText(name: string, kind: 'new' | 'modified'): { title: string; body: string } {
  return { title: 'SafePeek', body: `${kind === 'new' ? 'New file detected' : 'File changed'} · analysis starting\n${cleanDisplayName(name)}` };
}
