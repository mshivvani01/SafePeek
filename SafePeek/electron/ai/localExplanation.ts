import type { ThreatAssessment, ThreatCategory, ThreatIndicator, ThreatStatus } from '../threat/types';
import type { ThreatExplanation } from './types';

/**
 * Deterministic, offline explanation built ONLY from the Phase 5 assessment (indicators, reasons, evidence, coverage, recommendations).
 * Sentences are fixed templates keyed by rule id / category; they restate what a rule reported and never add facts
 * (no malware family names, no attacker attribution, no behaviour that was not observed, no reputation or antivirus claims).
 */

const SUMMARY: Record<ThreatStatus, string> = {
  SAFE: 'SafePeek did not detect suspicious indicators in this file based on the available static and content analysis. This is not a guarantee that the file is safe.',
  LOW_RISK: 'SafePeek found only minor warning signs in this file based on the available static and content analysis.',
  SUSPICIOUS: 'SafePeek found warning signs in this file that deserve a closer look before you open it.',
  HIGH_RISK: 'This file is considered high risk based on the available static and content analysis.',
  CRITICAL: "SafePeek's threat engine detected multiple serious indicators associated with malicious files.",
  UNKNOWN: 'SafePeek could not fully analyze this file, so its risk could not be determined.'
};
const ACTION: Record<ThreatStatus, string> = {
  SAFE: 'No action is suggested. As with any file, only open files from sources you trust.',
  LOW_RISK: 'Review the notes above. If you do not recognise the source of this file, treat it with caution before opening it.',
  SUSPICIOUS: 'Review the findings before opening. If you cannot confirm the sender through a channel you already trust, do not open it.',
  HIGH_RISK: 'Do not open this file. Quarantine it unless you are certain you trust the source.',
  CRITICAL: 'Do not open this file. Quarantine it unless you are certain you trust the source.',
  UNKNOWN: 'Because the analysis is incomplete, treat the file with caution. Try Rescan; if it still cannot be analyzed, only open it if you trust where it came from.'
};

/** What a rule reported, in plain words. Only rules listed here are re-worded; every other indicator uses Phase 5's own title. */
const SIMPLE: Record<string, string> = {
  FILE_DOUBLE_EXTENSION: 'The file name uses a double extension, a pattern commonly used to disguise executable or script files.',
  FILE_TYPE_MISMATCH: 'The actual contents of the file do not match the type its name suggests.',
  FILE_EXEC_DISGUISED: 'The file is named like a different type of file, but its contents indicate an executable program.',
  FILE_EXEC_AS_SCRIPT: 'The file has a script-style extension but its contents indicate an executable program.',
  FILE_SCRIPT_DISGUISED: 'The file is named like a document, but its contents look like script code.',
  FILE_ARCHIVE_DISGUISED: 'The file is named like one type of file, but its contents are an archive.',
  FILE_EXT_CLAIMS_EXEC: 'The file name claims an executable type, but its contents are something different.',
  FILE_LURE_NAME: 'The file name looks like an ordinary document while the file itself is an executable or disguised file.',
  FILE_BIDI_NAME: 'The file name contains hidden direction-control characters, which can make a name read differently than it really is.',
  EXEC_FILE: 'The file is a Windows executable program.',
  SCRIPT_FILE: 'The file is a script that can run commands when launched.',
  SCRIPT_DOWNLOAD_EXEC: 'The script text contains commands that download content and then run it.',
  PDF_JAVASCRIPT: 'The PDF contains JavaScript.',
  PDF_OPENACTION: 'The PDF is set up to perform an action automatically when it is opened.',
  PDF_LAUNCH: 'The PDF contains a Launch action, which can start other programs.',
  PDF_EMBEDDED_FILES: 'The PDF contains embedded files.',
  OFFICE_MACROS: 'The Office document contains macros.',
  OFFICE_REMOTE_TEMPLATE: 'The Office document is set up to load a template from a remote location.',
  CORR_MACRO_ENABLE_LURE: 'The document contains macros and its text asks you to enable content.',
  CONTENT_ENABLE_PROMPT: 'The text asks you to enable macros or content.',
  CONTENT_CREDENTIAL_REQUEST: 'The text asks you to provide or confirm account credentials.',
  CONTENT_URGENT_CREDENTIALS: 'The text urgently asks you to verify or enter account details.',
  CONTENT_OTP_REQUEST: 'The text asks you to share a one-time code.',
  CONTENT_URGENCY: 'The text uses pressure or urgency language.',
  CORR_CREDENTIAL_LURE_URL: 'The text asks for account credentials and includes an external link that SafePeek flagged as suspicious.',
  CORR_SCAM_LURE_URL: 'The text contains scam-like wording and points you to an external link.',
  CORR_URGENT_ORG_URL: 'The text is urgent, names an organization, and includes a link that SafePeek flagged as suspicious.',
  CONTENT_PRIZE_FEE: 'The text mentions a prize or winnings together with a payment request.',
  CONTENT_ADVANCE_FEE: 'The text asks for an upfront payment in exchange for a promised benefit.',
  CONTENT_REFUND_BANK: 'The text offers a refund while asking for bank details.',
  CONTENT_INVOICE_URGENT: 'The text presents an invoice together with urgent payment pressure.',
  CONTENT_UNTRACEABLE_PAYMENT: 'The text mentions gift cards, crypto or wire services as a way to pay.',
  CONTENT_IMPERSONATION: 'The text claims to come from an organization while pressuring for details or money.',
  CONTENT_SALARY_CREDENTIAL: 'The text uses a salary or payroll theme together with a credential request.',
  HTML_PASSWORD_FORM: 'The HTML file contains a password form.',
  HTML_FORM_EXTERNAL: 'The HTML file contains a password form that submits to an external site.',
  ARCHIVE_EXECUTABLES: 'The archive contains executable files.',
  ARCHIVE_SCRIPTS: 'The archive contains script files.',
  ARCHIVE_DOUBLE_EXT: 'The archive contains a file with a double extension.',
  ARCHIVE_DOC_PLUS_EXEC: 'The archive bundles documents together with an executable.',
  ARCHIVE_PATH_TRAVERSAL: 'The archive contains entries with unsafe paths that could write outside their folder when extracted.',
  ARCHIVE_ENCRYPTED: 'The archive contains password-protected entries, so SafePeek could not inspect them.'
};
/** One generic, true statement about why a category of finding matters. Only added when that category actually appears. */
const MATTERS: Partial<Record<ThreatCategory, string>> = {
  FILE_TYPE_MISMATCH: 'A file that pretends to be a different type can trick you into running it.',
  SOCIAL_ENGINEERING: 'Disguised names and pressure wording are tactics used to make people open files they would otherwise avoid.',
  PHISHING: 'Requests to verify an account combined with an external link are a common phishing pattern.',
  CREDENTIAL_THEFT: 'Requests for credentials or one-time codes can lead to account takeover if you comply.',
  FINANCIAL_FRAUD: 'Wording about prizes, refunds, fees or untraceable payments is common in payment scams.',
  SCAM: 'Prize or winner language is a common feature of scams.',
  MALWARE: 'Behaviour such as downloading and then running content is associated with malicious files.',
  SUSPICIOUS_EXECUTABLE: 'Executable programs can change your system when run, so they should only come from sources you trust.',
  SUSPICIOUS_SCRIPT: 'Scripts can run commands on your device when launched.',
  EXECUTION_RISK: 'Features that run actions automatically can start code without you noticing.',
  MACRO_RISK: 'Macros in documents can run code when you enable them.',
  SUSPICIOUS_DOCUMENT: 'Active or embedded content in a document goes beyond ordinary text and images.',
  ARCHIVE_RISK: 'Archives can hide executable content inside what looks like a single harmless download.',
  OBFUSCATION: 'Obfuscation makes content harder to inspect and is used to hide what a file really does.',
  MALICIOUS_URL: 'Links in files can lead to look-alike or unwanted websites.'
};

const humanCategory = (c: string) => c.toLowerCase().replace(/_/g, ' ');

const STATUSES = new Set(['SAFE', 'LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK', 'CRITICAL', 'UNKNOWN']);
/** Stored assessments are read from disk, so they are treated as untrusted data: wrong types fall back to the cautious 'UNKNOWN / incomplete' reading and never throw. */
export function coerceAssessment(x: unknown): ThreatAssessment {
  const o = (typeof x === 'object' && x !== null ? x : {}) as Partial<ThreatAssessment>;
  const arr = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
  const valid = typeof o.status === 'string' && STATUSES.has(o.status);
  const indicators = arr<ThreatIndicator>(o.indicators).filter((i) => i && typeof i.title === 'string' && typeof i.ruleId === 'string').map((i) => ({ ...i, severity: i.severity ?? 'LOW', category: i.category ?? 'UNKNOWN', source: typeof i.source === 'string' ? i.source : 'METADATA', points: Number.isFinite(i.points) ? i.points : 0 }));
  const cov = (typeof o.coverage === 'object' && o.coverage ? o.coverage : { static: 'PENDING', content: 'PENDING', threat: 'INCOMPLETE', notes: [] }) as ThreatAssessment['coverage'];
  return {
    ...(o as ThreatAssessment), status: valid ? (o.status as ThreatStatus) : 'UNKNOWN', score: Number.isFinite(o.score) ? Math.max(0, Math.min(100, Math.round(o.score as number))) : 0,
    confidence: Number.isFinite(o.confidence) ? (o.confidence as number) : 0, confidenceLevel: o.confidenceLevel === 'HIGH' || o.confidenceLevel === 'MEDIUM' ? o.confidenceLevel : 'LOW',
    analysisComplete: valid && o.analysisComplete === true, indicators, categories: arr<ThreatCategory>(o.categories).filter((c) => typeof c === 'string'), reasons: arr(o.reasons), evidence: arr(o.evidence), recommendations: arr(o.recommendations),
    coverage: { ...cov, notes: arr<string>(cov.notes).filter((n) => typeof n === 'string') }, engineVersion: typeof o.engineVersion === 'string' ? o.engineVersion : 'unknown', fileName: typeof o.fileName === 'string' ? o.fileName : '', analyzedAt: typeof o.analyzedAt === 'string' ? o.analyzedAt : ''
  };
}

export function buildLocalExplanation(input: ThreatAssessment, now: string = new Date().toISOString()): ThreatExplanation {
  const a = coerceAssessment(input);
  const real = a.indicators.filter((i) => i.severity !== 'INFO');
  const top = real.slice(0, 8);
  const found: string[] = top.map((i) => SIMPLE[i.ruleId] ?? i.title);
  if (real.length > top.length) found.push(`${real.length - top.length} additional lower-ranked indicator${real.length - top.length === 1 ? '' : 's'} (see the technical view).`);
  if (!real.length && a.status !== 'UNKNOWN') found.push('No suspicious indicators were reported by the available analysis.');
  if (!a.analysisComplete) found.push('Part of the file could not be fully inspected, so the result may miss indicators.');

  const why: string[] = []; const seen = new Set<string>();
  for (const c of a.categories) { const m = MATTERS[c]; if (m && !seen.has(m)) { seen.add(m); why.push(m); } if (why.length >= 4) break; }
  if (a.status === 'UNKNOWN') why.push('When a file cannot be fully analyzed, SafePeek cannot rule out hidden risks.');
  if (!why.length && a.status === 'SAFE') why.push('Nothing in the available analysis suggested a specific concern.');

  const summary = a.status === 'UNKNOWN' || !a.categories.length || a.status === 'SAFE' ? SUMMARY[a.status]
    : `${SUMMARY[a.status]} Main concern${a.categories.slice(0, 3).length > 1 ? 's' : ''}: ${a.categories.slice(0, 3).map(humanCategory).join(', ')}.`;

  const byInd = (i: ThreatIndicator) => `${i.severity} · ${i.title} (${i.category}, source: ${i.source.toLowerCase().replace(/_/g, ' ')}, +${i.points})${i.evidence ? ` — evidence: ${i.evidence}` : ''}`;
  const tech: string[] = [
    `Threat status: ${a.status}; heuristic risk score ${a.score}/100 (not a probability of malware); engine v${a.engineVersion}.`,
    `Coverage — static: ${a.coverage.static}; content: ${a.coverage.content}; threat: ${a.coverage.threat}.`,
    ...real.map(byInd), ...a.coverage.notes.map((n) => `Coverage note: ${n}`)
  ];
  const conf = `Confidence ${a.confidence}% (${a.confidenceLevel.toLowerCase()}) describes how complete the analysis was, not how risky the file is.${a.analysisComplete ? '' : ' The analysis was incomplete.'}`;
  return { summary, whatWasFound: found, whyItMatters: why, recommendedAction: ACTION[a.status], technicalDetails: tech, confidenceExplanation: conf, generatedBy: 'LOCAL_RULE_ENGINE', generatedAt: now };
}
