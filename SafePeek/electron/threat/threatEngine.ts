import { extractUrls, extractVisualUrls } from '../analysis/urls';
import { analyzeLure, sniffScript } from './lure';
import { applyGuards, scoreFindings, scoreToStatus, severityRank } from './scoring';
import { analyzeUrls, type UrlInput } from './urlAnalyzer';
import { archiveRules } from './rules/archiveRules';
import { contentRules } from './rules/contentRules';
import { htmlRules, officeRules, pdfRules } from './rules/documentRules';
import { executableRules, scriptContentRules } from './rules/executableRules';
import { fileRules } from './rules/fileRules';
import { socialEngineeringRules } from './rules/socialEngineeringRules';
import { urlRules } from './rules/urlRules';
import { visualRules } from './rules/visualRules';
import { EXEC_EXT, SCRIPT_EXT, F, clip, extOfName } from './rules/util';
import { ENGINE_VERSION, type EvidenceOrigin, type ContentCoverage, type Rule, type RuleContext, type RuleFinding, type StaticCoverage, type ThreatAssessment, type ThreatCategory, type ThreatCoverage, type ThreatEvidence, type ThreatIndicator, type ThreatInput, type ThreatReason, type ThreatRecommendation, type ThreatStatus } from './types';

export const DISCLAIMER = "SafePeek's threat engine is a heuristic static/content-based detection system. It does not guarantee malware detection and does not replace a full antivirus, behavioral sandbox, or endpoint security product. The score is a heuristic risk score, not a probability.";
/** Order matters only for display ties. Add new rule modules here. */
export const RULES: { name: string; run: Rule }[] = [
  { name: 'file', run: fileRules }, { name: 'executable', run: executableRules }, { name: 'script', run: scriptContentRules }, { name: 'pdf', run: pdfRules },
  { name: 'office', run: officeRules }, { name: 'html', run: htmlRules }, { name: 'archive', run: archiveRules }, { name: 'url', run: urlRules },
  { name: 'content', run: contentRules }, { name: 'social-engineering', run: socialEngineeringRules }, { name: 'visual', run: visualRules }
];

const DANGEROUS_QR_SCHEMES = new Set(['javascript', 'vbscript', 'data', 'file', 'ms-msdt', 'search-ms', 'ms-officecmd', 'smb']);
const originOfSource = (src: string): EvidenceOrigin => (/qr/i.test(src) ? 'QR' : /ocr/i.test(src) ? 'OCR' : /^(static|pdf|office)$/i.test(src) ? 'STATIC' : 'TEXT');

export function buildContext(input: ThreatInput): RuleContext {
  const a = input.analysis ?? null; const content = input.content ?? null;
  const typeId = a?.identity.detectedTypeId ?? 'unknown'; const ext = extOfName(input.fileName);
  // Phase 8: evidence arrives through several channels. Each channel is kept as its own segment so findings can say where they came from,
  // but the lure analysis runs ONCE over the combined text (distinct phrases are counted once, so the same phrase seen in the PDF text AND in an
  // image is one piece of evidence, not two).
  const ocr = (content?.ocrText ?? '').slice(0, 200_000);
  const direct = content?.extractorType === 'image' ? '' : (content?.extractedText ?? '').slice(0, 200_000);
  const qrCodes = content?.visual?.qrCodes ?? [];
  const qrText = qrCodes.filter((q) => q.kind === 'text' || q.kind === 'other-scheme' || q.kind === 'sms' || q.kind === 'email').map((q) => q.payload).join('\n');
  const segments: { origin: EvidenceOrigin; text: string }[] = [];
  if (direct.trim()) segments.push({ origin: 'TEXT', text: direct });
  if (ocr.trim()) segments.push({ origin: 'OCR', text: ocr });
  if (qrText.trim()) segments.push({ origin: 'QR', text: qrText });
  const rawText = segments.map((x) => x.text).join('\n\n').slice(0, 200_000);
  const textual = ['text', 'script', 'unknown'].includes(typeId) && !SCRIPT_EXT.has(ext) && !EXEC_EXT.has(ext);
  const scriptKind = textual && rawText ? sniffScript(rawText, a?.identity.typeMismatch ? 2 : 3) : null;
  const isExecutable = ['pe', 'dos-exe', 'elf'].includes(typeId);
  const isScript = !isExecutable && typeId !== 'html' && (typeId === 'script' || !!a?.script && a.identity.category === 'script' || (SCRIPT_EXT.has(ext) && ['text', 'script'].includes(typeId)) || scriptKind !== null) || ext === 'hta';
  const inputs: UrlInput[] = [];
  for (const l of content?.links ?? []) inputs.push({ url: l.url, text: l.text, source: l.source });
  for (const q of qrCodes) { // QR payloads are untrusted text: web addresses and risky URI schemes are analyzed; wifi:/tel:/mailto: are only displayed
    if (q.kind === 'url' && q.url) inputs.push({ url: q.url, source: 'QR code' });
    else if (q.kind === 'other-scheme' && q.scheme && DANGEROUS_QR_SCHEMES.has(q.scheme)) inputs.push({ url: q.payload, source: 'QR code' });
  }
  for (const u of a?.urls ?? []) inputs.push({ url: u, source: 'static' });
  for (const u of a?.pdf?.urls ?? []) inputs.push({ url: u, source: 'pdf' });
  for (const r of a?.office?.externalRelationships ?? []) if (/hyperlink/i.test(r.type)) inputs.push({ url: r.target, source: 'office' });
  for (const sg of segments) {
    if (sg.origin === 'TEXT') for (const u of extractUrls(sg.text, 100)) inputs.push({ url: u, source: 'text' });
    else for (const u of extractVisualUrls(sg.text, 100)) inputs.push({ url: u.url, source: sg.origin === 'QR' ? 'QR code' : 'OCR text' });
  }
  const urls = analyzeUrls(inputs, { scriptContext: isExecutable || isScript }).map((u) => ({ ...u, origin: originOfSource(u.source) }));

  const lure = analyzeLure(rawText);
  const lureOrigins = new Map<string, Set<EvidenceOrigin>>();
  if (segments.length > 1) for (const sg of segments) for (const h of analyzeLure(sg.text).hits) lureOrigins.set(h.id, (lureOrigins.get(h.id) ?? new Set()).add(sg.origin));
  for (const h of lure.hits) h.origins = [...(lureOrigins.get(h.id) ?? new Set<EvidenceOrigin>([segments.length === 1 ? segments[0].origin : 'COMBINED']))];

  const v = content?.visual;
  const visual = {
    ocrText: !!ocr.trim(), directText: !!direct.trim(), qrCount: qrCodes.length, qrWebCount: qrCodes.filter((q) => q.kind === 'url').length, ocrPages: v?.ocrPages.length ?? 0, imagesAnalyzed: v?.imagesAnalyzed ?? 0, pdfKind: v?.pdfKind,
    partial: !!v && (v.ocrStatus === 'PARTIAL' || v.ocrStatus === 'FAILED' || v.limitsHit.length > 0), qr: qrCodes.map((q) => ({ payload: q.payload, kind: q.kind, scheme: q.scheme, url: q.url }))
  };
  return {
    fileName: input.fileName, ext, analysis: a, content, typeId, typeLabel: a?.identity.detectedType ?? 'Unknown', category: a?.identity.category ?? 'unknown',
    isExecutable, isScript, rawText, urls, segments, visual, lure, scriptKind
  };
}

const defaultOrigins = (src: RuleFinding['source']): EvidenceOrigin[] => (src === 'ARCHIVE_ANALYSIS' ? ['ARCHIVE'] : src === 'CONTENT_ANALYSIS' ? ['TEXT'] : src === 'CORRELATION' ? ['COMBINED'] : ['STATIC']);

export function computeCoverage(input: ThreatInput): { coverage: ThreatCoverage; incomplete: boolean } {
  const a = input.analysis ?? null; const c = input.content ?? null; const notes: string[] = [];
  const st: StaticCoverage = !a ? 'PENDING' : a.status === 'failed' ? 'FAILED' : a.status === 'partial' ? 'PARTIAL' : 'COMPLETE';
  if (a && a.status !== 'complete') for (const r of a.partialReasons.slice(0, 4)) notes.push(`Static analysis: ${r}`);
  const cs = c?.status ?? input.contentStatus ?? 'NOT_STARTED';
  let ct: ContentCoverage;
  if (cs === 'COMPLETED') ct = c?.truncated ? 'TRUNCATED' : 'COMPLETE';
  else if (cs === 'PARTIAL') ct = c?.truncated ? 'TRUNCATED' : 'PARTIAL';
  else if (cs === 'UNSUPPORTED') ct = 'UNSUPPORTED'; else if (cs === 'FAILED') ct = 'FAILED'; else ct = 'PENDING';
  const expectedUnsupported = !!a && (['pe', 'dos-exe', 'elf', 'empty'].includes(a.identity.detectedTypeId));
  if (ct === 'UNSUPPORTED') notes.push(expectedUnsupported ? 'Content extraction is intentionally not performed for executables; only static structure was analyzed.' : `Content could not be read for this file type${c?.unsupportedReason ? `: ${c.unsupportedReason}` : ''}.`);
  if (ct === 'PARTIAL' || ct === 'TRUNCATED' || ct === 'FAILED') for (const w of (c?.extractionWarnings ?? []).slice(0, 3)) notes.push(`Content analysis: ${w}`);
  if (ct === 'TRUNCATED' && c?.truncationNote) notes.push(c.truncationNote);
  if (ct === 'PENDING') notes.push('Content analysis has not finished for this file.');
  if (c?.visual && (c.visual.ocrStatus === 'PARTIAL' || c.visual.ocrStatus === 'FAILED' || c.visual.ocrStatus === 'UNSUPPORTED' || c.visual.limitsHit.length)) notes.push('Some visual content could not be fully analyzed.');
  const incomplete = st !== 'COMPLETE' || ['PARTIAL', 'TRUNCATED', 'FAILED', 'PENDING'].includes(ct) || (ct === 'UNSUPPORTED' && !expectedUnsupported);
  return { coverage: { static: st, content: ct, threat: incomplete ? 'INCOMPLETE' : 'COMPLETE', notes }, incomplete };
}

function computeConfidence(input: ThreatInput, cov: ThreatCoverage, ruleErrors: number, ctx: RuleContext): number {
  let c = 95; const a = input.analysis; const content = input.content;
  if (cov.static === 'FAILED' || cov.static === 'PENDING') c -= 70; else if (cov.static === 'PARTIAL') c -= 15 + Math.min(10, (a?.partialReasons.length ?? 1) * 3);
  if (cov.content === 'PARTIAL') c -= 15; else if (cov.content === 'TRUNCATED') c -= 10; else if (cov.content === 'FAILED') c -= 30; else if (cov.content === 'PENDING') c -= 25;
  else if (cov.content === 'UNSUPPORTED') c -= ctx.isExecutable ? 12 : 22;
  if (ctx.isExecutable) c -= 8; // no behaviour, no signature verification, DLL-level imports only
  if (a?.pdf?.encrypted) c -= 15; if (a?.archive?.encryptedEntries) c -= 12; if (a?.pdf?.truncated) c -= 5; if (!a?.sha256) c -= 3;
  if (content?.ocrConfidence != null && content.ocrConfidence < 60) c -= 10;
  c -= ruleErrors * 10;
  return Math.max(5, Math.min(95, Math.round(c)));
}

const HEADLINE: Record<ThreatStatus, string> = {
  SAFE: 'No suspicious indicators detected (based on available static analysis)', LOW_RISK: 'Low risk based on available static analysis', SUSPICIOUS: 'Suspicious indicators detected',
  HIGH_RISK: 'High-risk indicators detected', CRITICAL: 'Multiple serious risk indicators detected', UNKNOWN: 'Analysis incomplete — risk could not be determined'
};

function recommend(status: ThreatStatus, cats: Set<ThreatCategory>, ctx: RuleContext, incomplete: boolean): ThreatRecommendation[] {
  const r: ThreatRecommendation[] = [];
  if (status === 'CRITICAL' || status === 'HIGH_RISK') {
    r.push({ action: 'DO_NOT_OPEN', title: 'Do not open this file', description: 'Several indicators point to a deceptive or harmful file. Do not open it, run it, enable macros or click links in it.' });
    r.push({ action: 'QUARANTINE', title: 'Consider isolating the file', description: 'Move it into SafePeek\'s quarantine folder if you do not recognize or trust the source. You can restore it later. SafePeek only moves a file when you choose Quarantine, or when you turn on automatic quarantine for CRITICAL files.' });
  } else if (status === 'SUSPICIOUS') {
    r.push({ action: 'REVIEW_CONTENT', title: 'Review before opening', description: 'Check the indicators below and confirm the file with the sender through a channel you already trust before opening it.' });
    r.push({ action: 'OPEN_WITH_CAUTION', title: 'If you must open it, take precautions', description: 'Do not enable macros or run programs from it, and do not enter passwords or payment details.' });
  } else if (status === 'LOW_RISK') r.push({ action: 'OPEN_WITH_CAUTION', title: 'Open with normal caution', description: 'Only minor or context-dependent indicators were found. Make sure you expect this file and trust its source.' });
  else if (status === 'UNKNOWN') {
    r.push({ action: 'REVIEW_CONTENT', title: 'Treat as unverified', description: 'SafePeek could not fully inspect this file, so the absence of findings is not reassuring. Confirm the source before opening it.' });
    r.push({ action: 'OPEN_WITH_CAUTION', title: 'Open only if you trust the source', description: 'Avoid enabling macros, running programs or entering information until you know the file is legitimate.' });
  } else r.push({ action: 'NO_ACTION', title: 'No action suggested by this analysis', description: 'No suspicious indicators were found in the available static analysis. This is not a guarantee: SafePeek cannot detect everything.' });
  if (cats.has('MACRO_RISK')) r.push({ action: 'DO_NOT_OPEN', title: 'Do not enable macros', description: 'Macros run only after you click "Enable". Leave them disabled unless you know exactly why this document needs them.' });
  if (ctx.isExecutable && status !== 'SAFE') r.push({ action: 'OPEN_WITH_CAUTION', title: 'Run programs only from sources you trust', description: 'Prefer downloading installers from the publisher\'s own website and compare the file hash with the one the publisher lists.' });
  if (cats.has('PHISHING') || cats.has('CREDENTIAL_THEFT')) r.push({ action: 'REVIEW_CONTENT', title: 'Do not enter credentials or follow links', description: 'If the message claims to be from your bank, employer or a service, contact them using a phone number or site you already know.' });
  if (incomplete && status !== 'UNKNOWN') r.push({ action: 'REVIEW_CONTENT', title: 'Analysis was incomplete', description: 'Parts of the file could not be inspected; there may be indicators SafePeek did not see.' });
  return r.slice(0, 5);
}

/** Pure, deterministic and synchronous: same input => same output (apart from analyzedAt). Never touches the file system, network or processes. */
export function assessThreat(input: ThreatInput): ThreatAssessment {
  const ctx = buildContext(input); const findings: RuleFinding[] = []; let ruleErrors = 0;
  for (const r of RULES) { try { findings.push(...r.run(ctx)); } catch { ruleErrors++; } }
  const { coverage, incomplete } = computeCoverage(input);
  if (ruleErrors) coverage.notes.push(`${ruleErrors} detection rule group(s) failed to run; results may be incomplete.`);
  const hasEvidence = findings.some((f) => f.weight > 0);
  if (incomplete || ruleErrors) {
    coverage.threat = 'INCOMPLETE';
    findings.push(F({ ruleId: 'COVERAGE_GAP', category: 'UNKNOWN', weight: 0, severity: 'INFO', source: 'METADATA', title: 'Analysis incomplete',
      description: `The file could not be fully inspected.${hasEvidence ? '' : ' No malicious indicators were detected in the available analysis.'} ${coverage.notes.slice(0, 2).join(' ')}`.trim(),
      reason: 'Part of the file could not be inspected, so the result may miss indicators.', evidence: `Static: ${coverage.static}; Content: ${coverage.content}` }));
  }
  const execLike = ctx.isExecutable || ctx.isScript;
  const { scored, breakdown } = scoreFindings(findings, execLike);
  let score = applyGuards(breakdown.finalScore, scored.filter((s) => s.finding.weight > 0 || s.finding.correlation).map((s) => s.finding.severity), breakdown.notes);
  breakdown.finalScore = score;
  let status = scoreToStatus(score);
  const noData = coverage.static === 'FAILED' || coverage.static === 'PENDING';
  if (noData || (incomplete && score < 20)) status = 'UNKNOWN';
  if (noData) score = 0;
  breakdown.finalScore = score;

  const indicators: ThreatIndicator[] = scored.map(({ finding: f, points }) => ({
    id: f.ruleId, ruleId: f.ruleId, category: f.category, severity: f.severity, title: f.title, description: f.description, evidence: f.evidence ? clip(f.evidence, 400) : undefined,
    source: f.source, points, correlated: !!f.correlation, origins: f.origins?.length ? [...new Set(f.origins)] : defaultOrigins(f.source)
  })).sort((x, y) => severityRank(y.severity) - severityRank(x.severity) || y.points - x.points || x.title.localeCompare(y.title));
  const byId = new Map(findings.map((f) => [f.ruleId, f]));

  const reasons: ThreatReason[] = []; const seen = new Set<string>();
  for (const i of indicators) {
    if (i.severity === 'INFO' && i.id !== 'COVERAGE_GAP') continue; const f = byId.get(i.id)!; const text = f.reason ?? f.title;
    if (seen.has(text)) continue; seen.add(text); reasons.push({ id: `reason:${i.id}`, text, severity: i.severity, category: i.category, indicatorIds: [i.id] });
    if (reasons.length >= 10) break;
  }
  const evidence: ThreatEvidence[] = [];
  for (const i of indicators) {
    const f = byId.get(i.id)!;
    if (f.evidenceItems?.length) for (const e of f.evidenceItems) evidence.push({ indicatorId: i.id, type: e.type, description: e.description, value: e.value, source: i.source, origin: e.origin ?? i.origins?.[0] });
    else if (i.evidence) evidence.push({ indicatorId: i.id, type: i.category.toLowerCase(), description: i.title, value: i.evidence, source: i.source, origin: i.origins?.[0] });
  }
  const catPts = new Map<ThreatCategory, number>();
  for (const i of indicators) if (i.severity !== 'INFO' && i.category !== 'UNKNOWN') catPts.set(i.category, (catPts.get(i.category) ?? 0) + i.points + 0.01);
  const categories = [...catPts.entries()].sort((a, b) => b[1] - a[1]).map(([c]) => c);

  const confidence = computeConfidence(input, coverage, ruleErrors, ctx);
  const limitations = [
    'Heuristic static and content analysis only: files were never run, opened in their native application, or extracted to disk.',
    'No antivirus signatures, behavioral sandbox, reputation lookup or cloud service is used; unknown or novel threats can be missed.',
    'Text rules are English-oriented keyword/phrase combinations and can produce false positives (legitimate notices) and false negatives (obfuscated or image-based text).',
    ...(ctx.isExecutable ? ['Digital signatures are not cryptographically verified and imports are checked at DLL level only; a signed or well-formed executable is not thereby trusted.'] : []),
    ...(ctx.visual.ocrText || ctx.visual.qrCount || input.content?.visual?.ocrStatus === 'FAILED' ? ['Text read from images (OCR) and QR codes is best-effort: OCR is not guaranteed to read every image, font, language or low-quality scan correctly, and image content SafePeek could not read is not assessed.'] : []),
    ...(ctx.urls.length ? ['URLs were analyzed as text only (never visited); a URL without findings is not proven safe.'] : []),
    ...coverage.notes
  ];
  const headline = noData ? 'The file could not be analyzed' : HEADLINE[status];
  return {
    version: 1, fileName: input.fileName, status, score, confidence, confidenceLevel: confidence >= 75 ? 'HIGH' : confidence >= 45 ? 'MEDIUM' : 'LOW', headline, analysisComplete: !incomplete && !ruleErrors,
    indicators, reasons, categories, evidence, recommendations: recommend(status, new Set(categories), ctx, incomplete), coverage, breakdown, limitations, disclaimer: DISCLAIMER,
    analyzedAt: input.now ?? new Date().toISOString(), engineVersion: ENGINE_VERSION, scoreKind: 'heuristic', executionPerformed: false, uploaded: false
  };
}
export const threatEngine = { evaluate: assessThreat };
