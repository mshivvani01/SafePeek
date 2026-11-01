import type { Rule, RuleFinding } from '../types';
import { lureState } from './contentRules';
import { F, clip, list } from './util';

/** Correlation rules: the same story told by independent evidence (text + links, macros + "enable content", active PDF + lure). */
export const socialEngineeringRules: Rule = (c) => {
  const out: RuleFinding[] = []; const s = lureState(c);
  const bad = c.urls.filter((u) => u.suspicious).sort((a, b) => b.score - a.score);
  const why = (u: (typeof bad)[number]) => u.issues.slice(0, 3).map((i) => i.kind.toLowerCase().replace(/_/g, ' ')).join(', ');
  if (!c.isScript && !c.isExecutable && s.credLure && bad.length) {
    out.push(F({ ruleId: 'CORR_CREDENTIAL_LURE_URL', category: 'PHISHING', weight: 30, severity: 'HIGH', correlation: true, source: 'CORRELATION', title: 'Credential request alongside a suspicious link',
      description: `The text asks the reader to verify or enter account details, and the file also contains a suspicious link (${clip(bad[0].host || bad[0].url, 60)}: ${why(bad[0])}). Text and link reinforce each other, which is how phishing documents work. Nothing was opened.`,
      reason: 'Extracted content requests credentials and the file contains a suspicious link.', evidence: `${clip(bad[0].url, 100)} + credential wording`,
      evidenceItems: [{ type: 'url', description: 'Suspicious link', value: clip(bad[0].url, 120) }, { type: 'phrase', description: 'Credential wording', value: clip(c.lure.first('credential')?.snippet ?? '', 100) }] }));
  }
  if (!c.isScript && !c.isExecutable && s.scam && c.urls.length) out.push(F({ ruleId: 'CORR_SCAM_LURE_URL', category: 'FINANCIAL_FRAUD', weight: bad.length ? 14 : 8, correlation: true, source: 'CORRELATION', title: 'Scam-like text directs the reader to an external link', description: 'Prize, fee or refund wording appears together with a link the reader is expected to follow. The link was not opened and has no reputation data.', reason: 'Scam-like content comes with an external link.', evidence: list(c.urls.map((u) => u.url), 2) }));
  if (!c.isScript && !c.isExecutable && s.urgency >= 1 && bad.length && s.org && !s.credLure) out.push(F({ ruleId: 'CORR_URGENT_ORG_URL', category: 'SOCIAL_ENGINEERING', weight: 14, correlation: true, source: 'CORRELATION', title: 'Urgent message naming an organization with a suspicious link', description: 'Urgent wording, a named organization and a suspicious link appear together.', reason: 'Urgent content naming an organization comes with a suspicious link.', evidence: clip(bad[0].url, 100) }));
  const o = c.analysis?.office;
  if (c.lure.has('m_enable')) {
    if (o?.hasMacros || o?.macroEnabledType) out.push(F({ ruleId: 'CORR_MACRO_ENABLE_LURE', category: 'MACRO_RISK', weight: 26, correlation: true, source: 'CORRELATION', title: 'Macro document asks the reader to enable content', description: 'The document contains macros AND its text urges the reader to "enable macros/content". Macros do not run until enabled, so this instruction is the social-engineering step used to deliver macro malware.', reason: 'The macro-enabled document tells the reader to enable macros/content.', evidence: clip(c.lure.first('macroLure')?.snippet ?? 'enable content', 100) }));
    else if (!c.isScript) out.push(F({ ruleId: 'CONTENT_ENABLE_PROMPT', category: 'SOCIAL_ENGINEERING', weight: 6, source: 'CONTENT_ANALYSIS', title: 'Text asks the reader to enable macros/content', description: 'No macros were found, but the text still pushes the reader to enable content, a lure often shown in malicious documents.', reason: 'The document text pushes the reader to enable content.', evidence: clip(c.lure.first('macroLure')?.snippet ?? '', 100) }));
  }
  const p = c.analysis?.pdf;
  if (p && (p.hasJavaScript || p.hasOpenAction || p.hasLaunchAction) && (s.credLure || s.scam)) out.push(F({ ruleId: 'CORR_PDF_ACTIVE_LURE', category: 'SUSPICIOUS_DOCUMENT', weight: 14, correlation: true, source: 'CORRELATION', title: 'Active PDF features combined with lure wording', description: 'The PDF has script/automatic actions and its text contains credential or scam wording. Either alone is weak; together they are more notable.', reason: 'The PDF combines active features with phishing/scam wording.', evidence: p.suspiciousActions.slice(0, 2).join('; ') }));
  return out;
};
