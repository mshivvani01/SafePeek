import type { PhraseHit, Rule, RuleContext, RuleFinding } from '../types';
import { F, clip } from './util';

const hasAny = (c: RuleContext, ids: string[]) => ids.some((i) => c.lure.has(i));
export const STRONG_CRED = ['c_verify', 'c_confirm', 'c_login', 'c_enter', 'c_update', 'c_otp', 'c_card', 'c_kyc'];
const PAYMENT_ASK = ['f_fee', 'f_payment', 'f_amount', 'f_send', 'f_giftcard', 'f_upi'];
const PRIZE_STRONG = ['p_won', 'p_claim', 'p_lottery'];
const ev = (hits: (PhraseHit | undefined)[]) => hits.filter(Boolean).map((h) => ({ type: 'phrase', description: (h as PhraseHit).label, value: `…${clip((h as PhraseHit).snippet, 100)}…` }));
const evStr = (hits: (PhraseHit | undefined)[]) => hits.filter(Boolean).map((h) => `"${clip((h as PhraseHit).snippet, 70)}"`).slice(0, 3).join(' · ');
const pick = (c: RuleContext, ids: string[]) => ids.map((i) => c.lure.hits.find((h) => h.id === i)).filter(Boolean) as PhraseHit[];

/** Phase 8: tags each finding with the extraction paths of the phrases it quotes (matched by snippet), so an explanation can say "OCR detected…". */
function withOrigins(c: RuleContext, fs: RuleFinding[]): RuleFinding[] {
  return fs.map((f) => {
    const hay = `${f.evidence ?? ''} ${(f.evidenceItems ?? []).map((e) => e.value ?? '').join(' ')}`;
    const hits = c.lure.hits.filter((h) => hay.includes(clip(h.snippet, 40)));
    const used = hits.length ? hits : c.lure.hits;
    const origins = [...new Set(used.flatMap((h) => h.origins ?? []))];
    return { ...f, origins: origins.length ? origins : undefined, evidenceItems: f.evidenceItems?.map((e) => { const h = hits.find((x) => (e.value ?? '').includes(clip(x.snippet, 40))); return h?.origins?.length ? { ...e, origin: h.origins[0] } : e; }) };
  });
}

/** Which lure conditions hold; shared by the content rules and the correlation rules so both agree. */
export function lureState(c: RuleContext) {
  const strong = STRONG_CRED.filter((i) => c.lure.has(i));
  const urgency = c.lure.count('urgency');
  const prizeStrong = hasAny(c, PRIZE_STRONG); const payAsk = hasAny(c, PAYMENT_ASK);
  const topicJobSch = c.lure.has('t_job') || c.lure.has('t_scholarship');
  const credLure = strong.length >= 1 && (urgency >= 1 || strong.length >= 2 || c.lure.has('c_enter') || c.lure.has('t_salary'));
  const prizeFee = prizeStrong && payAsk;
  const advFee = !prizeFee && topicJobSch && hasAny(c, ['f_fee', 'f_payment', 'f_amount', 'f_giftcard', 'f_upi']);
  const refundBank = c.lure.has('t_refund') && c.lure.has('f_askbank');
  const scam = prizeFee || advFee || refundBank;
  return { strong, urgency, prizeStrong, payAsk, credLure, prizeFee, advFee, refundBank, scam, org: c.lure.first('impersonation') };
}

/** Phishing / scam / social-engineering language. Weighted, combination-based, negation-aware; a single keyword never produces a high score. */
export const contentRules: Rule = (c) => withOrigins(c, contentRulesCore(c));
const contentRulesCore: Rule = (c) => {
  if (!c.rawText || c.isScript || c.isExecutable || c.lure.hits.length === 0) return [];
  const s = lureState(c); const out: RuleFinding[] = []; const CA = 'CONTENT_ANALYSIS' as const;
  const cred = pick(c, STRONG_CRED); const urg = c.lure.hits.filter((h) => h.group === 'urgency');
  if (s.strong.length && s.urgency >= 1) out.push(F({ ruleId: 'CONTENT_URGENT_CREDENTIALS', category: 'PHISHING', weight: 30, severity: 'MEDIUM', source: CA, title: 'Urgent request to verify or enter account details',
    description: 'The text asks the reader to verify, confirm or enter account details while pressuring them to act quickly. Urgency plus a credential request is the core pattern of phishing messages. Genuine notices can read similarly, so check the sender independently.',
    reason: 'Extracted content requests account verification with urgent language.', evidence: evStr([...cred.slice(0, 2), urg[0]]), dedupeKey: 'credential-lure', capGroup: 'content-lure', evidenceItems: ev([...cred.slice(0, 2), urg[0]]) }));
  else if (s.strong.length) {
    const sensitive = c.lure.has('c_enter') || c.lure.has('c_card');
    const w = sensitive ? 18 : s.strong.length >= 2 ? 14 : 5;
    out.push(F({ ruleId: 'CONTENT_CREDENTIAL_REQUEST', category: 'CREDENTIAL_THEFT', weight: w, source: CA, title: sensitive ? 'Text asks for credentials or card details' : 'Text asks the reader to verify account details',
      description: `${sensitive ? 'The text asks the reader to provide passwords, PINs or card details.' : 'The text refers to verifying/confirming account information.'} Documents that merely mention the word "password" are not flagged; this fires on request-style wording. Context decides whether it is legitimate.`,
      reason: 'Extracted content requests credentials or account verification.', evidence: evStr(cred.slice(0, 3)), dedupeKey: 'credential-lure', capGroup: 'content-lure', evidenceItems: ev(cred.slice(0, 3)) }));
  }
  if (c.lure.has('c_otp')) out.push(F({ ruleId: 'CONTENT_OTP_REQUEST', category: 'CREDENTIAL_THEFT', weight: 20, source: CA, title: 'Text asks the reader to share a one-time code', description: 'Asking someone to send or enter a one-time password is a standard account-takeover technique; real services tell users never to share them.', reason: 'Extracted content asks for a one-time code.', evidence: evStr(pick(c, ['c_otp'])), dedupeKey: 'credential-lure', capGroup: 'content-lure', evidenceItems: ev(pick(c, ['c_otp'])) }));
  if (c.lure.has('t_salary') && s.strong.length) out.push(F({ ruleId: 'CONTENT_SALARY_CREDENTIAL', category: 'PHISHING', weight: 28, source: CA, title: 'Salary / payroll theme combined with a credential request', description: 'Pay-related wording (salary, bonus, increment) together with a request to verify or enter account details is a common lure, because it makes people eager to comply.', reason: 'Salary-themed content requests account details.', evidence: evStr([c.lure.first('topic'), ...cred.slice(0, 1)]), dedupeKey: 'credential-lure', capGroup: 'content-lure' }));
  if (s.urgency >= 2) out.push(F({ ruleId: 'CONTENT_URGENCY', category: 'SOCIAL_ENGINEERING', weight: 5, source: CA, title: 'Pressure / urgency language', description: `${s.urgency} different urgency or threat phrases were found. Urgency alone is common in ordinary notices; it is a pressure tactic when combined with requests for money or credentials.`, reason: 'Extracted content uses urgent, threatening language.', evidence: evStr(urg.slice(0, 3)), dedupeKey: 'urgency', capGroup: 'content-lure', evidenceItems: ev(urg.slice(0, 3)) }));

  if (s.prizeFee) out.push(F({ ruleId: 'CONTENT_PRIZE_FEE', category: 'FINANCIAL_FRAUD', weight: 60, source: CA, title: 'Prize or winnings combined with a payment request', description: 'The text announces a prize, lottery or reward and asks for a fee or payment to receive it. Genuine prizes do not require advance payment; this is the standard advance-fee scam pattern.', reason: 'Extracted content promises a prize but asks for a payment or fee.', evidence: evStr([...pick(c, PRIZE_STRONG).slice(0, 1), ...pick(c, PAYMENT_ASK).slice(0, 2)]), dedupeKey: 'financial-scam', capGroup: 'content-lure', evidenceItems: ev([...pick(c, PRIZE_STRONG).slice(0, 1), ...pick(c, PAYMENT_ASK).slice(0, 2)]) }));
  else if (s.prizeStrong) out.push(F({ ruleId: 'CONTENT_PRIZE', category: 'SCAM', weight: 6, source: CA, title: 'Prize / winner language', description: 'The text uses prize or winner wording. On its own this is common (competitions, results) and is only a weak signal.', reason: 'Extracted content uses prize / winner wording.', evidence: evStr(pick(c, PRIZE_STRONG).slice(0, 2)), dedupeKey: 'financial-scam', capGroup: 'content-lure' }));
  if (s.advFee) out.push(F({ ruleId: 'CONTENT_ADVANCE_FEE', category: 'FINANCIAL_FRAUD', weight: 36, source: CA, title: `${c.lure.has('t_job') ? 'Job / internship offer' : 'Scholarship'} combined with a fee or payment request`, description: 'Offers of jobs, internships or scholarships that ask the recipient to pay a fee, deposit or processing charge are a widespread fraud pattern. Some genuine programs do charge enrolment fees, so verify directly with the organization.', reason: `Extracted content ties a ${c.lure.has('t_job') ? 'job/internship' : 'scholarship'} offer to a fee payment.`, evidence: evStr([c.lure.first('topic'), ...pick(c, PAYMENT_ASK).slice(0, 2)]), dedupeKey: 'financial-scam', capGroup: 'content-lure', evidenceItems: ev([c.lure.first('topic'), ...pick(c, PAYMENT_ASK).slice(0, 2)]) }));
  if (s.refundBank) out.push(F({ ruleId: 'CONTENT_REFUND_BANK', category: 'FINANCIAL_FRAUD', weight: 32, source: CA, title: 'Refund combined with a request for bank details', description: 'Refund notices that ask the reader to supply bank or card details are a common way to harvest financial information.', reason: 'Extracted content offers a refund and asks for bank details.', evidence: evStr(pick(c, ['t_refund', 'f_askbank'])), dedupeKey: 'financial-scam', capGroup: 'content-lure' }));
  if (c.lure.has('t_invoice') && s.urgency >= 1 && hasAny(c, ['f_payment', 'f_send', 'f_bank', 'f_amount'])) out.push(F({ ruleId: 'CONTENT_INVOICE_URGENT', category: 'FINANCIAL_FRAUD', weight: 22, source: CA, title: 'Invoice with urgent payment pressure', description: 'An invoice plus urgent wording and payment details matches business-email-compromise style fraud. Real overdue notices look similar, so confirm via a known contact.', reason: 'Extracted content is an invoice demanding urgent payment.', evidence: evStr([...pick(c, ['t_invoice']), urg[0], ...pick(c, ['f_payment', 'f_send', 'f_bank', 'f_amount']).slice(0, 1)]), dedupeKey: 'financial-scam', capGroup: 'content-lure' }));
  if (c.lure.has('f_giftcard') && !s.prizeFee) out.push(F({ ruleId: 'CONTENT_UNTRACEABLE_PAYMENT', category: 'FINANCIAL_FRAUD', weight: 18, source: CA, title: 'Mentions gift cards, crypto or wire services', description: 'Requests for payment through gift cards, cryptocurrency or wire services are hard to reverse and favored by scammers. The mention may also be innocent.', reason: 'Extracted content mentions hard-to-trace payment methods.', evidence: evStr(pick(c, ['f_giftcard'])), dedupeKey: 'financial-scam', capGroup: 'content-lure' }));
  if (s.org && (s.strong.length || hasAny(c, ['f_fee', 'f_askbank', 'f_giftcard'])) && s.urgency >= 1) out.push(F({ ruleId: 'CONTENT_IMPERSONATION', category: 'SOCIAL_ENGINEERING', weight: 22, source: CA, title: 'Claims to come from an organization while pressuring for details or money', description: `The text mentions ${s.org.label} while combining urgency with a request for credentials or payment. Impersonating banks, employers, authorities or well-known companies is how phishing gains trust. Naming an organization is normal; the combination is the signal.`, reason: `Extracted content invokes ${s.org.label} alongside urgent requests.`, evidence: evStr([s.org, urg[0]]), dedupeKey: 'impersonation', capGroup: 'content-lure', evidenceItems: ev([s.org, urg[0]]) }));
  if (c.lure.has('a_click') && (s.strong.length || s.urgency >= 1 || s.scam)) out.push(F({ ruleId: 'CONTENT_CLICK_LURE', category: 'PHISHING', weight: 6, source: CA, title: 'Call to action pushing the reader to follow a link or code', description: '"Click here" / "scan the code" wording appears together with urgency, credential or payment wording. On its own it is ordinary; combined with pressure it is how phishing steers readers to a fake page.', reason: 'The text pushes the reader to follow a link or scan a code while pressuring or asking for details.', evidence: evStr(pick(c, ['a_click'])), dedupeKey: 'click-lure', capGroup: 'content-lure', evidenceItems: ev(pick(c, ['a_click'])) }));
  return out;
};
