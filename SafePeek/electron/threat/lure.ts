import type { PhraseHit } from './types';

/**
 * Deterministic phrase library for phishing / scam / social-engineering language. Patterns run on lower-cased, whitespace-normalized text.
 * A single phrase proves nothing (legitimate letters say "urgent" and "bank account"); rules combine groups and apply negation checks.
 */
interface P { group: string; id: string; label: string; re: RegExp }
const P = (group: string, id: string, label: string, re: RegExp): P => ({ group, id, label, re });
const MONEY = '(?:₹|rs\\.?|inr|\\$|usd|eur|€|£)\\s?\\d[\\d,]*';

export const PATTERNS: P[] = [
  // urgency / threat
  P('urgency', 'u_urgent', 'urgent', /\burgent(?:ly)?\b/), P('urgency', 'u_immediately', 'immediately', /\b(?:immediately|right away|without delay)\b/),
  P('urgency', 'u_actnow', 'act now', /\bact (?:now|fast|quickly)\b/),
  P('urgency', 'u_deadline', 'short deadline', /\bwithin\s+(?:(?:\d{1,2}|one|two)\s*(?:hours?|hrs?)|24 hours|48 hours|72 hours|(?:1|one|2|two) days?)\b/),
  P('urgency', 'u_final', 'final warning', /\b(?:final (?:warning|notice|reminder|chance)|last chance)\b/),
  P('urgency', 'u_closure', 'account closure threat', /\b(?:account|access|card|mailbox|profile|wallet)\b[^.\n]{0,40}\b(?:will be|has been|is being|shall be|may be)\s+(?:closed|suspended|blocked|locked|terminated|deactivated|disabled|restricted)\b|\b(?:suspend|terminate|deactivate|block)(?:ed|ion)? (?:of )?your (?:account|access|card)\b/),
  P('urgency', 'u_expire', 'expires soon', /\b(?:expires?|expiring)\s+(?:today|tonight|soon|in\s+\d+\s*(?:hours?|minutes?))\b/),
  P('urgency', 'u_consequence', 'penalty threat', /\bfailure to (?:comply|respond|verify|act)\b|\bavoid (?:suspension|penalt(?:y|ies)|closure|legal action)\b|\blegal action will be taken\b/),
  // credential requests
  P('credential', 'c_verify', 'verify your account/password', /\bverify (?:your|the) (?:password|account|identity|email|details|information|login|credentials|bank|card)\b/),
  P('credential', 'c_confirm', 'confirm your account/details', /\bconfirm (?:your|the) (?:password|account|identity|details|credentials|login|bank|card|information)\b/),
  P('credential', 'c_login', 'log in immediately / to verify', /\b(?:log ?in|sign ?in)\s+(?:immediately|now|here|to (?:verify|confirm|restore|secure|unlock|avoid|keep|continue))\b/),
  P('credential', 'c_enter', 'enter/provide your credentials', /\b(?:enter|provide|submit|send|share|reply with|type)\s+(?:us\s+)?your (?:credentials|password|username|login|otp|pin|passcode|ssn|card number|cvv|account number|bank details|aadhaar|pan)\b/),
  P('credential', 'c_update', 'update your password/payment details', /\bupdate your (?:password|payment|billing|bank|card|account|login|security)(?: details| information| info)?\b/),
  P('credential', 'c_otp', 'share one-time code', /\b(?:share|send|tell|give|enter|provide|reply with)\b[^.\n]{0,30}\b(?:otp|one[- ]time (?:password|passcode|code)|verification code)\b/),
  P('credential', 'c_card', 'card / PIN details', /\b(?:card number|cvv|cvc|card verification|expiry date|atm pin|net ?banking (?:id|password))\b/),
  P('credential', 'c_alert', 'security alert wording', /\bsecurity alert\b|\bunusual (?:sign[- ]?in|activity|login)\b|\bsuspicious (?:activity|login|sign[- ]?in)\b/),
  P('credential', 'c_verifynow', 'verify now / verify identity', /\bverify (?:now|immediately|today)\b|\bverify (?:your )?identity\b|\b(?:account|identity) verification\b/),
  P('credential', 'c_kyc', 'KYC update request', /\bkyc\b[^.\n]{0,40}\b(?:update|expire[sd]?|pending|verify|incomplete)/),
  // financial requests
  P('financial', 'f_payment', 'payment required', /\bpayment (?:is )?(?:required|due|pending|needed|overdue)\b|\bpay (?:the |a |an )?(?:small |nominal |one[- ]time )?(?:fee|amount|charges?|deposit)\b/),
  P('financial', 'f_send', 'send/transfer money', /\b(?:send|transfer|wire|deposit|remit) (?:the )?(?:money|funds|amount|payment|cash)\b|\bwire transfer\b|\btransfer funds\b/),
  P('financial', 'f_bank', 'bank account details', /\bbank (?:account|details|transfer)(?: number| no\.?)?\b|\baccount number\b|\bifsc\b|\biban\b|\bswift code\b/),
  P('financial', 'f_card', 'credit/debit card', /\b(?:credit|debit) card\b/),
  P('financial', 'f_fee', 'advance fee', /\b(?:processing|registration|clearance|handling|administration|admin|activation|verification|release|insurance|customs|delivery|security|advance|training|kit|documentation|booking|refundable) (?:fees?|charges?|deposit)\b/),
  P('financial', 'f_giftcard', 'gift card / crypto / wire service', /\bgift cards?\b|\bbitcoin\b|\bcrypto(?:currency)? wallet\b|\busdt\b|\bwestern union\b|\bmoneygram\b/),
  P('financial', 'f_upi', 'UPI / wallet payment request', /\b(?:upi|gpay|google pay|phonepe|paytm)\b[^.\n]{0,40}\b(?:id|number|pay|send|transfer)/),
  P('financial', 'f_amount', 'asks to pay an amount', new RegExp(`\\b(?:pay|send|transfer|deposit|remit)\\b[^.\\n]{0,25}${MONEY}`)),
  P('financial', 'f_askbank', 'asks for bank details', /\b(?:provide|send|share|enter|submit|confirm|reply with)\b[^.\n]{0,40}\b(?:bank|account|card)\b/),
  // prize / reward
  P('prize', 'p_won', 'you won / winner', /\byou (?:have |'ve )?(?:won|been selected as (?:a |the )?winner)\b|\byou are (?:a|the) (?:lucky )?winner\b|\bwinner\b/),
  P('prize', 'p_congrats', 'congratulations', /\bcongratulations\b/), P('prize', 'p_claim', 'claim your prize', /\bclaim (?:your|the) (?:prize|reward|gift|winnings|cash|bonus)\b/),
  P('prize', 'p_lottery', 'lottery / lucky draw', /\blottery\b|\blucky draw\b|\bsweepstakes?\b|\bjackpot\b/), P('prize', 'p_reward', 'reward / cashback', /\b(?:reward|cashback|free gift|prize money)\b/),
  // impersonation (weak on their own)
  P('impersonation', 'i_hr', 'HR department', /\b(?:hr|human resources) (?:department|team|desk|manager)\b/),
  P('impersonation', 'i_bank', 'bank / payment brand', /\b(?:your bank|sbi|hdfc|icici|axis bank|paypal|visa|mastercard)\b/),
  P('impersonation', 'i_gov', 'government / tax authority', /\b(?:government|income tax|tax department|irs|hmrc|customs|revenue (?:service|department)|police|cyber ?crime|ministry|court)\b/),
  P('impersonation', 'i_tech', 'well-known company', /\b(?:microsoft|google|amazon|apple|netflix|facebook|linkedin|whatsapp|office ?365|outlook|onedrive|dropbox|docusign|dhl|fedex|india post|ebay)\b/),
  P('impersonation', 'i_edu', 'college / university', /\b(?:college|university|registrar|admissions?)\b/),
  P('impersonation', 'i_support', 'IT / customer support', /\b(?:it support|help ?desk|technical support|security team|customer (?:care|support|service)|system administrator)\b/),
  // topics used by themed lures
  P('topic', 't_invoice', 'invoice', /\binvoice\b/), P('topic', 't_refund', 'refund', /\brefund\b/), P('topic', 't_salary', 'salary / payroll', /\b(?:salary|payroll|bonus|increment)\b/),
  P('topic', 't_scholarship', 'scholarship', /\bscholarship\b/), P('topic', 't_job', 'job / internship offer', /\b(?:job offer|offer letter|internship|work from home|appointment letter|recruitment)\b/),
  // call-to-action (weak on its own; counted only in combination, see contentRules)
  P('action', 'a_click', 'click here / follow the link', /\bclick (?:here|the link|below|on the link|this link)\b|\bscan (?:the|this) (?:qr|code)\b[^.\n]{0,30}\b(?:verify|pay|login|log in|confirm|claim)\b|\bfollow (?:the|this) link\b/),
  // macro lure
  P('macroLure', 'm_enable', 'asks to enable macros/content', /\benable (?:the )?(?:macros?|content|editing)\b/)
];

const NEGATION = /\b(?:no|not|never|without|free of|nor|don'?t|do not|zero|nil)\s+(?:\w+\s+){0,2}$/;
export const normalize = (s: string): string => s.normalize('NFKC').replace(/[\u200b-\u200f\u2060\ufeff\u00ad]/g, '').replace(/[\u2018\u2019]/g, "'").replace(/\s+/g, ' ').toLowerCase();
const snip = (t: string, i: number, len: number) => t.slice(Math.max(0, i - 25), Math.min(t.length, i + len + 25)).replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '').trim();

export function analyzeLure(text: string) {
  const t = normalize(text.slice(0, 200_000));
  const hits: PhraseHit[] = [];
  for (const p of PATTERNS) {
    const re = new RegExp(p.re.source, 'g');
    for (const m of t.matchAll(re)) {
      const before = t.slice(Math.max(0, m.index! - 30), m.index!);
      if (p.group === 'financial' || p.group === 'prize') { if (NEGATION.test(before)) continue; }
      hits.push({ group: p.group, id: p.id, label: p.label, snippet: snip(t, m.index!, m[0].length) });
      break; // one hit per pattern is enough (we count DISTINCT phrases, not repetitions)
    }
  }
  const ids = new Set(hits.map((h) => h.id));
  return {
    hits, has: (id: string) => ids.has(id), count: (g: string) => hits.filter((h) => h.group === g).length,
    first: (g: string) => hits.find((h) => h.group === g), ids: (g: string) => hits.filter((h) => h.group === g).map((h) => h.id)
  };
}

/** Script-language sniffing for content that hides behind a non-script extension. Requires several signatures to limit false positives. */
const SCRIPT_SIGS: { kind: string; res: RegExp[] }[] = [
  { kind: 'PowerShell', res: [/\bparam\s*\(/i, /\bwrite-host\b/i, /\binvoke-(?:expression|webrequest|restmethod|command)\b/i, /\$erroractionpreference/i, /\bnew-object\b/i, /\bget-(?:childitem|content|process|item)\b/i, /\bset-executionpolicy\b/i, /\[system\.[a-z.]+\]::/i, /\bstart-process\b/i] },
  { kind: 'Batch', res: [/^\s*@echo off/im, /%~dp0/i, /\bcmd(?:\.exe)? \/c\b/i, /^\s*set \/p\b/im, /^\s*goto :?\w+/im, /^\s*if (?:not )?exist\b/im, /^\s*:\w+\s*$/im, /\bstart \/(?:min|b)\b/i] },
  { kind: 'VBScript', res: [/\bwscript\.\w+/i, /\bcreateobject\s*\(/i, /^\s*dim \w+/im, /on error resume next/i, /\bscripting\.filesystemobject\b/i, /\bmsgbox\b/i, /\bwscript\.shell\b/i] },
  { kind: 'JavaScript (Windows Script Host)', res: [/\bactivexobject\s*\(/i, /\bwscript\.\w+/i, /\bnew activexobject/i, /\bfunction\s+\w+\s*\(/, /\bvar\s+\w+\s*=/, /\bwindow\.location\b/, /\bdocument\.write\s*\(/, /\beval\s*\(/, /\bfromcharcode\b/i] },
  { kind: 'Shell script', res: [/^#!\s*\/(?:usr\/)?bin\/(?:env )?(?:ba|z|da)?sh/m, /\bchmod \+x\b/, /\bcurl\s+-[a-z]*\s/i, /\bwget\s+/i, /\|\s*(?:ba)?sh\b/] }
];
export function sniffScript(text: string, min = 2): string | null {
  const t = text.slice(0, 100_000);
  let best: { kind: string; n: number } | null = null;
  for (const s of SCRIPT_SIGS) { const n = s.res.filter((r) => r.test(t)).length; if (n >= min && (!best || n > best.n)) best = { kind: s.kind, n }; }
  return best?.kind ?? null;
}
