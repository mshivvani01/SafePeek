import { cleanInline } from '../content/sanitizer';
import type { ThreatAssessment } from '../threat/types';

/** Validation of OPTIONAL external-AI output. AI text is an explanation only: it is length-limited, sanitized, checked against the Phase 5 result, and rejected when it makes claims SafePeek cannot support. */
export interface AiExplanationFields { summary: string; whatWasFound: string[]; whyItMatters: string[]; recommendedAction: string }
export type AiValidation = { ok: true; value: AiExplanationFields } | { ok: false; reason: string };

export const LIMITS = { RAW: 8000, SUMMARY: 600, ITEM: 300, ITEMS: 8, ACTION: 350 };
const FORBIDDEN: [RegExp, string][] = [
  [/virustotal|antivirus|anti-virus|av engines?|reputation (score|service)|sandbox (report|result)/i, 'claims about external detections or reputation'],
  [/\b(emotet|trickbot|wannacry|lockbit|qakbot|formbook|agent tesla|cobalt strike|mimikatz|ryuk|conti|redline|asyncrat|njrat|remcos|dridex|zeus|petya|notpetya)\b/i, 'malware family names'],
  [/\bAPT ?\d+\b|nation[- ]state|threat actor|attributed to|lazarus|fancy bear/i, 'attacker attribution'],
  [/\b(definitely|certainly|undoubtedly|100 ?%|guaranteed)\b[^.]{0,60}\b(malware|malicious|virus|ransomware|trojan|infected)\b/i, 'certainty claims'],
  [/\b(contains|is (a|an)) (malware|virus|ransomware|trojan)\b/i, 'definitive malware claims'],
  [/\b(is|are) (completely |totally |100% )?(safe|harmless|virus[- ]free|clean)\b|safe to (open|run)|no risk\b/i, 'safety guarantees'],
  [/ignore (all |any )?(previous|prior|above)|system prompt|as an ai\b|<\s*\/?\s*[a-z][^>]*>|https?:\/\/|\]\(|```/i, 'instructions, markup or links'],
  [/\byou (can|should|may) (safely )?(open|run|execute|click|install|enable)\b/i, 'instructions to open or run the file']
];

export function validateAiOutput(raw: unknown, a: ThreatAssessment): AiValidation {
  if (typeof raw !== 'string' || !raw.trim()) return { ok: false, reason: 'empty response' };
  if (raw.length > LIMITS.RAW) return { ok: false, reason: 'response too long' };
  const m = raw.match(/\{[\s\S]*\}/); if (!m) return { ok: false, reason: 'no JSON object' };
  let obj: unknown; try { obj = JSON.parse(m[0]); } catch { return { ok: false, reason: 'malformed JSON' }; }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return { ok: false, reason: 'unexpected shape' };
  const o = obj as Record<string, unknown>;
  const str = (v: unknown, max: number) => (typeof v === 'string' && v.trim() ? cleanInline(v, max + 1) : null);
  const list = (v: unknown) => (Array.isArray(v) && v.length <= LIMITS.ITEMS && v.every((x) => typeof x === 'string') ? (v as string[]).map((x) => cleanInline(x, LIMITS.ITEM + 1)).filter(Boolean) : null);
  const summary = str(o.summary, LIMITS.SUMMARY), action = str(o.recommendedAction, LIMITS.ACTION), found = list(o.whatWasFound), why = list(o.whyItMatters);
  if (!summary || !action || !found || !why) return { ok: false, reason: 'missing or invalid fields' };
  if (summary.length > LIMITS.SUMMARY || action.length > LIMITS.ACTION || [...found, ...why].some((x) => x.length > LIMITS.ITEM)) return { ok: false, reason: 'field too long' };
  const all = [summary, action, ...found, ...why].join('\n');
  for (const [re, label] of FORBIDDEN) if (re.test(all)) return { ok: false, reason: `contains ${label}` };
  // The AI may not contradict Phase 5: any score it quotes must match, and it may not use a higher risk label than the engine assigned.
  for (const s of all.matchAll(/\b(\d{1,3})\s*(?:\/|out of)\s*100\b/gi)) if (Number(s[1]) !== a.score) return { ok: false, reason: 'quotes a different score' };
  if (/\bcritical\b/i.test(all) && a.status !== 'CRITICAL') return { ok: false, reason: 'overstates the risk level' };
  if (/\bhigh[- ]risk\b/i.test(all) && a.status !== 'HIGH_RISK' && a.status !== 'CRITICAL') return { ok: false, reason: 'overstates the risk level' };
  return { ok: true, value: { summary, whatWasFound: found, whyItMatters: why, recommendedAction: action } };
}
