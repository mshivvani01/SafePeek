import type { ContentSummary, Entities, ExtractorType, Section } from './types';
import { cleanInline } from './sanitizer';

/** Deterministic, local, keyword-based document-type guess. It describes WHAT the content looks like, never whether it is safe (Phase 5). */
const DOC_TYPES: [string, RegExp, string][] = [
  ['Salary increment letter', /(salary|compensation|ctc|pay)\b.{0,60}\b(revis|increment|hike|raise|increase)|increment (letter|notification)|\bappraisal\b/is, 'a salary increment notification'],
  ['Internship offer letter', /intern(ship)?\b.{0,80}\b(offer|stipend|position)|offer\b.{0,80}\bintern/is, 'an internship offer'],
  ['Job offer letter', /(offer (letter|of employment)|pleased to offer you|position of|joining date|job offer)/i, 'a job offer letter'],
  ['Scholarship notice', /scholarship/i, 'a scholarship notice or application'],
  ['Invoice / payment request', /(invoice|amount due|bill to|payment (due|request)|purchase order)/i, 'an invoice or payment request'],
  ['Receipt', /(receipt|payment received|transaction id)/i, 'a receipt'],
  ['Resume / CV', /(curriculum vitae|\bresume\b|work experience.{0,400}education|education.{0,400}skills)/is, 'a resume or CV'],
  ['Academic / college notice', /(college|university|semester|examination|timetable|circular|notice to students|campus)/i, 'a college or academic notice'],
  ['Meeting / project document', /(agenda|minutes of|project (plan|overview)|architecture|roadmap|milestone)/i, 'a project or meeting document'],
  ['Financial / tabular data', /(salary|revenue|budget|employee|quarter|total)\b/i, 'financial or tabular data'],
  ['Legal / terms document', /(agreement|terms and conditions|hereby|confidential|non-disclosure)/i, 'an agreement or legal text']
];

const ORG_RE = /\b([A-Z][\w&.'-]*(?:[ \t]+[A-Z][\w&.'-]*){0,3}[ \t]+(?:Technologies|Technology|Pvt\.?\s*Ltd\.?|Ltd\.?|Limited|Inc\.?|LLC|Corporation|Corp\.?|Solutions|Systems|University|College|Institute|Bank|Foundation|Services|Industries))\b/g;
const AMOUNT_RE = /(?:₹|Rs\.?|INR|USD|\$|€|£)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:\/month|per month|lakhs?|crores?|k))?/gi;
const DATE_RE = /\b(?:\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?,?\s+\d{4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}|\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PHONE_RE = /(?:\+\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)\d{3,4}[\s-]?\d{3,4}\b/g;
const uniq = (a: string[], n = 10) => [...new Set(a.map((x) => x.trim()).filter(Boolean))].slice(0, n);

export function extractEntities(text: string): Entities {
  const people: string[] = [];
  for (const m of text.matchAll(/\b(?:Dear|Hi|Hello)\s+((?:Mr\.?|Ms\.?|Mrs\.?|Dr\.?)?\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\s*[,:]/g)) if (!/^(Sir|Madam|Employee|Student|Customer|Candidate|All|Team|User)$/i.test(m[1].trim())) people.push(m[1]);
  for (const m of text.matchAll(/\b(?:Name|Employee Name|Candidate Name)\s*[:\-]\s*([A-Z][A-Za-z.' -]{2,40})/g)) people.push(m[1]);
  return {
    organizations: uniq([...text.matchAll(ORG_RE)].map((m) => m[1])), people: uniq(people),
    amounts: uniq([...text.matchAll(AMOUNT_RE)].map((m) => m[0].replace(/[.,\s]+$/, '')).filter((a) => /\d{2}/.test(a) || /[k]/i.test(a))),
    dates: uniq([...text.matchAll(DATE_RE)].map((m) => m[0])),
    emails: uniq([...text.matchAll(EMAIL_RE)].map((m) => m[0])),
    phones: uniq([...text.matchAll(PHONE_RE)].map((m) => m[0]).filter((p) => p.replace(/\D/g, '').length >= 8 && !/^\d{4}-\d{2}-\d{2}$/.test(p)))
  };
}

const KIND_NOUN: Partial<Record<ExtractorType, string>> = { pdf: 'document', docx: 'document', xlsx: 'workbook', pptx: 'presentation', image: 'image', text: 'text file', archive: 'archive' };

export function summarize(opts: { text: string; extractor: ExtractorType; pageCount?: number | null; sections?: Section[]; titleHint?: string | null; extra?: string }): ContentSummary {
  const text = opts.text;
  const lines = text.split('\n').map((l) => cleanInline(l, 200)).filter((l) => l.length > 2);
  const heading = opts.sections?.find((s) => s.kind === 'heading')?.text;
  const title = cleanInline(opts.titleHint || heading || lines.find((l) => l.length >= 4 && l.length <= 120) || '', 160) || null;
  const hit = text.length > 20 ? DOC_TYPES.find(([, re]) => re.test(text.slice(0, 40_000))) : undefined;
  const noun = KIND_NOUN[opts.extractor] ?? 'file';
  const documentType = hit ? hit[0] : text.trim().length ? `General ${noun}` : `${noun[0].toUpperCase()}${noun.slice(1)} (no readable text)`;
  const base = hit ? `This ${noun} appears to contain ${hit[2]}.` : text.trim().length ? `This ${noun} contains readable text, but SafePeek could not classify its subject.` : `No readable text was found in this ${noun}.`;
  const sectionTitles = (opts.sections ?? []).filter((s) => s.kind === 'heading').map((s) => s.text).slice(0, 8);
  return {
    documentType, title, description: opts.extra ? `${base} ${opts.extra}` : base, pageCount: opts.pageCount ?? null, textLength: text.length,
    entities: extractEntities(text), keySections: sectionTitles
  };
}
