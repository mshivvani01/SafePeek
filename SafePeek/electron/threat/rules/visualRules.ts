import type { EvidenceOrigin, Rule, RuleFinding } from '../types';
import { lureState } from './contentRules';
import { F, clip } from './util';

const FILENAME_THEME = /\b(invoice|payment|receipt|statement|refund|salary|payroll|verify|verification|security|otp|kyc|bank|account|password|login)\b/i;
const originsOfLure = (c: Parameters<Rule>[0], ids: string[]): EvidenceOrigin[] => [...new Set(c.lure.hits.filter((h) => ids.includes(h.id)).flatMap((h) => h.origins ?? []))];

/**
 * Phase 8: visual evidence and cross-modal correlation. These rules add NO new scoring system: they emit ordinary findings (correlation findings go
 * through the existing correlation cap, de-duplication and severity guards). Text found in images and QR codes is already part of the shared
 * lure/URL analysis, so each rule here only describes how DIFFERENT channels reinforce each other.
 */
export const visualRules: Rule = (c) => {
  const out: RuleFinding[] = []; const s = lureState(c); const v = c.visual;
  const bad = c.urls.filter((u) => u.suspicious).sort((a, b) => b.score - a.score);
  const lureAny = s.credLure || s.scam;
  const credIds = ['c_verify', 'c_confirm', 'c_login', 'c_enter', 'c_update', 'c_otp', 'c_card', 'c_kyc', 'c_verifynow'];
  const lureOrig = new Set(originsOfLure(c, [...credIds, 'u_urgent', 'u_immediately', 'u_closure', 'u_deadline', 'f_payment', 'f_fee', 'f_send', 'f_amount', 'p_won', 'p_claim', 'p_lottery']));
  const visualLure = lureOrig.has('OCR') || lureOrig.has('QR');

  if (v.qrCount) {
    const web = v.qr.filter((q) => q.kind === 'url');
    out.push(F({ ruleId: 'VISUAL_QR_PRESENT', category: 'MALICIOUS_URL', weight: 0, severity: 'INFO', source: 'CONTENT_ANALYSIS', origins: ['QR'], title: `${v.qrCount} QR code${v.qrCount === 1 ? '' : 's'} detected`, description: `${web.length ? `${web.length} point${web.length === 1 ? 's' : ''} to a web address. ` : ''}QR codes hide their destination from the reader. SafePeek decoded the content as text only and never opened it.`, evidence: v.qr.slice(0, 3).map((q) => clip(q.payload, 90)).join(' | ') }));
    const odd = v.qr.filter((q) => q.kind !== 'url' && q.kind !== 'text');
    if (odd.length) out.push(F({ ruleId: 'VISUAL_QR_NON_WEB', category: 'UNKNOWN', weight: 0, severity: 'INFO', source: 'CONTENT_ANALYSIS', origins: ['QR'], title: 'QR code contains non-web content', description: `The QR code contains a ${[...new Set(odd.map((q) => `${q.scheme ?? q.kind}:`))].join(', ')} payload. It is shown as text and was not launched.`, evidence: odd.slice(0, 3).map((q) => clip(q.payload, 90)).join(' | ') }));
  }

  // Credential/scam wording that arrives through an image or QR AND a suspicious address (any channel): the channels reinforce each other.
  const badOrigins = new Set(bad.map((u) => u.origin ?? 'TEXT'));
  const channels = new Set<EvidenceOrigin>([...lureOrig, ...badOrigins]);
  // Cross-modal = the lure and the link reached us through DIFFERENT channels. If the lure is also present in the link's own channel (e.g. the same
  // sentence in the PDF text and in an image) that is duplicated evidence, not reinforcement, and is not counted again.
  const separate = ![...lureOrig].some((o) => badOrigins.has(o));
  if (lureAny && bad.length && (channels.has('OCR') || channels.has('QR')) && separate)
    out.push(F({ ruleId: 'CORR_CROSS_MODAL_LURE_URL', category: 'PHISHING', weight: 14, severity: 'HIGH', correlation: true, source: 'CORRELATION', origins: [...channels], dedupeKey: 'cross-modal',
      title: 'Message and link come from different parts of the file and reinforce each other', description: `The pressure/credential wording (${[...lureOrig].map((o) => o.toLowerCase()).join(' + ') || 'text'}) and the suspicious address (${[...badOrigins].map((o) => o.toLowerCase()).join(' + ')}) were found through different channels of the same file. Phishing documents commonly split the lure and the link like this, partly to avoid text-based filters. Nothing was opened.`,
      reason: 'Wording found in the file and a suspicious link found through another channel (image text or QR code) point the same way.', evidence: `${clip(bad[0].url, 100)} [${bad[0].origin ?? 'TEXT'}] + ${clip(c.lure.first('credential')?.snippet ?? c.lure.first('urgency')?.snippet ?? 'lure wording', 80)}`,
      evidenceItems: [{ type: 'url', description: 'Suspicious address', value: clip(bad[0].url, 120), origin: bad[0].origin }, { type: 'phrase', description: 'Lure wording', value: clip(c.lure.first('credential')?.snippet ?? c.lure.first('urgency')?.snippet ?? '', 100), origin: [...lureOrig][0] }] }));

  // "Quishing": a QR code to an external page next to pressure or credential/payment wording, even when the address itself looks plain.
  if (v.qrWebCount && lureAny && !bad.length)
    out.push(F({ ruleId: 'CORR_QR_LURE', category: 'PHISHING', weight: 12, severity: 'MEDIUM', correlation: true, source: 'CORRELATION', origins: ['QR', ...lureOrig], dedupeKey: 'cross-modal',
      title: 'QR code to an external page alongside pressure or credential wording', description: 'The file asks the reader for credentials or payment (or pressures them) and also contains a QR code that leads to a web page. The destination hides behind the code and was not opened or checked against any reputation data.',
      reason: 'A QR code leads to an external page while the file pressures the reader or asks for details.', evidence: clip(v.qr.find((q) => q.kind === 'url')?.payload ?? '', 100) }));

  // Message hidden in an image of a text-less document.
  if (lureAny && lureOrig.has('OCR') && !lureOrig.has('TEXT') && v.ocrText && v.pdfKind && v.pdfKind !== 'TEXT')
    out.push(F({ ruleId: 'CORR_TEXT_IN_IMAGE', category: 'SUSPICIOUS_DOCUMENT', weight: 6, severity: 'LOW', correlation: true, source: 'CORRELATION', origins: ['OCR', 'STATIC'], dedupeKey: 'text-in-image',
      title: 'The message is only present as an image', description: `${v.pdfKind === 'IMAGE_ONLY' ? 'This PDF has no selectable text; ' : 'Some pages of this PDF have no selectable text; '}the wording exists only as a picture, which is how some phishing documents avoid text scanners. Genuine scans look the same, so this is a weak signal on its own.`,
      reason: 'Phishing-style wording exists only inside an image.', evidence: `OCR text, no selectable text${v.ocrPages ? ` (${v.ocrPages} page${v.ocrPages === 1 ? '' : 's'} read with OCR)` : ''}` }));

  // Name of the file matches the theme of the visual lure.
  if (visualLure && lureAny && FILENAME_THEME.test(c.fileName))
    out.push(F({ ruleId: 'CORR_FILENAME_VISUAL_LURE', category: 'SOCIAL_ENGINEERING', weight: 6, severity: 'LOW', correlation: true, source: 'CORRELATION', origins: ['STATIC', ...lureOrig], dedupeKey: 'filename-lure',
      title: 'File name matches the theme of the lure in the image', description: `The file name ("${clip(c.fileName, 60)}") uses wording like the pressure or credential request found in its image content. Ordinary documents are named like this too; it is a weak supporting signal.`,
      reason: 'The file name matches the theme of the lure inside the file.', evidence: clip(c.fileName, 80) }));

  // An "image" that claims to be another type and also carries lure text.
  if (c.analysis?.identity.typeMismatch && c.category === 'image' && lureAny && v.ocrText)
    out.push(F({ ruleId: 'CORR_DISGUISED_IMAGE_LURE', category: 'FILE_TYPE_MISMATCH', weight: 14, severity: 'MEDIUM', correlation: true, source: 'CORRELATION', origins: ['STATIC', 'OCR'], dedupeKey: 'disguised',
      title: 'An image disguised as another file type contains phishing-style text', description: `The file is really an image but its name suggests ${c.analysis.identity.declaredType ?? 'a different type'}, and the text inside the picture asks for details or pressures the reader.`,
      reason: 'An image with a misleading file type contains phishing-style wording.', evidence: `${c.analysis.identity.declaredType ?? c.ext} vs ${c.typeLabel}` }));

  return out;
};
