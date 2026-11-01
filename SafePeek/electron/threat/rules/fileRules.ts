import type { Rule, RuleFinding } from '../types';
import { sniffScript } from '../lure';
import { F, EXEC_EXT, SCRIPT_EXT, clip } from './util';

const TEXTY_EXT = new Set(['txt', 'log', 'csv', 'rtf', 'md', 'json', 'xml', '']);
const BIDI = /[\u202a-\u202e\u2066-\u2069]/;
const THEME = /(invoice|salary|payment|scholarship|offer|resume|cv|verification|statement|receipt|delivery|shipping|tax|refund|payslip|bank|account|notice|document|scan)/i;

/** Extension / real-type rules. They use Phase 3's detected type, never the file name alone. */
export const fileRules: Rule = (c) => {
  const a = c.analysis; if (!a) return [];
  const out: RuleFinding[] = [];
  const id = a.identity;
  const execContent = ['pe', 'dos-exe', 'elf', 'jar'].includes(c.typeId);
  const declared = id.declaredType ?? (c.ext ? c.ext.toUpperCase() : 'none');

  if (id.typeMismatch) {
    const ev = `Declared ".${c.ext}" (${declared}); detected ${c.typeLabel}`;
    if (execContent && !EXEC_EXT.has(c.ext)) {
      out.push(F({ ruleId: 'FILE_EXEC_DISGUISED', category: 'FILE_TYPE_MISMATCH', weight: 60, title: 'Executable disguised with a non-executable extension',
        description: `The file extension is ".${c.ext}" (${declared}), but the file content matches a ${c.typeLabel}. This mismatch can be used to disguise executable files as ordinary documents or images.`,
        reason: `File extension (.${c.ext}) does not match the detected executable type (${c.typeLabel}).`, evidence: ev, dedupeKey: 'disguise-type', evidenceItems: [{ type: 'file-extension', description: 'Declared extension', value: `.${c.ext}` }, { type: 'detected-type', description: 'Type detected from file content', value: c.typeLabel }] }));
    } else if (SCRIPT_EXT.has(c.ext) && execContent) {
      out.push(F({ ruleId: 'FILE_EXEC_AS_SCRIPT', category: 'FILE_TYPE_MISMATCH', weight: 50, title: 'Script extension on an executable file', description: `The extension ".${c.ext}" suggests a script, but the content is a ${c.typeLabel}.`, reason: `A ".${c.ext}" file actually contains ${c.typeLabel}.`, evidence: ev, dedupeKey: 'disguise-type' }));
    } else if (c.scriptKind && !SCRIPT_EXT.has(c.ext) && !EXEC_EXT.has(c.ext)) {
      out.push(F({ ruleId: 'FILE_SCRIPT_DISGUISED', category: 'FILE_TYPE_MISMATCH', weight: 45, title: 'Script code hidden behind a document extension',
        description: `The extension is ".${c.ext}" (${declared}), but the content is plain text that looks like ${c.scriptKind} code. Disguising scripts as documents is a common way to get them opened.`,
        reason: `File named ".${c.ext}" contains what looks like ${c.scriptKind} code.`, evidence: ev, dedupeKey: 'disguise-type' }));
    } else if (['zip', 'ooxml', 'docx', 'xlsx', 'pptx', '7z', 'rar', 'gzip'].includes(c.typeId) && !['zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', '7z', 'rar', 'gz', 'jar'].includes(c.ext)) {
      out.push(F({ ruleId: 'FILE_ARCHIVE_DISGUISED', category: 'FILE_TYPE_MISMATCH', weight: 24, title: 'Archive hidden behind another extension', description: `The extension ".${c.ext}" (${declared}) does not match the container format ${c.typeLabel}. Archives renamed like this can hide their contents from the user.`, reason: `A ".${c.ext}" file is really a ${c.typeLabel}.`, evidence: ev, dedupeKey: 'disguise-type' }));
    } else if (EXEC_EXT.has(c.ext)) {
      out.push(F({ ruleId: 'FILE_EXT_CLAIMS_EXEC', category: 'FILE_TYPE_MISMATCH', weight: 10, title: 'Extension claims an executable but the content is different', description: `The extension ".${c.ext}" says executable, but the content is ${c.typeLabel}. The file is probably not a working program.`, reason: `A ".${c.ext}" file contains ${c.typeLabel}, not an executable.`, evidence: ev }));
    } else {
      out.push(F({ ruleId: 'FILE_TYPE_MISMATCH', category: 'FILE_TYPE_MISMATCH', weight: 8, title: 'File type does not match its extension', description: `The extension ".${c.ext}" (${declared}) does not match the detected content (${c.typeLabel}). This is often harmless (mis-named or renamed files) but is also used to mislead.`, reason: `Extension (.${c.ext}) does not match the detected type (${c.typeLabel}).`, evidence: ev }));
    }
  } else if (c.category === 'text' && TEXTY_EXT.has(c.ext) && c.typeId === 'text') {
    const kind = sniffScript(c.rawText, 3);
    if (kind) out.push(F({ ruleId: 'FILE_SCRIPT_IN_TEXT', category: 'SUSPICIOUS_SCRIPT', weight: 30, source: 'CONTENT_ANALYSIS', title: 'Script code inside a text file',
      description: `The file is named ".${c.ext || '(no extension)'}" and detected as plain text, but its content looks like ${kind} code. Renaming a script to a text-like extension can hide what it is.`, reason: `A text file contains what looks like ${kind} code.`, evidence: `Content resembles ${kind}`, dedupeKey: 'disguise-type' }));
  }

  // Double extension: Phase 3 filename analysis (the archive-entry variant is handled in archiveRules).
  const dbl = a.indicators.find((i) => i.code === 'DOUBLE_EXTENSION' && !/inside archive/i.test(i.title));
  if (dbl) {
    const confirmed = execContent || c.isScript;
    out.push(F({ ruleId: 'FILE_DOUBLE_EXTENSION', category: 'SOCIAL_ENGINEERING', weight: confirmed ? 36 : 24, severity: confirmed ? 'HIGH' : 'MEDIUM', title: 'Double file extension',
      description: `The file name ends with ${dbl.evidence?.replace('Filename contains ', '') ?? 'a document extension followed by an executable/script extension'}: a document-like extension followed by a program/script extension. Depending on Windows settings the real extension may be hidden, so the file can look like a document.${confirmed ? ' The file content is in fact executable/script data.' : ''} A double extension is one piece of evidence, not proof of malware.`,
      reason: `Filename uses a double extension (${(dbl.evidence ?? '').replace('Filename contains ', '').replace(/"/g, '') || 'decoy + executable'}).`, evidence: dbl.evidence, evidenceItems: [{ type: 'file-name', description: 'Static file name analysis', value: clip(c.fileName, 120) }] }));
  }
  if ((dbl || execContent || c.isScript) && THEME.test(c.fileName)) {
    out.push(F({ ruleId: 'FILE_LURE_NAME', category: 'SOCIAL_ENGINEERING', weight: 10, title: 'Document-themed name on an executable/disguised file', description: `The file name uses everyday business wording (e.g. invoice, salary, scholarship) while the file is ${dbl ? 'double-extension' : 'executable or script'} content. Lure names are a common way to get files opened.`, reason: 'The file name looks like an everyday business document but the file is not a document.', evidence: clip(c.fileName, 120) }));
  }
  if (BIDI.test(c.fileName)) out.push(F({ ruleId: 'FILE_BIDI_NAME', category: 'OBFUSCATION', weight: 45, title: 'File name contains a text-direction override character', description: 'Right-to-left override characters can make "gpj.exe" display like ".jpg" (reversing the end of the name). They have almost no legitimate use in file names.', reason: 'The file name contains hidden text-direction control characters.', evidence: clip(c.fileName.replace(BIDI, '⟦RLO⟧'), 120) }));
  else if (/ {10,}\.\w{2,5}$/.test(c.fileName)) out.push(F({ ruleId: 'FILE_PADDED_NAME', category: 'OBFUSCATION', weight: 20, title: 'File name padded with many spaces', description: 'Long runs of spaces before the extension push the real extension out of view in file lists.', reason: 'The file name is padded with spaces to hide its real extension.', evidence: clip(c.fileName, 120) }));
  return out;
};
