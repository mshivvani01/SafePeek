import type { FileCategory } from './types';
import { extOf } from './extensions';

export interface Detected { id: string; label: string; mime: string | null; category: FileCategory }
const T = (id: string, label: string, mime: string | null, category: FileCategory): Detected => ({ id, label, mime, category });
export const TYPES = {
  pdf: T('pdf', 'PDF Document', 'application/pdf', 'document'), png: T('png', 'PNG Image', 'image/png', 'image'),
  jpeg: T('jpeg', 'JPEG Image', 'image/jpeg', 'image'), gif: T('gif', 'GIF Image', 'image/gif', 'image'),
  webp: T('webp', 'WebP Image', 'image/webp', 'image'), zip: T('zip', 'ZIP Archive', 'application/zip', 'archive'),
  gzip: T('gzip', 'GZIP Archive', 'application/gzip', 'archive'), sevenz: T('7z', '7-Zip Archive', 'application/x-7z-compressed', 'archive'),
  rar: T('rar', 'RAR Archive', 'application/vnd.rar', 'archive'),
  pe: T('pe', 'Windows Executable (PE)', 'application/vnd.microsoft.portable-executable', 'executable'),
  dos: T('dos-exe', 'DOS/MZ Executable', 'application/x-msdownload', 'executable'),
  elf: T('elf', 'ELF Executable', 'application/x-elf', 'executable'),
  ole2: T('ole2', 'Legacy Office / OLE2 Document', 'application/x-ole-storage', 'document'),
  docx: T('docx', 'Microsoft Word Document', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'document'),
  xlsx: T('xlsx', 'Microsoft Excel Workbook', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'document'),
  pptx: T('pptx', 'Microsoft PowerPoint Presentation', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'document'),
  ooxml: T('ooxml', 'Office Open XML Package', null, 'document'),
  jar: T('jar', 'Java Archive', 'application/java-archive', 'executable'),
  html: T('html', 'HTML Document', 'text/html', 'text'), script: T('script', 'Script', 'text/plain', 'script'),
  text: T('text', 'Plain Text', 'text/plain', 'text'), empty: T('empty', 'Empty File', null, 'other'),
  unknown: T('unknown', 'Unknown Binary Data', 'application/octet-stream', 'unknown')
} as const;

const starts = (b: Buffer, sig: number[], off = 0) => b.length >= off + sig.length && sig.every((v, i) => b[off + i] === v);

function looksLikeText(b: Buffer): boolean {
  if (starts(b, [0xff, 0xfe]) || starts(b, [0xfe, 0xff]) || starts(b, [0xef, 0xbb, 0xbf])) return true;
  const n = Math.min(b.length, 4096);
  let ctrl = 0;
  for (let i = 0; i < n; i++) { const c = b[i]; if (c === 0) return false; if (c < 9 || (c > 13 && c < 32)) ctrl++; }
  return ctrl / n < 0.05;
}

/** Content-based detection from the first bytes. The filename is only used to refine plain-text (script vs text), never to trust binary types. */
export function detectType(head: Buffer, fileName: string, size: number): Detected {
  if (size === 0 || head.length === 0) return TYPES.empty;
  const ascii = head.subarray(0, 1024).toString('latin1');
  if (ascii.includes('%PDF-')) return TYPES.pdf;
  if (starts(head, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return TYPES.png;
  if (starts(head, [0xff, 0xd8, 0xff])) return TYPES.jpeg;
  if (ascii.startsWith('GIF87a') || ascii.startsWith('GIF89a')) return TYPES.gif;
  if (ascii.startsWith('RIFF') && ascii.slice(8, 12) === 'WEBP') return TYPES.webp;
  if (starts(head, [0x50, 0x4b, 0x03, 0x04]) || starts(head, [0x50, 0x4b, 0x05, 0x06])) return TYPES.zip; // refined to OOXML/JAR by the ZIP inspector
  if (starts(head, [0x1f, 0x8b])) return TYPES.gzip;
  if (starts(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return TYPES.sevenz;
  if (ascii.startsWith('Rar!\x1a\x07')) return TYPES.rar;
  if (starts(head, [0x7f, 0x45, 0x4c, 0x46])) return TYPES.elf;
  if (starts(head, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return TYPES.ole2;
  if (starts(head, [0x4d, 0x5a])) {
    if (head.length >= 0x40) { const o = head.readUInt32LE(0x3c); if (o + 4 <= head.length && starts(head, [0x50, 0x45, 0, 0], o)) return TYPES.pe; if (o + 4 > head.length && o < size) return TYPES.pe; }
    return TYPES.dos;
  }
  if (looksLikeText(head)) {
    const lower = ascii.trimStart().toLowerCase();
    if (lower.startsWith('<!doctype html') || lower.startsWith('<html')) return TYPES.html;
    const ext = extOf(fileName);
    if (['html', 'htm'].includes(ext)) return TYPES.html;
    if (['ps1', 'psm1', 'js', 'jse', 'vbs', 'vbe', 'bat', 'cmd', 'hta', 'wsf', 'wsh', 'sh'].includes(ext)) return TYPES.script;
    return TYPES.text;
  }
  return TYPES.unknown;
}

/** What each declared extension should contain (type ids). Unlisted extensions are not judged. */
const EXPECTED: Record<string, string[]> = {
  pdf: ['pdf'], png: ['png'], jpg: ['jpeg'], jpeg: ['jpeg'], gif: ['gif'], webp: ['webp'], zip: ['zip'], gz: ['gzip'], '7z': ['7z'], rar: ['rar'],
  docx: ['docx'], xlsx: ['xlsx'], pptx: ['pptx'], docm: ['docx'], xlsm: ['xlsx'], pptm: ['pptx'], doc: ['ole2'], xls: ['ole2'], ppt: ['ole2'],
  exe: ['pe', 'dos-exe'], dll: ['pe'], scr: ['pe', 'dos-exe'], sys: ['pe'], ocx: ['pe'], cpl: ['pe'], jar: ['jar', 'zip'],
  txt: ['text'], log: ['text'], csv: ['text'], json: ['text'], xml: ['text'], md: ['text'], ini: ['text'], rtf: ['text'],
  html: ['html', 'text'], htm: ['html', 'text'],
  ps1: ['script', 'text'], psm1: ['script', 'text'], js: ['script', 'text'], jse: ['script', 'text', 'unknown'], vbs: ['script', 'text'], vbe: ['script', 'text', 'unknown'],
  bat: ['script', 'text'], cmd: ['script', 'text'], hta: ['script', 'html', 'text'], wsf: ['script', 'text']
};
export const DECLARED_LABEL: Record<string, string> = {
  pdf: 'PDF', png: 'PNG', jpg: 'JPEG', jpeg: 'JPEG', gif: 'GIF', webp: 'WebP', zip: 'ZIP', gz: 'GZIP', '7z': '7-Zip', rar: 'RAR', docx: 'Word (DOCX)', xlsx: 'Excel (XLSX)',
  pptx: 'PowerPoint (PPTX)', docm: 'Word (DOCM)', xlsm: 'Excel (XLSM)', pptm: 'PowerPoint (PPTM)', doc: 'Word (DOC)', xls: 'Excel (XLS)', ppt: 'PowerPoint (PPT)',
  exe: 'Windows Executable', dll: 'DLL', scr: 'Screensaver (executable)', txt: 'Text', csv: 'CSV', json: 'JSON', xml: 'XML', html: 'HTML', htm: 'HTML', rtf: 'RTF',
  ps1: 'PowerShell script', js: 'JavaScript', vbs: 'VBScript', bat: 'Batch', cmd: 'Batch', hta: 'HTML Application', jar: 'Java Archive'
};

export function declaredTypeLabel(ext: string): string | null { return ext ? DECLARED_LABEL[ext] ?? ext.toUpperCase() : null; }
/** true = definite mismatch; false = consistent or not judgeable. */
export function isMismatch(ext: string, actual: Detected): boolean {
  const exp = EXPECTED[ext];
  if (!exp || actual.id === 'empty') return false;
  return !exp.includes(actual.id);
}
