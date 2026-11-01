/** Extensible lists. Edit here only. */
export const EXECUTABLE_EXTENSIONS = ['exe', 'dll', 'scr', 'sys', 'ocx', 'cpl', 'msi', 'com', 'pif', 'jar'];
export const SCRIPT_EXTENSIONS = ['bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'lnk', 'sh'];
export const MACRO_EXTENSIONS = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm'];
export const DANGEROUS_EXTENSIONS = new Set([...EXECUTABLE_EXTENSIONS, ...SCRIPT_EXTENSIONS]);
/** Extensions commonly used as a decoy before a real executable extension. */
export const DECOY_EXTENSIONS = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'jpg', 'jpeg', 'png', 'gif', 'zip', 'mp3', 'mp4', 'html', 'htm']);

export const SCRIPT_LANGUAGES: Record<string, string> = {
  ps1: 'PowerShell', psm1: 'PowerShell', js: 'JavaScript', jse: 'JavaScript (encoded)', vbs: 'VBScript', vbe: 'VBScript (encoded)',
  bat: 'Batch', cmd: 'Batch', hta: 'HTML Application', wsf: 'Windows Script Host', wsh: 'Windows Script Host settings', html: 'HTML', htm: 'HTML', sh: 'Shell script'
};

export function extOf(name: string): string { const i = name.lastIndexOf('.'); return i > 0 && i < name.length - 1 ? name.slice(i + 1).trim().toLowerCase() : ''; }

/** "invoice.pdf .exe", "a.docx.scr": decoy extension followed by a dangerous one. Returns the offending suffix or null. */
export function doubleExtension(name: string): string | null {
  const parts = name.split('.').map((s) => s.trim().toLowerCase());
  if (parts.length < 3) return null;
  const last = parts[parts.length - 1], prev = parts[parts.length - 2];
  return DANGEROUS_EXTENSIONS.has(last) && DECOY_EXTENSIONS.has(prev) ? `.${prev}.${last}` : null;
}
