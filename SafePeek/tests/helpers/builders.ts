import { makeZip } from './fixtures';

const esc = (s: string) => s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
/** Benign text PDF writer: Helvetica text pages, optional URI link annotation on page 1. No scripts. */
export function makeTextPdf(pages: string[][], opts: { linkUrl?: string; title?: string } = {}): Buffer {
  const objs: string[] = [];
  const pageIds = pages.map((_, i) => 4 + i * 2);
  objs[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objs[2] = `<< /Type /Pages /Kids [${pageIds.map((n) => `${n} 0 R`).join(' ')}] /Count ${pages.length} >>`;
  objs[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  pages.forEach((lines, i) => {
    const content = `BT /F1 12 Tf 14 TL 72 740 Td ${lines.map((l) => `(${esc(l)}) Tj T*`).join(' ')} ET`;
    const annot = i === 0 && opts.linkUrl ? ` /Annots [<< /Type /Annot /Subtype /Link /Rect [72 100 300 120] /Border [0 0 0] /A << /S /URI /URI (${esc(opts.linkUrl)}) >> >>]` : '';
    objs[4 + i * 2] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${5 + i * 2} 0 R${annot} >>`;
    objs[5 + i * 2] = `<< /Length ${content.length} >>\nstream\n${content}\nendstream`;
  });
  const infoId = objs.length; objs[infoId] = `<< /Title (${esc(opts.title ?? 'Document')}) /Producer (SafePeek test fixture) >>`;
  let out = '%PDF-1.4\n'; const offs: number[] = [];
  for (let i = 1; i < objs.length; i++) { offs[i] = out.length; out += `${i} 0 obj\n${objs[i]}\nendobj\n`; }
  const x = out.length;
  out += `xref\n0 ${objs.length}\n0000000000 65535 f \n${offs.slice(1).map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objs.length} /Root 1 0 R /Info ${infoId} 0 R >>\nstartxref\n${x}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

const X = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
const CT = (extra: string) => `${HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>${extra}</Types>`;
const RELS = (t: string, target: string) => `${HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${t}" Target="${target}"/></Relationships>`;
const CORE = (title: string) => `${HEAD}<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>${X(title)}</dc:title><dc:creator>SafePeek Fixtures</dc:creator></cp:coreProperties>`;
const RELNS = 'http://schemas.openxmlformats.org/package/2006/relationships';

export interface DocxOpts { paragraphs: { text: string; style?: string; link?: string }[]; table?: string[][]; macro?: boolean; withEmbedded?: boolean }
export function makeDocx(o: DocxOpts): Buffer {
  const rels: string[] = []; let rid = 1;
  const body = o.paragraphs.map((p) => {
    const style = p.style ? `<w:pPr><w:pStyle w:val="${p.style}"/></w:pPr>` : '';
    if (p.link) { const id = `rId${rid++}`; rels.push(`<Relationship Id="${id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${X(p.link)}" TargetMode="External"/>`); return `<w:p>${style}<w:hyperlink r:id="${id}"><w:r><w:t>${X(p.text)}</w:t></w:r></w:hyperlink></w:p>`; }
    return `<w:p>${style}<w:r><w:t xml:space="preserve">${X(p.text)}</w:t></w:r></w:p>`;
  }).join('') + (o.table ? `<w:tbl>${o.table.map((r) => `<w:tr>${r.map((c) => `<w:tc><w:p><w:r><w:t>${X(c)}</w:t></w:r></w:p></w:tc>`).join('')}</w:tr>`).join('')}</w:tbl>` : '');
  const files: Record<string, string | Buffer> = {
    '[Content_Types].xml': CT(`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml${o.macro ? '' : ''}"/>`),
    '_rels/.rels': RELS('officeDocument', 'word/document.xml'),
    'word/document.xml': `${HEAD}<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>${body}</w:body></w:document>`,
    'word/_rels/document.xml.rels': `${HEAD}<Relationships xmlns="${RELNS}">${rels.join('')}</Relationships>`,
    'docProps/core.xml': CORE('Fixture document')
  };
  if (o.macro) files['word/vbaProject.bin'] = Buffer.from('NOT REAL MACRO');
  if (o.withEmbedded) files['word/embeddings/oleObject1.bin'] = Buffer.from('not executed');
  return makeZip(files);
}

export function makeXlsx(sheets: { name: string; rows: (string | number)[][]; link?: string }[]): Buffer {
  const ss: string[] = []; const idx = (s: string) => { let i = ss.indexOf(s); if (i < 0) { ss.push(s); i = ss.length - 1; } return i; };
  const col = (n: number) => String.fromCharCode(65 + n);
  const files: Record<string, string | Buffer> = {
    '[Content_Types].xml': CT('<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'),
    '_rels/.rels': RELS('officeDocument', 'xl/workbook.xml'),
    'docProps/core.xml': CORE('Fixture workbook')
  };
  sheets.forEach((s, i) => {
    files[`xl/worksheets/sheet${i + 1}.xml`] = `${HEAD}<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><dimension ref="A1:${col(Math.max(...s.rows.map((r) => r.length)) - 1)}${s.rows.length}"/><sheetData>${s.rows.map((r, ri) => `<row r="${ri + 1}">${r.map((v, ci) => typeof v === 'number' ? `<c r="${col(ci)}${ri + 1}"><v>${v}</v></c>` : `<c r="${col(ci)}${ri + 1}" t="s"><v>${idx(v)}</v></c>`).join('')}</row>`).join('')}</sheetData>${s.link ? '<hyperlinks><hyperlink ref="A1" r:id="rId1"/></hyperlinks>' : ''}</worksheet>`;
    if (s.link) files[`xl/worksheets/_rels/sheet${i + 1}.xml.rels`] = `${HEAD}<Relationships xmlns="${RELNS}"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${X(s.link)}" TargetMode="External"/></Relationships>`;
  });
  files['xl/workbook.xml'] = `${HEAD}<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((s, i) => `<sheet name="${X(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets></workbook>`;
  files['xl/_rels/workbook.xml.rels'] = `${HEAD}<Relationships xmlns="${RELNS}">${sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('')}</Relationships>`;
  files['xl/sharedStrings.xml'] = `${HEAD}<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">${ss.map((s) => `<si><t>${X(s)}</t></si>`).join('')}</sst>`;
  return makeZip(files);
}

export function makePptx(slides: { title: string; body: string[]; notes?: string; link?: string }[]): Buffer {
  const files: Record<string, string | Buffer> = {
    '[Content_Types].xml': CT('<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'),
    '_rels/.rels': RELS('officeDocument', 'ppt/presentation.xml'), 'docProps/core.xml': CORE('Fixture presentation')
  };
  const A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';
  slides.forEach((s, i) => {
    const n = i + 1;
    files[`ppt/slides/slide${n}.xml`] = `${HEAD}<p:sld ${A}><p:cSld><p:spTree><p:sp><p:nvSpPr><p:cNvPr id="2" name="Title"/><p:cNvSpPr/><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr><p:txBody><a:p><a:r><a:t>${X(s.title)}</a:t></a:r></a:p></p:txBody></p:sp><p:sp><p:nvSpPr><p:cNvPr id="3" name="Body"/><p:cNvSpPr/><p:nvPr><p:ph type="body"/></p:nvPr></p:nvSpPr><p:txBody>${s.body.map((b, bi) => `<a:p><a:r>${s.link && bi === 0 ? '<a:rPr><a:hlinkClick r:id="rId2"/></a:rPr>' : ''}<a:t>${X(b)}</a:t></a:r></a:p>`).join('')}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`;
    files[`ppt/slides/_rels/slide${n}.xml.rels`] = `${HEAD}<Relationships xmlns="${RELNS}">${s.notes ? `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../notesSlides/notesSlide${n}.xml"/>` : ''}${s.link ? `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${X(s.link)}" TargetMode="External"/>` : ''}</Relationships>`;
    if (s.notes) files[`ppt/notesSlides/notesSlide${n}.xml`] = `${HEAD}<p:notes ${A}><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>${X(s.notes)}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>`;
  });
  files['ppt/presentation.xml'] = `${HEAD}<p:presentation ${A}><p:sldIdLst>${slides.map((_, i) => `<p:sldId id="${256 + i}" r:id="rId${i + 1}"/>`).join('')}</p:sldIdLst></p:presentation>`;
  files['ppt/_rels/presentation.xml.rels'] = `${HEAD}<Relationships xmlns="${RELNS}">${slides.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide${i + 1}.xml"/>`).join('')}</Relationships>`;
  return makeZip(files);
}

export const SALARY_PDF_PAGES = [
  ['Orbit Systems Pvt Ltd', 'Salary Increment Notification', '', 'Dear Priya Sharma,', '', 'We are pleased to inform you that your salary has been revised.', 'Your new monthly salary is Rs 85,000, effective 1 November 2026.', 'Contact hr@orbit-example.test for questions.'],
  ['Page 2', 'Details of the revised compensation are on the HR portal:', 'https://hr.orbit-example.test/increment', 'This is a fictional demo letter.']
];
export const OFFER_DOCX = (macro = false): Buffer => makeDocx({ macro, paragraphs: [
  { text: 'ABC Technologies', style: 'Title' }, { text: 'Internship Offer', style: 'Heading1' }, { text: 'We are pleased to offer you an internship at ABC Technologies.' },
  { text: 'Position', style: 'Heading2' }, { text: 'Software Intern' }, { text: 'Duration: 6 months. Stipend: ₹20,000/month. Starting 3 January 2027.' },
  { text: 'Read the policy', link: 'https://abc-technologies.example.test/policy' }], table: [['Item', 'Detail'], ['Position', 'Software Intern'], ['Duration', '6 months']] });
export const PROJECT_XLSX = (): Buffer => makeXlsx([
  { name: 'October', rows: [['Employee', 'Salary'], ['Asha', 52000], ['Ravi', 61000]], link: 'https://payroll.example.test/oct' }, { name: 'Employees', rows: [['Name', 'Team'], ['Asha', 'Platform'], ['Ravi', 'Data']] }]);
export const PROJECT_PPTX = (): Buffer => makePptx([
  { title: 'Project Overview', body: ['Goals and scope of the demo project'], notes: 'Speaker note: keep it short', link: 'https://project.example.test/' }, { title: 'Architecture', body: ['Desktop agent', 'Static analysis', 'Content intelligence'] }]);
export const COLLEGE_NOTICE = 'COLLEGE NOTICE\n\nGreenfield College of Engineering\nSemester examination timetable will be published on 15 December 2026.\nAll students must collect hall tickets from the office.\nDetails: https://greenfield.example.test/exams\n';
export const SCHOLARSHIP_ZIP = (): Buffer => makeZip({ 'scholarship_form.pdf': makeTextPdf([['Scholarship Application Form', 'Fictional demo']]), 'instructions.txt': 'Fill the form and submit it.\n', 'documents/': '', 'documents/identity.pdf': makeTextPdf([['Identity placeholder']]), 'verification.exe': 'MZ not a real executable (fixture)' });
