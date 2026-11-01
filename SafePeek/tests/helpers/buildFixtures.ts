import fs from 'node:fs';
import path from 'node:path';
import { COLLEGE_NOTICE, OFFER_DOCX, PROJECT_PPTX, PROJECT_XLSX, SALARY_PDF_PAGES, SCHOLARSHIP_ZIP, makeTextPdf } from './builders';

/** Regenerates the synthetic demo fixtures (job-offer.png is committed; it was rendered once with Pillow). Run: npm run fixtures */
const dir = path.join(__dirname, '..', 'fixtures'); fs.mkdirSync(dir, { recursive: true });
const w = (n: string, d: string | Buffer) => fs.writeFileSync(path.join(dir, n), d);
w('salary-increment.pdf', makeTextPdf(SALARY_PDF_PAGES, { linkUrl: 'https://hr.orbit-example.test/increment', title: 'Salary Increment Notification' }));
w('internship-offer.docx', OFFER_DOCX()); w('project-data.xlsx', PROJECT_XLSX()); w('project-presentation.pptx', PROJECT_PPTX());
w('college-notice.txt', COLLEGE_NOTICE); w('scholarship.zip', SCHOLARSHIP_ZIP());
console.log('fixtures written to', dir);
