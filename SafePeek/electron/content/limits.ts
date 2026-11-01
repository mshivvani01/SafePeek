/** Phase 4 extraction policy. All values are defaults; documented in docs/ARCHITECTURE.md. */
export const LIMITS = {
  MAX_FILE_SIZE: 50 * 1024 * 1024,          // parsers that must read the whole file (PDF, Office, images)
  TEXT_PREVIEW_BYTES: 100 * 1024,           // plain text: only the first 100 KB is ever read
  MAX_TEXT_LENGTH: 200_000,                 // chars kept per file after extraction
  MAX_PDF_PAGES: 50,
  MAX_PDF_PAGE_CHARS: 20_000,
  MAX_OFFICE_PART_BYTES: 8 * 1024 * 1024,   // uncompressed bytes read from any single package part (zip-bomb safe)
  MAX_ARCHIVE_ENTRIES: 1000,
  MAX_ARCHIVE_DEPTH: 12,
  MAX_OCR_PIXELS: 25_000_000,               // legacy name kept for compatibility; see the Phase 8 bounds below
  MAX_IMAGE_PREVIEW_BYTES: 4 * 1024 * 1024,
  MAX_TABLE_ROWS: 100, MAX_TABLE_COLS: 30, MAX_TABLES: 50,
  MAX_SHEETS: 20, MAX_SHEET_ROWS: 200, MAX_SLIDES: 100, MAX_LINKS: 200, MAX_SECTIONS: 2000,
  TIMEOUT_MS: 30_000, OCR_TIMEOUT_MS: 90_000,

  // ---- Phase 8: visual / cross-modal analysis. Every stage is bounded; exceeding a bound yields PARTIAL, never SAFE. ----
  MAX_IMAGE_PIXELS: 50_000_000,             // refuse to decode anything larger (decompression-bomb guard; also enforced by the image engine)
  MAX_IMAGE_SIDE: 20_000,                   // longest side accepted
  OCR_WORK_MAX_SIDE: 2_200,                 // images are downsampled so the OCR engine never sees more than this on the long side...
  OCR_WORK_MAX_PIXELS: 4_500_000,           // ...or more than this many pixels (OCR time grows with pixels x text density)
  OCR_MIN_SIDE_UPSCALE: 700,                // very small images are enlarged (up to 3x) so characters are big enough to read
  QR_WORK_MAX_SIDE: 1_600,                  // QR search works on a downsampled copy as well
  MAX_QR_CODES: 6,                          // per image
  MAX_QR_CODES_TOTAL: 20,                   // per file
  MAX_QR_PAYLOAD_CHARS: 2_000,
  OCR_BAND_MIN_PIXELS: 1_800_000,           // above this the OCR image is read in horizontal bands
  OCR_BAND_HEIGHT: 1_000,
  OCR_MAX_BANDS: 8,
  OCR_START_TIMEOUT_MS: 40_000,             // starting the OCR worker (loads the engine and the language model)
  OCR_CALL_TIMEOUT_MS: 30_000,              // one OCR call; on expiry the OCR worker is terminated and restarted (no runaway worker)
  IMAGE_VISUAL_TOTAL_MS: 70_000,            // whole image analysis (prepare + QR + OCR)
  MAX_OCR_TEXT: 100_000,                    // chars of OCR text kept per file
  MAX_PDF_OCR_PAGES: 10,                    // pages OCR'd per PDF
  MAX_PDF_VISUAL_PAGES: 25,                 // pages inspected for embedded images / QR codes
  MAX_PDF_IMAGES_PER_PAGE: 3,               // largest images only
  PDF_MAX_IMAGE_PIXELS: 36_000_000,         // handed to pdf.js (maxImageSize): larger embedded images are skipped, not decoded
  MAX_PDF_VISUAL_TOTAL_PIXELS: 90_000_000,  // total source pixels decoded across a PDF
  PDF_OCR_TOTAL_MS: 100_000,                // total OCR budget per PDF
  PDF_PAGE_TEXT_MIN_ALNUM: 40,              // a page with fewer letters/digits than this has no meaningful text layer
  PDF_PAGE_TEXT_WITH_IMAGE_ALNUM: 200,      // ...and with a large image it is still OCR'd below this
  PDF_LARGE_IMAGE_SIDE: 600,
  MIN_QR_IMAGE_SIDE: 60,
  OCR_CACHE_MAX_ENTRIES: 200
} as const;
export type Limits = typeof LIMITS;
