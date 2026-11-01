# Phase 8 - Visual & cross-modal threat intelligence (v1.1.0)

SafePeek can analyze visual content and scanned documents using **bounded local OCR**, detect **QR codes**, extract **URLs**, and **correlate** visual evidence with the existing threat analysis. The visual system is an additional **evidence source**; the existing deterministic threat engine remains the authority (no second engine, no second scoring system).

```
FILE -> STATIC -> CONTENT -> { TEXT | IMAGE -> OCR | PDF -> OCR (pages without a text layer) } + QR DETECTION
     -> URL EXTRACTION -> URL ANALYSIS -> CROSS-MODAL CORRELATION -> EXISTING THREAT ENGINE -> SCORE -> EXPLANATION -> ALERT
```

## Root cause of "Extraction timed out" on normal images
1. **Environment bug (the main one).** tesseract.js treats `process.versions.electron` as an "electron" environment and handles a local `langPath` as a URL to download. Under Electron this fails ("Only absolute URLs are supported"), the error was swallowed by a no-op error handler, and the worker never finished starting, so *every* image waited out the 90 s budget regardless of size. Reproduced by running the old code under Electron 31's runtime (`ELECTRON_RUN_AS_NODE`); plain Node (and therefore the old unit tests) cannot see it. **Fix:** the bundled model is staged in a plain directory and loaded through the engine's read-only cache; worker start-up is bounded (40 s) and errors surface instead of being swallowed.
2. **No downscaling.** A dense 4000x3000 photo-like image took **70 s** with the old code on a fast machine (a slower laptop passes 90 s). Now it is downsampled to <= 2 200 px / 4.5 MP and read in bands (**~5-45 s -> typically 1-5 s** for normal images in the test environment).
3. **A timed-out OCR call kept running** inside the shared worker, so the next image queued behind it. Now the worker is terminated and restarted on timeout/crash.
4. A crashed worker thread hung silently (no exit/error listener). Now it rejects immediately.
5. Heavy hOCR/TSV output was generated although only text is used. Now only text is requested.

I could **not** observe the reporter's actual 1.7 MB file or Windows; (1) is the cause that reproduces the exact symptom ("Extraction timed out", PARTIAL, UNKNOWN) for any image under Electron; (2)-(5) are real defects fixed regardless.

## Bounds (electron/content/limits.ts)
| Bound | Value |
|---|---|
| Max image pixels / side (decode refused above) | 50 MP / 20 000 px |
| OCR working size | <= 2 200 px long side and <= 4.5 MP; tiny images enlarged up to 3x |
| OCR bands (dense pages) | image > 1.8 MP read in <= 8 overlapping bands |
| OCR call timeout / total image budget / worker start | 30 s / 70 s / 40 s |
| OCR text kept | 100 000 chars |
| PDF: OCR pages / inspected pages / images per page | 10 / 25 / 3 |
| PDF: pdf.js maxImageSize / total decoded pixels / OCR budget | 36 MP / 90 MP / 100 s |
| QR codes per image / per file / payload length | 6 / 20 / 2 000 chars |
Any bound reached => **PARTIAL** (or UNKNOWN risk), "Some visual content could not be fully analyzed", never SAFE.

## How PDFs are handled
Direct text is extracted first (unchanged). A page needs OCR when it has < 40 letters/digits and an embedded image, or a large image and < 200 letters/digits. Pages with real text are not OCR'd. Page images come from the pdf.js operator list as pixel data (no rendering of page content, no scripts/actions/URLs). Kind: TEXT / IMAGE_ONLY / MIXED / EMPTY. QR codes are searched on every page that paints a usable image.
**Known limitation:** text drawn as vector paths (not an image) and image masks are not read.

## Evidence model
`ThreatIndicator.origins` / `ThreatEvidence.origin` (`STATIC | TEXT | OCR | QR | ARCHIVE | COMBINED`). The lure analysis runs once over the combined text, so the same phrase seen in PDF text *and* OCR is **one** indicator with origins `[OCR, TEXT]`; URLs are de-duplicated by canonical key; the cross-modal correlation only fires when lure and link arrived through *different* channels. New rules: `CORR_CROSS_MODAL_LURE_URL`, `CORR_QR_LURE`, `CORR_TEXT_IN_IMAGE`, `CORR_FILENAME_VISUAL_LURE`, `CORR_DISGUISED_IMAGE_LURE`, `CONTENT_CLICK_LURE`, info rules `VISUAL_QR_PRESENT`, `VISUAL_QR_NON_WEB`; URL checks `DECEPTIVE_HOSTNAME`, `SUSPICIOUS_SUBDOMAIN`, `MANY_HYPHENS`. All go through the existing weights, correlation cap and severity guards. Engine version 5.1.0.

## Fixtures (harmless, synthetic; `npm run fixtures:visual` regenerates them, needs Python + pillow/qrcode/reportlab)
`test-phishing-image.{png,jpg,webp}`, `test-normal-image.{png,jpg,webp}`, `test-qr-{phishing,benign,wifi,text,multi}.png`, `test-large-image.png`, `test-corrupt-image.png`, `test-scanned-phishing.pdf`, `test-normal-scanned-document.pdf`, `test-mixed-phishing.pdf`, `test-pdf-qr.pdf`, `test-pdf-text-and-same-ocr.pdf`, `test-text-only.pdf`, `test-multipage-scanned.pdf`. Domains are reserved (`.test`, `example.org`) or RFC 5737 documentation addresses.

## Verification record (build environment: Linux, Node 22, Electron 31.7.7 runtime)
| Check | Result |
|---|---|
| `npm run typecheck` | PASS |
| `npm test` | PASS - 477/477 (424 pre-existing + 53 new) |
| `npm run build` | PASS |
| OCR/QR/PDF pipeline under **Electron's runtime** (`npm run verify:ocr`) | PASS (6/6) |
| Windows installer (`npm run package`) | **NOT VERIFIED** - electron-builder needs Wine to produce the .exe on Linux; the `win-unpacked` stage was reached but not completed |
| Windows runtime (install, Downloads monitoring, alerts, quarantine, restore with the new code) | **NOT VERIFIED** |

### Windows checklist
`npm install` -> `npm run typecheck` -> `npm test` -> `npm run build` -> `npm run build:electron` -> `npm run verify:ocr` -> `npm run package` -> install `SafePeek-Setup-1.1.0.exe` -> copy the fixtures into Downloads: confirm test-phishing-image.png / test-scanned-phishing.pdf / test-qr-phishing.png are High/Critical with *Visual Analysis* shown, test-normal-image.png / test-qr-benign.png are Safe, Quarantine and Restore still work. Check that `sharp` loaded (Visual Analysis appears; otherwise OCR status shows *Unsupported*).

## Known limitations
- OCR is English-only and is not guaranteed to read every image, font, language, handwriting or low-quality scan.
- Vector-drawn text in PDFs, image masks and PDF page rotation are not handled; images over the pixel limits are skipped (reported as partial).
- QR decoding uses jsQR (single code per window, tiled search); damaged, tiny or heavily distorted codes may not decode.
- Static analysis, OCR and QR evidence is best-effort and offline: no URL reputation or network lookups are made (local-first), so a malicious page with a clean-looking address is not detected.
- The Windows build is untested (see above).
