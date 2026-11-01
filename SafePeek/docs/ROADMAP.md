# Roadmap

## Delivered (v1.0.0 release candidate)
- **Phase 1** Desktop foundation: Electron / React / TypeScript shell, screens, settings.
- **Phase 2** File monitoring: Downloads + custom folders, stability check, temp-file filter, dedupe, notifications.
- **Phase 3** Static analysis: SHA-256, magic bytes, mismatch, double extensions, PE / PDF / Office / ZIP / script, URL extraction.
- **Phase 4** Content intelligence: PDF / Office / text extraction, local OCR, archive trees, safe preview.
- **Phase 5** Threat engine: deterministic rules, heuristic score, confidence, evidence, recommendations.
- **Phase 6** Explanations, alerts, quarantine / restore / delete, safe open, protection settings, threat history.
- **Phase 7A** Integration, race-condition fixes, IPC and path hardening, persistence resilience.
- **Phase 7B** Final release correction: documentation, release configuration review, branding and secrets audit (`docs/PHASE7B.md`).

## Before a public release
1. Build and test on Windows 10/11 x64 (`npm run package`); record results in `docs/FINAL_TEST_REPORT.md`.
2. Decide on code signing.
3. Verify toasts, `safeStorage`, start-with-Windows and the installer on Windows.

## Possible future work (not planned or committed)
- Utility process for parsers and the threat engine with real preemptive timeouts.
- Tray / run-in-background when the window is closed.
- Garbage collection of per-file result caches; handling of files deleted outside SafePeek.
- RAR / 7z / GZIP listing; legacy Office macro inspection; PDF OCR.
- Calibration of rule weights against a labelled corpus.
