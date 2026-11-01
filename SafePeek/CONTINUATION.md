# SafePeek v1.1.0 (Phase 8 on top of the v1.0.0 release candidate)

> **Phase 8 status: implemented.** See [`docs/PHASE8.md`](docs/PHASE8.md) for what is verified and what is not (notably: the Windows installer and Windows runtime were NOT verified in the build environment, which was Linux). To verify on Windows: `npm install`, `npm run typecheck`, `npm test`, `npm run build`, `npm run build:electron && npm run verify:ocr`, `npm run package`, install `release/SafePeek-Setup-1.1.0.exe`, then walk the Phase 8 checklist in `docs/PHASE8.md`. If `sharp`'s Windows binary is missing after install, run `npm install --os=win32 --cpu=x64 sharp@0.33.5`.

# (v1.0.0 notes below are unchanged)

| Phase | Status |
|---|---|
| Phase 1 - desktop foundation | COMPLETE |
| Phase 2 - automatic file monitoring | COMPLETE |
| Phase 3 - static file analysis | COMPLETE |
| Phase 4 - content intelligence + safe preview + OCR | COMPLETE |
| Phase 5 - threat & risk engine | COMPLETE |
| Phase 6 - explanations, alerts, quarantine, protection | COMPLETE |
| Phase 7A - integration + runtime hardening | COMPLETE |
| Phase 7B - final release correction | COMPLETE (documentation, release configuration, branding/secrets audit; see limits below) |

SafePeek is feature-complete as a release candidate. **It has not been run on Windows by the authors of this pass**, and the installer has never been built. Treat "release candidate" literally: the remaining step is a Windows run (see "Next steps").

Do not rebuild; extend. Start with `README.md`, then `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/THREAT_ENGINE.md`, `docs/PHASE6.md`, `docs/PHASE7A.md`, `docs/PHASE7B.md`. User-facing help is `docs/USER_GUIDE.md`. The old per-phase handoff notes are in `docs/CONTINUATION_HISTORY.md`.

## Pipeline (one chain, wired in `electron/main.ts`)
```
FILE -> watcher (stability, temp filter, dedupe) -> static analysis -> content analysis -> threat engine (authoritative verdict)
     -> history + explanation (local; optional AI wording) -> alert + notification -> user action: open / quarantine / restore / delete
```

## Verified
"Verified" means a command or run was observed to succeed. Items marked *(prior)* were reported by earlier phases in their own Linux sandbox and were **not re-run in the 7B pass** because dependencies could not be installed (see Not verified).

- *(prior, Phase 7A)* `npm install`, `npm run typecheck`, `npm test` (424 tests, 19 files), `npm run build`.
- *(prior, Phase 7A)* Real Electron 31 under Xvfb on Linux: window loads; preload bridge exposes 43 functions; `require`/`process` undefined in the renderer; a malformed id and invalid settings are rejected; a disguised `invoice.pdf.exe` in a watched folder was assessed HIGH_RISK (71/100) and raised an alert; opening it without confirmation was refused; quarantine succeeded and the renderer-visible record contained no vault path.
- *(this pass)* Every one of the 134 `.ts`/`.tsx` files under `electron/`, `src/` and `tests/` parses without syntax errors (TypeScript `transpileModule`; this is a syntax check, **not** a type check).
- *(this pass)* `package.json` is valid JSON; Electron Builder configuration inspected: `productName` SafePeek, `appId` com.safepeek.app, version 1.0.0, NSIS target, x64, `build/icon.ico` (16-256 px, 7 sizes), `build/icon.png` (512x512), artifact name `SafePeek-Setup-1.0.0.exe`.
- *(this pass)* Branding and secrets audit over the source tree: no real credentials; the only `sk-...` strings are fake values in `tests/ai.test.ts`.

## Not verified
- **`npm install`, `npm run typecheck`, `npm test`, `npm run build` in the 7B pass**: the sandbox had no npm registry access (HTTP 403 for every package), so dependencies could not be installed. The test and build results above are from Phase 7A. The 7B code edits were limited to a few message strings and comments (listed in `docs/PHASE7B.md`) and were syntax-checked only.
- `npm run package` / the NSIS installer: never executed anywhere.
- **Windows runtime**: toast notifications and click-to-navigate, `safeStorage` key encryption, junctions, ACL and exclusive-lock behaviour, start-with-Windows.
- Windows installer install/uninstall/upgrade; SmartScreen behaviour of an unsigned installer.
- Restore, permanent delete and settings persistence clicked through the real window.
- Visual appearance (no screenshots were taken in 7B).
- Real Anthropic/OpenAI calls (tests use a mocked `fetch`).
- Lint: the project defines no lint script.

## Next steps (in order)
1. On Windows 10/11 x64: `npm install`, `npm run typecheck`, `npm test`, `npm run build`, `npm run package`. Fix whatever surfaces.
2. Install the produced `release/SafePeek-Setup-1.0.0.exe`; walk `docs/USER_GUIDE.md` and tick off `docs/FINAL_TEST_REPORT.md`.
3. Decide on code signing (`win.certificateFile` / Azure Trusted Signing). An unsigned installer triggers SmartScreen.
4. Optional hardening: utility process for parsers and the threat engine (real preemptive timeouts), garbage collection of `userData/{content,threat,explanations}`, `unlink` handling, tray / run-in-background.

## Behaviours worth knowing
- Closing the SafePeek window **quits** the app (`window-all-closed` -> `app.quit()`); there is no tray. Monitoring runs only while SafePeek is running. "Start SafePeek when I sign in" launches it minimized.
- Defaults: AI explanation OFF, automatic quarantine OFF, confirmation before opening High risk ON, informational alerts OFF.
- The `minimizeToTray` key exists in the settings schema but nothing uses it and the UI does not expose it.
- Persistence: `userData/` holds the monitoring state, `content/`, `threat/`, `security/{settings,alerts,history,secrets}.json`, `quarantine/{quarantine.json,files/}`, `explanations/`.

## Known limitations
See `docs/SECURITY.md` ("Limitations"), `docs/THREAT_ENGINE.md`, `docs/PHASE6.md`, `docs/PHASE7A.md` and the "Partial / known limitations" sections of `docs/CONTINUATION_HISTORY.md`.
