# Phase 5 — Threat & Risk Detection Engine

> SafePeek's threat engine is a heuristic static/content-based detection system. It does not guarantee malware detection and does not replace a full antivirus, behavioral sandbox, or endpoint security product.

## Where it sits
```
Watcher -> AnalysisService (Phase 3 static) -> ContentService (Phase 4) -> ThreatService (Phase 5) -> userData/threat/<id>.json + FileRecord summary -> UI
```
* `electron/threat/threatEngine.ts` — `assessThreat(input)`: **pure, synchronous, deterministic** (no file system, network, processes, clock other than `analyzedAt`). Input = Phase 3 `AnalysisResult` + Phase 4 `ContentResult` (both already stored; nothing is re-read or re-scanned).
* `electron/threat/threatService.ts` — async queue (concurrency 1, yields to the event loop before the rules run). Triggered by `ContentService.onFinished` (any content outcome) or `AnalysisService.onFailed` (static analysis failed -> an `UNKNOWN` assessment is recorded). Resumes unfinished files on start-up. Persists the full assessment and writes summary fields + `riskLevel` on the FileRecord.
* `electron/threat/rules/*` — rule modules (`file`, `executable` + `scriptContent`, `document` = pdf/office/html, `archive`, `url`, `content`, `socialEngineering` = correlation). Each rule is `(ctx) => RuleFinding[]`; rules never compute the final score. A rule that throws is isolated and lowers confidence.
* `electron/threat/urlAnalyzer.ts` — local URL heuristics (strings only; no DNS, no fetch). `lure.ts` — phrase library + script sniffing. `scoring.ts` — all weights, caps and thresholds.
* IPC (read-only / by id): `threat:get(id)`, `threat:rerun(id)`; preload `getThreat`, `rerunThreat`. The renderer never supplies paths, rules or scores.

## Result model (`ThreatAssessment`)
`status` (SAFE, LOW_RISK, SUSPICIOUS, HIGH_RISK, CRITICAL, UNKNOWN), `score` 0-100, `confidence` 0-100, `headline`, `indicators[]` (id, ruleId, category, severity INFO..CRITICAL, title, description, evidence, source, points actually contributed, correlated), `reasons[]` (short "why" sentences linked to indicators), `categories[]` (ranked), `evidence[]` (typed items per indicator), `recommendations[]`, `coverage` (static / content / threat), `breakdown` (every contribution with weight -> applied and why), `limitations[]`, `disclaimer`, `analyzedAt`, `engineVersion`, `scoreKind: 'heuristic'`. Phase 6 should consume exactly this structure.

Categories (extensible in `THREAT_CATEGORIES`): MALWARE, PHISHING, SCAM, SOCIAL_ENGINEERING, SUSPICIOUS_DOCUMENT, SUSPICIOUS_EXECUTABLE, SUSPICIOUS_SCRIPT, MALICIOUS_URL, ARCHIVE_RISK, MACRO_RISK, OBFUSCATION, FILE_TYPE_MISMATCH, EXECUTION_RISK, CREDENTIAL_THEFT, FINANCIAL_FRAUD, UNKNOWN.

## Scoring methodology (`scoring.ts`)
The score is a **heuristic risk score — how many and how severe the suspicious indicators are. It is not a probability of malware and is not calibrated.**
1. Each rule emits a raw weight (INFO findings have weight 0 and never change the score).
2. **De-duplication**: findings sharing a `dedupeKey` describe the same evidence (e.g. "login" in a URL and "verify your password" in text); the strongest counts fully, the others 25%.
3. **Caps** per group (`url` 38, `content-lure` 60, `pe` 30, `script-content` 55, `archive` 62).
4. **Executable multiplier** x1.15 for non-base findings on a real executable/script.
5. **Diminishing returns**: the n-th largest contribution is multiplied by 0.9^n.
6. **Correlation bonus**: findings built from independent evidence (text + suspicious link, macro + "enable content", PDF script + auto-open, download + execute) are added, total capped at 35.
7. **Breadth bonus**: +8 / +14 / +18 for 3 / 4 / 5+ independent categories.
8. Clamp to 100, then **severity guards**: HIGH_RISK needs at least one HIGH indicator; CRITICAL needs two HIGH (or one CRITICAL). Many weak signals therefore cannot reach an alarming verdict.

| Score | Status |
|---|---|
| 0-19 | SAFE (UI wording: "No suspicious indicators detected" / "No indicators") |
| 20-39 | LOW_RISK |
| 40-59 | SUSPICIOUS |
| 60-79 | HIGH_RISK |
| 80-100 | CRITICAL |
`UNKNOWN` replaces SAFE/LOW whenever analysis was incomplete (below) and has no score shown. The full per-indicator breakdown is stored and shown in the UI ("How the score was calculated").

## Confidence vs. risk score
*Risk score* = how many and how severe the indicators are. *Confidence* = how complete and reliable the analysis was (starts at 95, reduced for partial/failed/truncated/unsupported content, failed static analysis, encrypted PDFs/archives, low OCR confidence, executables [no behavior, no signature verification], failed rule groups). They are independent: a failed analysis has score 0 and confidence ~5.

## Partial / unknown analysis
Static `partial|failed`, content `PARTIAL|TRUNCATED|FAILED|PENDING`, or `UNSUPPORTED` content on a file type that should have been readable => `analysisComplete = false`, an INFO indicator "Analysis incomplete" is added, and a result with no real findings becomes `UNKNOWN` ("The file could not be fully inspected. No malicious indicators were detected in the available analysis."). Findings that *were* detected are still reported with their normal status. Executables are intentionally never content-extracted (Phase 4), so `UNSUPPORTED` is expected for them and does not make the assessment incomplete (confidence is reduced instead).

## Rules (main families)
* **File / extension**: `FILE_EXEC_DISGUISED` (PE/ELF content under a non-executable extension, e.g. exe as .pdf/.jpg/.txt), `FILE_SCRIPT_DISGUISED`, `FILE_SCRIPT_IN_TEXT`, `FILE_ARCHIVE_DISGUISED`, `FILE_TYPE_MISMATCH` (generic, low), `FILE_DOUBLE_EXTENSION` (Phase 3 filename analysis; stronger when the content really is executable/script), `FILE_LURE_NAME`, bidi/space-padded names. Uses the Phase 3 *detected* type, never the extension alone.
* **Executable / PE**: `EXEC_FILE` (base weight; most executables are legitimate), `PE_PACKER_SECTIONS`, `PE_NETWORK_IMPORTS`, `PE_FEW_IMPORTS`, malformed/odd sections; `PE_SIGNATURE_INFO` is INFO only — **a signature block is never treated as trust** (Phase 3 does not verify signatures).
* **Script content** (text matching only, never executed): encoded PowerShell, download + execute, execution-policy bypass, hidden windows, security-tool tampering, injection APIs, persistence, LOLBins, backup deletion, WScript/ADODB droppers, obfuscation.
* **PDF**: JavaScript, OpenAction, JS + OpenAction (correlated), Launch, embedded files, other actions, encryption, odd metadata; links are INFO and go through URL analysis.
* **Office**: macros, ActiveX, embedded objects, remote template, external objects, UNC paths, remote resources; ordinary hyperlinks are INFO.
* **HTML**: password forms, form posting to an external site, obfuscated script, hidden iframes, meta refresh.
* **Archives**: executables, scripts, double extensions, Zip-Slip paths, nested/deep archives, disk images, encrypted entries, expansion ratio, and combinations (documents + executable, executable named like a document). Entries come from Phase 3's listing; nothing is extracted.
* **URLs** (one indicator per issue kind, not per link): risky scheme, UNC, HTTP, user@host trick, IP / obfuscated host, punycode, port, many subdomains, abused TLDs, shorteners, paste/file hosts, brand look-alike/typosquat (small local brand table — not a trust list), account/login wording on non-official domains, obfuscation, length, credential-like or redirect query parameters, link text vs. target mismatch.
* **Content (phishing/scam)**: urgency, credential requests, OTP requests, payment/fee requests, prize language, impersonation wording, with negation handling. Combination rules: urgency + credential request, salary + credential request, prize + fee, job/scholarship + fee, refund + bank details, invoice + urgent payment, untraceable payment methods, organization + urgency + request.
* **Correlation**: credential lure + suspicious link, scam text + link, macro + "enable content", active PDF + lure wording, download + execute in scripts.

## Recommendations
Deterministic actions from the status: `DO_NOT_OPEN`, `QUARANTINE` (advice only — Phase 5 never moves or deletes anything), `REVIEW_CONTENT`, `OPEN_WITH_CAUTION`, `NO_ACTION`, plus specific advice (do not enable macros; do not enter credentials).

## Limitations, false positives and false negatives
* Heuristic only. No signatures, sandbox, reputation data, cloud lookups or full cryptographic signature verification. Novel, obfuscated, encrypted, image-only or non-English content can be missed (**false negatives**); a clean result never means safe.
* Legitimate documents (real security notices, HR/finance letters, installers, forms with JavaScript, scripts that download things) can score above SAFE (**false positives**). Weights were chosen so single keywords stay at INFO/LOW and an ordinary installer stays LOW_RISK, but this is hand-tuned, not measured on a corpus.
* Phrase rules are English-oriented; the brand table is small; PE analysis is DLL-level (no function-level imports, entropy or resources); PDFs are scanned by token, so obfuscated names/encrypted object streams are invisible; OLE2 (.doc/.xls) macros are not inspected; archives other than ZIP/JAR are not listed.
* Thresholds, weights and caps are untuned defaults; changing them is a one-file change (`scoring.ts`, rule weights).

## Privacy and security model
Everything runs locally and offline. No file, text, URL or hash leaves the machine; there is no VirusTotal or AI service call. File content is untrusted data: it is only matched against patterns, rendered by the UI as React text nodes, never executed, opened, extracted to disk or followed. A test enforces that `electron/threat` contains no network/process/`eval` APIs. IPC accepts only a file id.
