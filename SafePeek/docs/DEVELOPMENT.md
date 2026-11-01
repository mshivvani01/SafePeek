# Development

Requires Node.js 20+ and npm.

- `npm install`
- `npm run dev` : compiles `electron/`, starts Vite on :5173 (development only), launches Electron
- `npm run typecheck` : `tsc --noEmit` for the renderer, tests and Vite config
- `npm test` : Vitest
- `npm run build` : typecheck + compile `electron/` -> `dist-electron/` + Vite build -> `dist/`
- `npm run package` : build + Windows NSIS installer via electron-builder (output in `release/`; build on Windows)
- `npm run package:dir` : unpacked Windows app for a quick smoke test
- `npm run fixtures` : regenerate the synthetic sample files in `tests/fixtures` (except `job-offer.png`)

There is no lint script.

Conventions: no Node APIs in the renderer; every IPC channel validates its input and takes ids/booleans (never paths); detection decisions belong to `electron/threat` only; demo data lives only in `src/data/mockData.ts` and is used only in browser preview mode.

If `npm install` cannot download Electron (restricted network), set `ELECTRON_SKIP_BINARY_DOWNLOAD=1`; you will then be unable to launch or package the app.
