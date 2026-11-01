import type { LiveState } from '../../hooks';

/** Shared loading / error banner for list pages. Empty states stay with each page because their wording differs. */
export default function LoadState({ state, what }: { state: Pick<LiveState<unknown>, 'loading' | 'error' | 'reload'>; what: string }) {
  if (state.error) return <div className="banner banner-warn" role="alert">Could not load {what}. {state.error} <button className="btn" onClick={state.reload}>Try again</button></div>;
  if (state.loading) return <div className="banner banner-info" role="status" aria-live="polite">Loading {what}…</div>;
  return null;
}
