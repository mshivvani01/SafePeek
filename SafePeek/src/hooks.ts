import { useCallback, useEffect, useRef, useState } from 'react';

export interface LiveState<T> { data: T; loading: boolean; error: string | null; reload(): void }
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e)).replace(/^Error invoking remote method '[^']*': (Error: )?/, '');

export function useAsync<T>(fn: () => Promise<T>, initial: T): T {
  const [v, setV] = useState<T>(initial);
  useEffect(() => { let on = true; fn().then((r) => on && setV(r)).catch((e) => console.error('[SafePeek] load failed:', msg(e))); return () => { on = false; }; }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return v;
}

/** Loads data and reloads whenever the main-process agent pushes a change. Exposes loading + error so pages can show real states instead of silently staying stale. */
export function useLiveState<T>(fn: () => Promise<T>, initial: T, deps: unknown[] = []): LiveState<T> {
  const [data, setData] = useState<T>(initial);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true); const fnRef = useRef(fn); fnRef.current = fn;
  const load = useCallback(() => {
    fnRef.current().then((r) => { if (alive.current) { setData(r); setError(null); setLoading(false); } })
      .catch((e) => { console.error('[SafePeek] load failed:', msg(e)); if (alive.current) { setError(msg(e) || 'Something went wrong while loading.'); setLoading(false); } });
  }, []);
  useEffect(() => {
    alive.current = true; load();
    // A burst of main-process change events (several downloads at once) triggers one reload, not one per event.
    let timer: ReturnType<typeof setTimeout> | null = null;
    const off = window.safepeek?.onChange?.(() => { if (timer) return; timer = setTimeout(() => { timer = null; load(); }, 200); });
    return () => { alive.current = false; if (timer) clearTimeout(timer); off?.(); };
  }, [load, ...deps]); // eslint-disable-line react-hooks/exhaustive-deps
  return { data, loading, error, reload: load };
}

/** Backwards-compatible: data only (errors are logged, last good data is kept). */
export function useLive<T>(fn: () => Promise<T>, initial: T): T { return useLiveState(fn, initial).data; }
