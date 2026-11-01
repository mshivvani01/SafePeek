import fs from 'node:fs';
import path from 'node:path';
import type { ThreatAssessment } from '../threat/types';
import { validateAiOutput } from './explanationEngine';
import { buildDisclosure, buildPrompt, providerHost } from './promptBuilder';
import { buildLocalExplanation, coerceAssessment } from './localExplanation';
import type { SecretStore } from './secretStore';
import type { AiDisclosure, AiSettings, ExplanationBundle, ThreatExplanation } from './types';

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal; redirect?: 'error' | 'follow' | 'manual' }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;
export interface ExplanationDeps {
  dir: string; log(m: string): void; getAssessment(id: string): Promise<ThreatAssessment | null>; getAiSettings(): AiSettings; secrets: SecretStore;
  fetchFn?: FetchLike; timeoutMs?: number; now?: () => string;
}
const safeId = (id: unknown): id is string => typeof id === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(id);
export const AI_SECRET = 'ai-api-key';
export const MODEL_RE = /^[A-Za-z0-9._:-]{1,80}$/;

/**
 * Explanation layer. The local engine ALWAYS works (offline, no key). The optional provider is only contacted when ALL of: AI explanation is enabled,
 * a provider + model + stored API key exist, and the user explicitly requested it for one file with `confirmed: true` after seeing the disclosure.
 * It receives evidence metadata only (never the file) and cannot change the Phase 5 status or score.
 */
export class ExplanationService {
  constructor(private deps: ExplanationDeps) {}
  private async assessment(id: string): Promise<ThreatAssessment | null> { const raw = await this.deps.getAssessment(id); return raw && typeof raw === 'object' ? coerceAssessment(raw) : null; }
  private now = () => (this.deps.now ?? (() => new Date().toISOString()))();
  private file(id: string) { return path.join(this.deps.dir, `${id}.json`); }

  private readAi(id: string, a: ThreatAssessment): { ai: ThreatExplanation } | null {
    try { const o = JSON.parse(fs.readFileSync(this.file(id), 'utf8')); if (o?.analyzedAt === a.analyzedAt && o?.ai?.generatedBy === 'OPTIONAL_AI') return { ai: o.ai as ThreatExplanation }; } catch { /* none stored */ }
    return null;
  }
  async get(id: string): Promise<ExplanationBundle | null> {
    if (!safeId(id)) return null;
    const a = await this.assessment(id); if (!a) return null;
    const stored = this.readAi(id, a); const s = this.deps.getAiSettings();
    return { fileId: id, status: a.status, score: a.score, analyzedAt: a.analyzedAt, local: buildLocalExplanation(a, this.now()), ai: stored?.ai, aiOutcome: stored ? 'USED' : s.enabled ? 'NOT_REQUESTED' : 'OFF' };
  }
  async disclosure(id: string): Promise<AiDisclosure | null> {
    if (!safeId(id)) return null; const a = await this.assessment(id); const s = this.deps.getAiSettings(); if (!a || s.provider === 'none') return null;
    return buildDisclosure(a, s);
  }
  readiness(): { ready: boolean; reason?: string } {
    const s = this.deps.getAiSettings();
    if (!s.enabled) return { ready: false, reason: 'AI explanation is turned off.' };
    if (s.provider === 'none') return { ready: false, reason: 'No provider selected.' };
    if (!MODEL_RE.test(s.model)) return { ready: false, reason: 'No model configured.' };
    if (!this.deps.secrets.has(AI_SECRET)) return { ready: false, reason: 'API key not configured.' };
    return { ready: true };
  }
  /** Explicit, per-file, user-confirmed request. Never called automatically. */
  async requestAi(id: string, confirmed: boolean): Promise<ExplanationBundle | null> {
    const base = await this.get(id); if (!base) return null;
    const fail = (aiOutcome: ExplanationBundle['aiOutcome'], aiMessage: string): ExplanationBundle => ({ ...base, ai: undefined, aiOutcome, aiMessage });
    const r = this.readiness(); if (!r.ready) return fail(this.deps.getAiSettings().enabled ? 'FAILED' : 'OFF', r.reason!);
    if (confirmed !== true) return fail('NOT_REQUESTED', 'Confirmation is required before any evidence is sent to the provider.');
    const a = (await this.assessment(id))!; const s = this.deps.getAiSettings(); const key = this.deps.secrets.get(AI_SECRET);
    if (!key) return fail('FAILED', 'The stored API key could not be read.');
    const { system, user } = buildPrompt(a, s);
    let text: string;
    try { text = await this.call(s, key, system, user); } catch (e) { this.deps.log(`[SafePeek] AI explanation request failed: ${(e as Error).message}`); return fail('FAILED', `The provider request failed (${(e as Error).message}). The local explanation is still available.`); }
    const v = validateAiOutput(text, a);
    if (!v.ok) { this.deps.log(`[SafePeek] AI explanation rejected: ${v.reason}`); return fail('REJECTED', `The AI response was rejected (${v.reason}). The local explanation is shown instead.`); }
    const ai: ThreatExplanation = { ...v.value, technicalDetails: base.local.technicalDetails, confidenceExplanation: base.local.confidenceExplanation, generatedBy: 'OPTIONAL_AI', generatedAt: this.now(), provider: s.provider, model: s.model };
    try { fs.mkdirSync(this.deps.dir, { recursive: true }); fs.writeFileSync(this.file(id), JSON.stringify({ analyzedAt: a.analyzedAt, ai }), 'utf8'); } catch (e) { this.deps.log(`[SafePeek] Could not store AI explanation: ${(e as Error).message}`); }
    return { ...base, ai, aiOutcome: 'USED' };
  }

  private async call(s: AiSettings, key: string, system: string, user: string): Promise<string> {
    const host = providerHost(s.provider); const f: FetchLike | undefined = this.deps.fetchFn ?? (globalThis.fetch as unknown as FetchLike | undefined);
    if (!f) throw new Error('network unavailable');
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), this.deps.timeoutMs ?? 25_000);
    try {
      const req: { url: string; headers: Record<string, string>; body: unknown } = s.provider === 'anthropic'
        ? { url: `https://${host}/v1/messages`, headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' }, body: { model: s.model, max_tokens: 800, system, messages: [{ role: 'user', content: user }] } }
        : { url: `https://${host}/v1/chat/completions`, headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` }, body: { model: s.model, max_tokens: 800, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] } };
      const res = await f(req.url, { method: 'POST', headers: req.headers, body: JSON.stringify(req.body), signal: ctl.signal, redirect: 'error' }); // never follow redirects: the request carries the API key
      if (!res.ok) throw new Error(`HTTP ${res.status}`); // the response body is never logged or surfaced (it could echo request data)
      const j = (await res.json()) as { content?: { type?: string; text?: string }[]; choices?: { message?: { content?: string } }[] };
      const out = s.provider === 'anthropic' ? j.content?.filter((c) => c.type === 'text').map((c) => c.text ?? '').join('') : j.choices?.[0]?.message?.content;
      if (typeof out !== 'string') throw new Error('unexpected response shape');
      return out;
    } finally { clearTimeout(t); }
  }
}
