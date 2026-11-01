import { DEFAULT_AI_SETTINGS, type AiProviderId, type AiSettings } from '../ai/types';
import { MODEL_RE } from '../ai/explanationService';
import { DEFAULT_SECURITY_SETTINGS, type SecuritySettings } from './types';
import { JsonStore } from './jsonStore';

interface SettingsFile { version: 1; security: SecuritySettings; ai: AiSettings }
const isFile = (x: unknown): x is SettingsFile => typeof x === 'object' && x !== null && (x as SettingsFile).version === 1 && typeof (x as SettingsFile).security === 'object' && typeof (x as SettingsFile).ai === 'object';
const bool = (v: unknown, d: boolean) => (typeof v === 'boolean' ? v : d);
const PROVIDERS: AiProviderId[] = ['none', 'anthropic', 'openai'];

/** Strict normalization: unknown keys are dropped, wrong types fall back to the (safe) defaults. */
export function normalizeSecurity(x: unknown, base: SecuritySettings = DEFAULT_SECURITY_SETTINGS): SecuritySettings {
  const o = (typeof x === 'object' && x ? x : {}) as Record<string, unknown>;
  return {
    notifyCritical: bool(o.notifyCritical, base.notifyCritical), notifyHigh: bool(o.notifyHigh, base.notifyHigh), notifySuspicious: bool(o.notifySuspicious, base.notifySuspicious),
    notifyInformational: bool(o.notifyInformational, base.notifyInformational), autoQuarantineCritical: bool(o.autoQuarantineCritical, base.autoQuarantineCritical),
    requireConfirmHighRisk: bool(o.requireConfirmHighRisk, base.requireConfirmHighRisk), explanationLevel: o.explanationLevel === 'technical' ? 'technical' : o.explanationLevel === 'simple' ? 'simple' : base.explanationLevel
  };
}
export function normalizeAi(x: unknown, base: AiSettings = DEFAULT_AI_SETTINGS): AiSettings {
  const o = (typeof x === 'object' && x ? x : {}) as Record<string, unknown>;
  const provider = PROVIDERS.includes(o.provider as AiProviderId) ? (o.provider as AiProviderId) : base.provider;
  const model = typeof o.model === 'string' && (o.model === '' || MODEL_RE.test(o.model)) ? o.model : base.model;
  // Enabling is only meaningful with a real provider; it can never be switched on while provider is 'none'.
  return { enabled: bool(o.enabled, base.enabled) && provider !== 'none', provider, model, shareFileName: bool(o.shareFileName, base.shareFileName), shareEvidenceSnippets: bool(o.shareEvidenceSnippets, base.shareEvidenceSnippets) };
}

export class SecuritySettingsStore {
  private store: JsonStore<SettingsFile>;
  constructor(file: string, log: (m: string) => void = () => undefined) {
    this.store = new JsonStore<SettingsFile>(file, () => ({ version: 1, security: { ...DEFAULT_SECURITY_SETTINGS }, ai: { ...DEFAULT_AI_SETTINGS } }), isFile, log);
    this.store.data = { version: 1, security: normalizeSecurity(this.store.data.security), ai: normalizeAi(this.store.data.ai) };
  }
  security(): SecuritySettings { return { ...this.store.data.security }; }
  ai(): AiSettings { return { ...this.store.data.ai }; }
  setSecurity(patch: unknown): SecuritySettings { this.store.data.security = normalizeSecurity(patch, this.store.data.security); this.store.save(); return this.security(); }
  setAi(patch: unknown): AiSettings { this.store.data.ai = normalizeAi(patch, this.store.data.ai); this.store.save(); return this.ai(); }
  flush() { return this.store.flush(); }
}
