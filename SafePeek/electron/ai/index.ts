export * from './types';
export { buildLocalExplanation } from './localExplanation';
export { buildPrompt, buildDisclosure, buildEvidencePayload, buildUntrustedSnippets, SYSTEM_PROMPT, providerHost } from './promptBuilder';
export { validateAiOutput } from './explanationEngine';
export { ExplanationService, AI_SECRET, MODEL_RE } from './explanationService';
export type { FetchLike, ExplanationDeps } from './explanationService';
export { SecretStore } from './secretStore';
export type { SecretCrypto } from './secretStore';
