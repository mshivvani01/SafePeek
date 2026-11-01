import type { FileRecord } from '../types/file';
import { storageService } from './storageService';

export const fileService = {
  list: (): Promise<FileRecord[]> => storageService.repository.listFiles(),
  get: (id: string) => storageService.repository.getFile(id),
  listActivity: () => storageService.repository.listActivity(),
  listQuarantine: () => storageService.repository.listQuarantine()
};

/** Phase 5: full threat assessment for one file (null in demo/browser mode or before the assessment exists). */
export const threatService = {
  get: async (id: string) => (window.safepeek?.getThreat ? window.safepeek.getThreat(id) : null),
  rerun: async (id: string) => { await window.safepeek?.rerunThreat?.(id); }
};

/** Phase 4: full extracted content for one file (loaded on demand; null in demo/browser mode or when not extracted yet). */
export const contentService = {
  get: async (id: string) => (window.safepeek?.getContent ? window.safepeek.getContent(id) : null),
  rerun: async (id: string) => { await window.safepeek?.rerunContent?.(id); }
};
