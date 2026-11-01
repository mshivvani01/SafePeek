/** One place for the wording shown when Windows (or any OS) refuses a file operation. SafePeek never asks for administrator rights to get around these. */
export const FILE_IN_USE = 'File is currently in use. SafePeek will retry or allow you to rescan later.';
export const FILE_ACCESS_DENIED = 'SafePeek does not have permission to access this file, or another program is holding it. SafePeek does not ask for administrator rights; you can rescan later.';
export const FILE_MISSING = 'The file no longer exists at the expected location.';

export const fsCode = (e: unknown): string => String((e as NodeJS.ErrnoException | undefined)?.code ?? '');
export const isLockedOrDenied = (e: unknown): boolean => ['EBUSY', 'EPERM', 'EACCES'].includes(fsCode(e));

/** Plain-language explanation of a filesystem error. Never includes the raw error text for the well-known cases (it can contain paths). */
export function describeFsError(e: unknown): string {
  const c = fsCode(e);
  if (c === 'EBUSY') return FILE_IN_USE;
  if (c === 'EPERM' || c === 'EACCES') return FILE_ACCESS_DENIED;
  if (c === 'ENOENT') return FILE_MISSING;
  if (c === 'ENOSPC') return 'There is not enough free disk space to finish this action.';
  if (c === 'ENAMETOOLONG') return 'The file path is too long for Windows to handle.';
  return e instanceof Error ? e.message : String(e);
}
