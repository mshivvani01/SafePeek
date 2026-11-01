/** File names come from outside and can contain control or direction-override characters that spoof extensions (e.g. "invoice\u202Efdp.exe"). Strip them before showing a name anywhere. */
export const cleanDisplayName = (s: unknown): string => String(s ?? '').replace(/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '').slice(0, 200);
