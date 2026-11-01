import fs from 'node:fs';
import { createHash } from 'node:crypto';

/** Streaming SHA-256 computed locally (constant memory). */
export function sha256File(file: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    const s = fs.createReadStream(file);
    s.on('data', (c) => h.update(c)).on('error', reject).on('end', () => resolve(h.digest('hex')));
  });
}

export async function readHead(file: string, max: number): Promise<Buffer> {
  const fh = await fs.promises.open(file, 'r');
  try { const b = Buffer.alloc(max); const { bytesRead } = await fh.read(b, 0, max, 0); return b.subarray(0, bytesRead); } finally { await fh.close(); }
}
