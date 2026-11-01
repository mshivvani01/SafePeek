import fs from 'node:fs';
import path from 'node:path';

/** OS-backed encryption (Electron safeStorage in production; a fake in tests). Secrets are NEVER written in plaintext: when encryption is unavailable, saving is refused. */
export interface SecretCrypto { isAvailable(): boolean; encrypt(plain: string): Buffer; decrypt(data: Buffer): string }
export class SecretStore {
  constructor(private file: string, private crypto: SecretCrypto) {}
  available(): boolean { try { return this.crypto.isAvailable(); } catch { return false; } }
  private read(): Record<string, string> { try { const o = JSON.parse(fs.readFileSync(this.file, 'utf8')); return o && typeof o === 'object' ? o : {}; } catch { return {}; } }
  private write(o: Record<string, string>) { fs.mkdirSync(path.dirname(this.file), { recursive: true }); fs.writeFileSync(`${this.file}.tmp`, JSON.stringify(o), 'utf8'); fs.renameSync(`${this.file}.tmp`, this.file); }
  has(name: string): boolean { return typeof this.read()[name] === 'string'; }
  set(name: string, value: string): void {
    if (!/^[a-z0-9-]{1,40}$/.test(name)) throw new Error('Invalid secret name');
    if (typeof value !== 'string' || value.length < 8 || value.length > 500 || /[\s\u0000-\u001f]/.test(value)) throw new Error('Invalid API key format');
    if (!this.available()) throw new Error('Secure storage is not available on this system, so the API key was not saved.');
    const o = this.read(); o[name] = this.crypto.encrypt(value).toString('base64'); this.write(o);
  }
  get(name: string): string | null { const v = this.read()[name]; if (typeof v !== 'string') return null; try { return this.crypto.decrypt(Buffer.from(v, 'base64')); } catch { return null; } }
  delete(name: string): void { const o = this.read(); delete o[name]; this.write(o); }
}
