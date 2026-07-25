// ===== VoxCrypt / CipherView - Secure Cyber Evidence Communication =====
// Browser-native crypto: SHA-256 integrity + AES-GCM encryption + secure packaging.
// This simulates the VoxCrypt secure transmission and CipherView report-encryption
// workflows entirely client-side using the Web Crypto API.

const enc = new TextEncoder();
const dec = new TextDecoder();

export interface EncryptedPayload {
  ciphertext: string; // base64
  iv: string; // base64
  salt: string; // base64
  hash: string; // SHA-256 of plaintext, hex
  algorithm: 'AES-GCM';
  keyBits: 256;
  packaged: boolean;
  createdAt: string;
}

// SHA-256 → hex
export async function sha256Hex(data: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(data));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function toB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// CipherView: encrypt a forensic report / evidence blob
export async function encryptEvidence(plaintext: string, passphrase: string): Promise<EncryptedPayload> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const hash = await sha256Hex(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return {
    ciphertext: toB64(ciphertext),
    iv: toB64(iv),
    salt: toB64(salt),
    hash,
    algorithm: 'AES-GCM',
    keyBits: 256,
    packaged: true,
    createdAt: new Date().toISOString(),
  };
}

export async function decryptEvidence(payload: EncryptedPayload, passphrase: string): Promise<string> {
  const salt = fromB64(payload.salt);
  const iv = fromB64(payload.iv);
  const key = await deriveKey(passphrase, salt);
  const ciphertext = fromB64(payload.ciphertext);
  const plaintextBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return dec.decode(plaintextBuf);
}

export async function verifyIntegrity(plaintext: string, expectedHash: string): Promise<boolean> {
  const actual = await sha256Hex(plaintext);
  return actual === expectedHash;
}

// VoxCrypt: package an incident report into a secure transfer envelope
export interface SecureEnvelope {
  envelopeId: string;
  incidentId: string;
  payload: EncryptedPayload;
  integrityVerified: boolean;
  transferStatus: 'packaged' | 'transferred' | 'received';
  recipient: string;
}

export async function packageIncidentReport(
  report: Record<string, unknown>,
  passphrase: string,
  recipient: string,
): Promise<SecureEnvelope> {
  const plaintext = JSON.stringify(report, null, 2);
  const payload = await encryptEvidence(plaintext, passphrase);
  const integrityVerified = await verifyIntegrity(plaintext, payload.hash);
  return {
    envelopeId: `ENV-${Date.now().toString(36).toUpperCase()}`,
    incidentId: String(report.incidentId || report.id || 'INC-UNKNOWN'),
    payload,
    integrityVerified,
    transferStatus: 'packaged',
    recipient,
    };
}

// Random passphrase generator for demo transfers (256-bit)
export function generatePassphrase(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}
