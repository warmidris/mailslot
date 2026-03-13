import { createHash } from 'node:crypto';
import { decryptContent, encryptContent } from '@stacks/encryption';

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * The plaintext payload encrypted inside every message.
 * Both the payment secret and message content live here together,
 * so neither is accessible without the recipient's private key.
 */
export interface MailPayload {
  /** Schema version */
  v: 1;
  /** 32-byte hex HTLC preimage. hash256(secret) == hashedSecret in the payment. */
  secret: string;
  /** Optional subject line, max 100 chars */
  subject?: string;
  /** Message body */
  body: string;
}

/**
 * The encrypted envelope stored by the server and returned to the recipient.
 * This is the Stacks.js ECIES cipher object shape.
 */
export interface EncryptedMail {
  /** AES-CBC IV, 16 bytes hex */
  iv: string;
  /** Sender's ephemeral compressed secp256k1 pubkey, 33 bytes hex */
  ephemeralPK: string;
  /** AES-CBC ciphertext, usually hex */
  cipherText: string;
  /** HMAC-SHA256 over iv + ephemeralPK + cipherText */
  mac: string;
  /** Stacks.js records whether the plaintext was a string */
  wasString: boolean;
  /** Optional explicit ciphertext encoding, omitted for default hex */
  cipherTextEncoding?: 'hex' | 'base64';
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function stripHex(s: string): string {
  return s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Encrypt a MailPayload for a recipient identified by their compressed
 * secp256k1 public key (33 bytes hex, with or without 0x prefix).
 *
 * This is what the sender calls before POSTing to the mailbox server.
 */
export async function encryptMail(payload: MailPayload, recipientPubkeyHex: string): Promise<EncryptedMail> {
  const recipientPubkey = stripHex(recipientPubkeyHex);
  if (recipientPubkey.length !== 66) {
    throw new TypeError(`recipientPubkey must be 33 bytes (compressed), got ${recipientPubkey.length / 2}`);
  }
  const content = await encryptContent(JSON.stringify(payload), { publicKey: recipientPubkey });
  return JSON.parse(content) as EncryptedMail;
}

/**
 * Decrypt an EncryptedMail using the recipient's secp256k1 private key
 * (32 bytes hex, with or without 0x prefix).
 *
 * This is what the recipient calls after polling and receiving the ciphertext.
 */
export async function decryptMail(encrypted: EncryptedMail, privkeyHex: string): Promise<MailPayload> {
  const privateKey = stripHex(privkeyHex);
  if (privateKey.length !== 64) {
    throw new TypeError(`privkey must be 32 bytes, got ${privateKey.length / 2}`);
  }
  const plaintext = await decryptContent(JSON.stringify(encrypted), { privateKey });
  return JSON.parse(String(plaintext)) as MailPayload;
}

/**
 * Compute the HTLC hash that goes into the StackFlow payment proof.
 * hash = SHA-256(secret_bytes)
 *
 * Both sender (when creating the payment) and recipient (when verifying)
 * use this to confirm hash(secret) == hashedSecret.
 */
export function hashSecret(secretHex: string): string {
  const bytes = Buffer.from(stripHex(secretHex), 'hex');
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Verify that hash(secret) == hashedSecret.
 * Call this after decrypting to confirm the payment proof is consistent
 * with the encrypted secret before revealing.
 */
export function verifySecretHash(secretHex: string, hashedSecretHex: string): boolean {
  const computed = hashSecret(secretHex);
  const expected = stripHex(hashedSecretHex).toLowerCase();
  return computed === expected;
}
