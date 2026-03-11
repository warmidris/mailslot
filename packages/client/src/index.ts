export { StackmailClient, StackmailError } from './client.js';
export type {
  ClaimProofRecord,
  ClientConfig,
  DecryptedMessage,
  EncryptedMail,
  InboxEntry,
  MailMessage,
  MailPayload,
  PaymentInfo,
  PendingPayment,
  PollResult,
  SendOptions,
} from './types.js';
export { verifyPendingPaymentProof } from './sip018.js';
// Re-export crypto primitives for convenience
export { encryptMail, decryptMail, hashSecret, verifySecretHash } from '@stackmail/crypto';
