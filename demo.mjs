#!/usr/bin/env node
/**
 * Stackmail end-to-end demo
 *
 * Spins through the full flow: register → send → inbox → preview → decrypt → claim.
 * Requires the server to be running locally (see README).
 *
 * Usage:
 *   node demo.mjs                         # default http://127.0.0.1:8800
 *   node demo.mjs http://127.0.0.1:9000   # custom base URL
 */

import { createECDH, createPrivateKey, createSign, createHash, randomBytes } from 'node:crypto';
import { execSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { encryptMail, decryptMail } from './packages/crypto/dist/index.js';

const BASE = process.argv[2] ?? 'http://127.0.0.1:8800';

// ─── Key setup ───────────────────────────────────────────────────────────────
// One secp256k1 keypair serves both purposes:
//   - signing auth headers (createSign)
//   - ECDH encryption/decryption (createECDH)

const ecdh = createECDH('secp256k1');
ecdh.generateKeys();
const privkeyRaw = ecdh.getPrivateKey();       // 32-byte Buffer
const pubkeyHex  = ecdh.getPublicKey('hex', 'compressed'); // 33-byte hex

// Import the raw private key as a Node.js KeyObject for signing
function makeSigningKey(rawPriv) {
  const oidVal = Buffer.from('2b8104000a', 'hex'); // secp256k1 OID: 1.3.132.0.10
  const oidEnc = Buffer.concat([Buffer.from([0x06, oidVal.length]), oidVal]);
  const ctx    = Buffer.concat([Buffer.from([0xa0, oidEnc.length]), oidEnc]);
  const inner  = Buffer.concat([Buffer.from([0x02,0x01,0x01, 0x04,0x20]), rawPriv, ctx]);
  const der    = Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
  return createPrivateKey({ key: der, format: 'der', type: 'sec1' });
}
const signingKey = makeSigningKey(privkeyRaw);

function sign(message) {
  return createSign('SHA256').update(message).sign(
    { key: signingKey, dsaEncoding: 'ieee-p1363' }
  ).toString('hex');
}

function hashSecret(hex) {
  return createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
}

// ─── Derive STX address ───────────────────────────────────────────────────────
writeFileSync('/tmp/_stackmail_addr.mjs',
  `import{pubkeyToStxAddress}from'${process.cwd()}/packages/server/dist/auth.js';` +
  `process.stdout.write(pubkeyToStxAddress('${pubkeyHex}'));`);
const myAddress = execSync('node /tmp/_stackmail_addr.mjs').toString().trim();

// ─── Auth header builder ──────────────────────────────────────────────────────
function authHeader(action, messageId) {
  const payload = {
    action,
    address: myAddress,
    timestamp: Date.now(),
    ...(messageId ? { messageId } : {}),
  };
  const signature = sign(JSON.stringify(payload));
  return Buffer.from(JSON.stringify({ pubkey: pubkeyHex, payload, signature })).toString('base64');
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function hr(title) { console.log(`\n${'─'.repeat(50)}\n  ${title}\n${'─'.repeat(50)}`); }
function ok(label, val)  { console.log(`  ✅ ${label}${val !== undefined ? ':  ' + val : ''}`); }
function err(label, val) { console.log(`  ❌ ${label}${val !== undefined ? ':  ' + val : ''}`); process.exitCode = 1; }
function check(label, cond, detail) { cond ? ok(label, detail) : err(label, detail); }

async function api(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, opts);
  const body = await res.json();
  return { status: res.status, body };
}

// ─── Demo ─────────────────────────────────────────────────────────────────────
console.log(`\nStackmail demo  →  ${BASE}`);
console.log(`My STX address  :  ${myAddress}`);
console.log(`My pubkey       :  ${pubkeyHex}`);

// 1. Health check
hr('1. Health check');
const health = await api('/health');
check('GET /health → 200', health.status === 200);

// 2. Auth to /inbox — registers our pubkey with the server
hr('2. Register via GET /inbox');
const inbox0 = await api('/inbox', {
  headers: { 'x-stackmail-auth': authHeader('get-inbox') },
});
check('GET /inbox → 200', inbox0.status === 200);
check('inbox is array', Array.isArray(inbox0.body.messages), `(${inbox0.body.messages?.length} messages)`);

// 3. Payment info — confirm pubkey is stored
hr('3. GET /payment-info (confirm registration)');
const pi = await api(`/payment-info/${myAddress}`);
check('GET /payment-info → 200', pi.status === 200);
check('recipientPublicKey matches', pi.body.recipientPublicKey === pubkeyHex);
console.log(`  amount: ${pi.body.amount} sats   fee: ${pi.body.fee} sats`);

// 4. Send a message to ourselves
hr('4. POST /messages (send to self)');
const secretHex       = randomBytes(32).toString('hex');
const hashedSecretHex = hashSecret(secretHex);

const encryptedPayload = encryptMail(
  { v: 1, secret: secretHex, subject: 'Hello from the demo!', body: 'End-to-end stackmail is working 🎉' },
  pubkeyHex,
);

const sendProof = JSON.stringify({
  hashedSecret: hashedSecretHex,
  forPrincipal: myAddress, // sender = us (sending to ourselves)
  amount: '1000',
});

const sent = await api(`/messages/${myAddress}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-x402-payment': sendProof },
  body: JSON.stringify({ from: myAddress, encryptedPayload }),
});
check('POST /messages → 200', sent.status === 200);
check('got messageId', typeof sent.body.messageId === 'string', sent.body.messageId);
const messageId = sent.body.messageId;

// 5. Check inbox
hr('5. GET /inbox (message appears)');
const inbox1 = await api('/inbox', {
  headers: { 'x-stackmail-auth': authHeader('get-inbox') },
});
const entry = inbox1.body.messages?.find(m => m.id === messageId);
check('message is in inbox', !!entry);
check('message is unclaimed', entry?.claimed === false);

// 6. Preview
hr('6. GET /inbox/:id/preview (fetch encrypted payload)');
const preview = await api(`/inbox/${messageId}/preview`, {
  headers: { 'x-stackmail-auth': authHeader('get-inbox') },
});
check('GET /preview → 200', preview.status === 200);
check('encryptedPayload.v === 1', preview.body.encryptedPayload?.v === 1);
check('hashedSecret matches', preview.body.hashedSecret === hashedSecretHex);

// 7. Decrypt
hr('7. Decrypt (client-side)');
const decrypted = decryptMail(preview.body.encryptedPayload, privkeyRaw.toString('hex'));
check('subject', decrypted.subject === 'Hello from the demo!', decrypted.subject);
check('body', decrypted.body === 'End-to-end stackmail is working 🎉', decrypted.body);
check('secret matches', decrypted.secret === secretHex);

// 8. Claim with wrong secret → 400
hr('8. POST /inbox/:id/claim  (wrong secret → rejected)');
const wrongClaim = await api(`/inbox/${messageId}/claim`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-stackmail-auth': authHeader('claim-message', messageId) },
  body: JSON.stringify({ secret: randomBytes(32).toString('hex') }),
});
check('wrong secret → 400', wrongClaim.status === 400, wrongClaim.body.error);

// 9. Claim with correct secret → 200
hr('9. POST /inbox/:id/claim  (correct secret → claimed)');
const goodClaim = await api(`/inbox/${messageId}/claim`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-stackmail-auth': authHeader('claim-message', messageId) },
  body: JSON.stringify({ secret: decrypted.secret }),
});
check('claim → 200', goodClaim.status === 200);
check('returned message id', goodClaim.body.message?.id === messageId);

// 10. Double-claim → 409
hr('10. Claim again (already-claimed → 409)');
const dup = await api(`/inbox/${messageId}/preview`, {
  headers: { 'x-stackmail-auth': authHeader('get-inbox') },
});
check('already-claimed → 409', dup.status === 409, dup.body.error);

// ─── Summary ─────────────────────────────────────────────────────────────────
console.log('\n' + '═'.repeat(50));
if (process.exitCode) {
  console.log('  Some checks failed — see ❌ above');
} else {
  console.log('  All checks passed ✅');
}
console.log('═'.repeat(50) + '\n');
