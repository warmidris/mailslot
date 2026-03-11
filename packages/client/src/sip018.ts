import { createHash } from 'node:crypto';

type ClarityValue =
  | { type: 'uint'; value: number | bigint | string }
  | { type: 'principal'; value: string }
  | { type: 'buff'; value: string }
  | { type: 'none' }
  | { type: 'some'; value: ClarityValue }
  | { type: 'string-ascii'; value: string }
  | { type: 'tuple'; fields: Record<string, ClarityValue> };

type TypedField = { type: string; value?: unknown };
type TypedMessage = Record<string, TypedField>;

const C32_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const SIP018_PREFIX = Buffer.from('534950303138', 'hex'); // "SIP018"
const SF_VERSION = '0.6.0';

function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

function c32DecodeFixed(encoded: string, expectedBytes: number): Buffer {
  const result = Buffer.alloc(expectedBytes, 0);
  let carry = 0;
  let carryBits = 0;
  let byteIdx = expectedBytes - 1;

  for (let i = encoded.length - 1; i >= 0 && byteIdx >= 0; i--) {
    const ch = encoded[i].toUpperCase();
    const val = C32_CHARS.indexOf(ch);
    if (val < 0) throw new Error(`Invalid c32 character: ${ch}`);
    carry |= (val << carryBits);
    carryBits += 5;
    if (carryBits >= 8) {
      result[byteIdx--] = carry & 0xff;
      carry >>= 8;
      carryBits -= 8;
    }
  }

  return result;
}

function c32encode(data: Buffer): string {
  let n = BigInt('0x' + (data.toString('hex') || '0'));
  const chars: string[] = [];
  while (n > 0n) {
    chars.push(C32_CHARS[Number(n % 32n)]);
    n /= 32n;
  }
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    chars.push('0');
  }
  return chars.reverse().join('');
}

function c32checkEncode(version: number, data: Buffer): string {
  const versionBuf = Buffer.from([version]);
  const payload = Buffer.concat([versionBuf, data]);
  const h1 = sha256(payload);
  const checksum = sha256(h1).subarray(0, 4);
  const full = Buffer.concat([data, checksum]);
  const encoded = c32encode(full);
  return `S${C32_CHARS[version & 0x1f]}${encoded}`;
}

function pubkeyToStxAddress(pubkeyHex: string, testnet = false): string {
  const pubkey = Buffer.from(pubkeyHex.replace(/^0x/, ''), 'hex');
  const digest = createHash('ripemd160').update(sha256(pubkey)).digest();
  const version = testnet ? 26 : 22;
  return c32checkEncode(version, digest);
}

export function parseStxAddress(address: string): { version: number; hash160: Buffer } {
  const dotIdx = address.indexOf('.');
  const addr = dotIdx >= 0 ? address.slice(0, dotIdx) : address;
  if (addr.length < 3 || addr[0] !== 'S') throw new Error(`Invalid STX address: ${addr}`);
  const version = C32_CHARS.indexOf(addr[1].toUpperCase());
  if (version < 0) throw new Error(`Invalid STX address version: ${addr[1]}`);
  const decoded = c32DecodeFixed(addr.slice(2), 24);
  return { version, hash160: decoded.subarray(0, 20) };
}

function u32be(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}

function u128be(n: bigint): Buffer {
  const b = Buffer.alloc(16, 0);
  let v = BigInt.asUintN(128, n);
  for (let i = 15; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

function serializePrincipal(value: string): Buffer {
  const dotIdx = value.indexOf('.');
  if (dotIdx < 0) {
    const { version, hash160 } = parseStxAddress(value);
    return Buffer.concat([Buffer.from([0x05, version]), hash160]);
  }
  const { version, hash160 } = parseStxAddress(value.slice(0, dotIdx));
  const nameBytes = Buffer.from(value.slice(dotIdx + 1), 'ascii');
  return Buffer.concat([
    Buffer.from([0x06, version]),
    hash160,
    Buffer.from([nameBytes.length]),
    nameBytes,
  ]);
}

function serializeClarityValue(cv: ClarityValue): Buffer {
  switch (cv.type) {
    case 'uint': {
      const n = typeof cv.value === 'bigint' ? cv.value : BigInt(String(cv.value));
      return Buffer.concat([Buffer.from([0x01]), u128be(n)]);
    }
    case 'principal':
      return serializePrincipal(cv.value);
    case 'buff': {
      const bytes = Buffer.from(cv.value.replace(/^0x/, ''), 'hex');
      return Buffer.concat([Buffer.from([0x02]), u32be(bytes.length), bytes]);
    }
    case 'none':
      return Buffer.from([0x09]);
    case 'some':
      return Buffer.concat([Buffer.from([0x0a]), serializeClarityValue(cv.value)]);
    case 'string-ascii': {
      const bytes = Buffer.from(cv.value, 'ascii');
      return Buffer.concat([Buffer.from([0x0d]), u32be(bytes.length), bytes]);
    }
    case 'tuple': {
      const names = Object.keys(cv.fields).sort();
      const parts: Buffer[] = [Buffer.from([0x0c]), u32be(names.length)];
      for (const name of names) {
        const nb = Buffer.from(name, 'utf-8');
        parts.push(Buffer.from([nb.length]), nb, serializeClarityValue(cv.fields[name]));
      }
      return Buffer.concat(parts);
    }
  }
}

function buildDomain(contractId: string, chainId: number): ClarityValue {
  return {
    type: 'tuple',
    fields: {
      'chain-id': { type: 'uint', value: BigInt(chainId) },
      name: { type: 'string-ascii', value: contractId },
      version: { type: 'string-ascii', value: SF_VERSION },
    },
  };
}

function convertTypedField(v: TypedField): ClarityValue {
  switch (v.type) {
    case 'uint': return { type: 'uint', value: BigInt(String(v.value)) };
    case 'principal': return { type: 'principal', value: v.value as string };
    case 'buff': return { type: 'buff', value: v.value as string };
    case 'none': return { type: 'none' };
    case 'some': return { type: 'some', value: convertTypedField(v.value as TypedField) };
    case 'string-ascii': return { type: 'string-ascii', value: v.value as string };
    default: throw new Error(`Unknown typed field: ${v.type}`);
  }
}

function buildMessageTuple(msg: TypedMessage): ClarityValue {
  const fields: Record<string, ClarityValue> = {};
  for (const [k, v] of Object.entries(msg)) fields[k] = convertTypedField(v);
  return { type: 'tuple', fields };
}

function computeSip018Hash(contractId: string, message: TypedMessage, chainId: number): Buffer {
  const domainHash = sha256(serializeClarityValue(buildDomain(contractId, chainId)));
  const messageHash = sha256(serializeClarityValue(buildMessageTuple(message)));
  return sha256(Buffer.concat([SIP018_PREFIX, domainHash, messageHash]));
}

interface TransferState {
  pipeKey: { 'principal-1': string; 'principal-2': string; token?: string | null };
  forPrincipal: string;
  myBalance: string;
  theirBalance: string;
  nonce: string;
  action: string;
  actor: string;
  hashedSecret: string | null;
  validAfter: string | null;
}

function buildTransferMessage(state: TransferState): TypedMessage {
  const localIsPrincipal1 = state.pipeKey['principal-1'] === state.forPrincipal;
  const balance1 = localIsPrincipal1 ? state.myBalance : state.theirBalance;
  const balance2 = localIsPrincipal1 ? state.theirBalance : state.myBalance;
  return {
    'principal-1': { type: 'principal', value: state.pipeKey['principal-1'] },
    'principal-2': { type: 'principal', value: state.pipeKey['principal-2'] },
    token: state.pipeKey.token == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'principal', value: state.pipeKey.token } },
    'balance-1': { type: 'uint', value: balance1 },
    'balance-2': { type: 'uint', value: balance2 },
    nonce: { type: 'uint', value: state.nonce },
    action: { type: 'uint', value: state.action },
    actor: { type: 'principal', value: state.actor },
    'hashed-secret': state.hashedSecret == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'buff', value: state.hashedSecret } },
    'valid-after': state.validAfter == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'uint', value: state.validAfter } },
  };
}

async function sip018Verify(
  contractId: string,
  message: TypedMessage,
  signatureHex: string,
  expectedAddress: string,
  chainId: number,
): Promise<boolean> {
  try {
    const { secp256k1 } = await import('@noble/curves/secp256k1');
    const hash = computeSip018Hash(contractId, message, chainId);
    const sigBytes = Buffer.from(signatureHex.replace(/^0x/, ''), 'hex');

    if (sigBytes.length === 64) {
      for (const recoveryId of [0, 1]) {
        try {
          const sig = secp256k1.Signature.fromCompact(sigBytes).addRecoveryBit(recoveryId);
          const pubkeyBytes = sig.recoverPublicKey(hash).toRawBytes(true);
          const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
          if (
            pubkeyToStxAddress(pubkeyHex) === expectedAddress ||
            pubkeyToStxAddress(pubkeyHex, true) === expectedAddress
          ) {
            return true;
          }
        } catch {
          // Try the next recovery ID.
        }
      }
      return false;
    }
    if (sigBytes.length !== 65) return false;

    const recoveryId = sigBytes[0];
    const compact = sigBytes.subarray(1);
    const sig = secp256k1.Signature.fromCompact(compact).addRecoveryBit(recoveryId);
    const pubkeyBytes = sig.recoverPublicKey(hash).toRawBytes(true);
    const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
    return (
      pubkeyToStxAddress(pubkeyHex) === expectedAddress ||
      pubkeyToStxAddress(pubkeyHex, true) === expectedAddress
    );
  } catch {
    return false;
  }
}

export async function verifyPendingPaymentProof(args: {
  pendingPayment: { hashedSecret: string; stateProof: Record<string, unknown> };
  recipientAddress: string;
  chainId?: number;
}): Promise<{ ok: true } | { ok: false; reason: string }> {
  const state = args.pendingPayment.stateProof;
  const contractId = typeof state['contractId'] === 'string' ? state['contractId'] : '';
  const withPrincipal = typeof state['withPrincipal'] === 'string' ? state['withPrincipal'] : '';
  const forPrincipal = typeof state['forPrincipal'] === 'string' ? state['forPrincipal'] : '';
  const actor = typeof state['actor'] === 'string' ? state['actor'] : '';
  const theirSignature = typeof state['theirSignature'] === 'string' ? state['theirSignature'] : '';
  const hashedSecret = typeof state['hashedSecret'] === 'string' ? state['hashedSecret'] : '';
  const myBalance = typeof state['myBalance'] === 'string' ? state['myBalance'] : String(state['myBalance'] ?? '');
  const theirBalance = typeof state['theirBalance'] === 'string' ? state['theirBalance'] : String(state['theirBalance'] ?? '');
  const nonce = typeof state['nonce'] === 'string' ? state['nonce'] : String(state['nonce'] ?? '');
  const action = typeof state['action'] === 'string' ? state['action'] : String(state['action'] ?? '');
  const validAfter = typeof state['validAfter'] === 'string' ? state['validAfter'] : null;
  const pipeKey = state['pipeKey'];

  if (!contractId || !withPrincipal || !forPrincipal || !theirSignature || !actor) {
    return { ok: false, reason: 'pending payment proof missing required fields' };
  }
  if (forPrincipal !== args.recipientAddress) {
    return { ok: false, reason: `pending payment forPrincipal mismatch: ${forPrincipal}` };
  }
  if (hashedSecret !== args.pendingPayment.hashedSecret) {
    return { ok: false, reason: 'pending payment hashedSecret mismatch' };
  }
  if (!pipeKey || typeof pipeKey !== 'object' || Array.isArray(pipeKey)) {
    return { ok: false, reason: 'pending payment missing pipeKey' };
  }

  const parsedPipeKey = pipeKey as { 'principal-1'?: unknown; 'principal-2'?: unknown; token?: unknown };
  if (typeof parsedPipeKey['principal-1'] !== 'string' || typeof parsedPipeKey['principal-2'] !== 'string') {
    return { ok: false, reason: 'pending payment pipeKey principals invalid' };
  }
  if (parsedPipeKey.token != null && typeof parsedPipeKey.token !== 'string') {
    return { ok: false, reason: 'pending payment pipeKey token invalid' };
  }

  const message = buildTransferMessage({
    pipeKey: {
      'principal-1': parsedPipeKey['principal-1'],
      'principal-2': parsedPipeKey['principal-2'],
      token: parsedPipeKey.token == null ? null : parsedPipeKey.token,
    },
    forPrincipal,
    myBalance,
    theirBalance,
    nonce,
    action,
    actor,
    hashedSecret: hashedSecret || null,
    validAfter,
  });

  const chainIds = args.chainId == null ? [1, 2147483648] : [args.chainId];
  let valid = false;
  for (const chainId of chainIds) {
    if (await sip018Verify(contractId, message, theirSignature, withPrincipal, chainId)) {
      valid = true;
      break;
    }
  }
  if (!valid) {
    return { ok: false, reason: 'pending payment signature invalid' };
  }
  return { ok: true };
}
