import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import {
  openContractCall,
  getStacksProvider,
} from '@stacks/connect';
import {
  principalCV,
  noneCV,
  someCV,
  tupleCV,
  uintCV,
  bufferCV,
  Pc,
  PostConditionMode,
  serializeCVBytes,
  ClarityType,
} from '@stacks/transactions';
import type { ClarityValue } from '@stacks/transactions';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SF_CONTRACT = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow';
const RESERVOIR   = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir';
const TOKEN       = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token';
const TOKEN_NAME  = 'sm-test-token'; // asset name inside the SIP-010 contract
const CHAIN_ID    = 1; // mainnet; updated from /status if available
const OPEN_TAP_AMOUNT = 1_000_000n; // 1 STX in microstacks
const OPEN_TAP_NONCE  = 0n;
const OPEN_BORROW_AMOUNT = 1_000_000n; // default borrowed inbound liquidity
const OPEN_BORROW_NONCE  = 1n;
const OPEN_BORROW_FEE_BPS = 1000n; // 10%

// (no session object needed — we use getStacksProvider() after wallet detection)

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  h = h.replace(/^0x/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical pipe key ordering (using @stacks/transactions serializeCV)
// ─────────────────────────────────────────────────────────────────────────────

interface PipeKey {
  token: string | null;
  'principal-1': string;
  'principal-2': string;
}

function canonicalPipeKey(token: string | null, a: string, b: string): PipeKey {
  const pa = serializeCVBytes(principalCV(a));
  const pb = serializeCVBytes(principalCV(b));
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
    if (pa[i] < pb[i]) return { token, 'principal-1': a, 'principal-2': b };
    if (pa[i] > pb[i]) return { token, 'principal-1': b, 'principal-2': a };
  }
  return { token, 'principal-1': a, 'principal-2': b };
}

// ─────────────────────────────────────────────────────────────────────────────
// buildTransferCV — builds the SIP-018 transfer tuple as a ClarityValue
// ─────────────────────────────────────────────────────────────────────────────

interface BuildTransferCVParams {
  pipeKey: PipeKey;
  forPrincipal: string;
  myBalance: bigint;
  theirBalance: bigint;
  nonce: bigint;
  action: bigint;
  actor: string;
  hashedSecret?: string | null;
  validAfter?: bigint | null;
}

function buildTransferCV(params: BuildTransferCVParams): ClarityValue {
  const localIsP1 = params.pipeKey['principal-1'] === params.forPrincipal;
  const balance1  = localIsP1 ? params.myBalance : params.theirBalance;
  const balance2  = localIsP1 ? params.theirBalance : params.myBalance;
  return tupleCV({
    'principal-1':   principalCV(params.pipeKey['principal-1']),
    'principal-2':   principalCV(params.pipeKey['principal-2']),
    token:           params.pipeKey.token == null ? noneCV() : someCV(principalCV(params.pipeKey.token)),
    'balance-1':     uintCV(balance1),
    'balance-2':     uintCV(balance2),
    nonce:           uintCV(params.nonce),
    action:          uintCV(params.action),
    actor:           principalCV(params.actor),
    'hashed-secret': params.hashedSecret == null ? noneCV() : someCV(bufferCV(hexToBytes(params.hashedSecret))),
    'valid-after':   params.validAfter == null ? noneCV() : someCV(uintCV(params.validAfter)),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// cvToWalletJson — converts ClarityValues to wallet JSON representation
// ─────────────────────────────────────────────────────────────────────────────

function cvToWalletJson(cv: ClarityValue): unknown {
  switch (cv.type) {
    case ClarityType.UInt:
      return { type: 'uint', value: String(cv.value) };
    case ClarityType.Int:
      return { type: 'int', value: String(cv.value) };
    case ClarityType.PrincipalStandard:
    case ClarityType.PrincipalContract:
      return { type: 'principal', value: cv.value };
    case ClarityType.StringASCII:
      return { type: 'string-ascii', value: cv.value };
    case ClarityType.StringUTF8:
      return { type: 'string-utf8', value: cv.value };
    case ClarityType.OptionalNone:
      return { type: 'none' };
    case ClarityType.OptionalSome:
      return { type: 'some', value: cvToWalletJson(cv.value) };
    case ClarityType.ResponseOk:
      return { type: 'ok', value: cvToWalletJson(cv.value) };
    case ClarityType.ResponseErr:
      return { type: 'err', value: cvToWalletJson(cv.value) };
    case ClarityType.Buffer:
      return { type: 'buffer', data: cv.value };
    case ClarityType.Tuple: {
      const data: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(cv.value as Record<string, ClarityValue>)) {
        data[k] = cvToWalletJson(v);
      }
      return { type: 'tuple', data };
    }
    case ClarityType.List: {
      return { type: 'list', list: cv.value.map(cvToWalletJson) };
    }
    case ClarityType.BoolTrue:
      return { type: 'bool', value: true };
    case ClarityType.BoolFalse:
      return { type: 'bool', value: false };
    default:
      return { type: 'unknown' };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ECIES encryption
// ─────────────────────────────────────────────────────────────────────────────

interface EncryptedMail {
  v: 1;
  epk: string;
  iv: string;
  data: string;
}

async function encryptMail(payload: unknown, recipientPubkeyHex: string): Promise<EncryptedMail> {
  const eskBytes    = secp256k1.utils.randomPrivateKey();
  const epkBytes    = secp256k1.getPublicKey(eskBytes, true);
  const recipientPub = hexToBytes(recipientPubkeyHex.replace(/^0x/, ''));
  const sharedFull  = secp256k1.getSharedSecret(eskBytes, recipientPub, true);
  const sharedX     = sharedFull.slice(1);
  const salt        = new TextEncoder().encode('stackmail-v1');
  const info        = new TextEncoder().encode('encrypt');
  const key         = hkdf(sha256, sharedX, salt, info, 32);
  const iv          = crypto.getRandomValues(new Uint8Array(12));
  const plaintext   = new TextEncoder().encode(JSON.stringify(payload));
  const cryptoKey   = await crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, ['encrypt']);
  const encrypted   = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext));
  return { v: 1, epk: bytesToHex(epkBytes), iv: bytesToHex(iv), data: bytesToHex(encrypted) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet state
// ─────────────────────────────────────────────────────────────────────────────

let walletAddress: string | null = null;
let walletPubkey: string | null  = null;
let serverStatus: Record<string, unknown> = {};
let pipeState = { myBalance: 0n, serverBalance: 0n, nonce: 0n };

// Auth header cache for get-inbox (avoids wallet popup on every inbox load)
let cachedGetInboxAuth: string | null = null;
let cachedGetInboxAuthExpiry = 0;

// ─────────────────────────────────────────────────────────────────────────────
// App state machine
// States: no-wallet | checking | no-tap | tx-pending | ready
// ─────────────────────────────────────────────────────────────────────────────

function setAppState(state: 'no-wallet' | 'checking' | 'no-tap' | 'tx-pending' | 'ready'): void {
  (document.getElementById('panel-no-wallet')  as HTMLElement).style.display = state === 'no-wallet'  ? '' : 'none';
  (document.getElementById('panel-checking')   as HTMLElement).style.display = state === 'checking'   ? '' : 'none';
  (document.getElementById('panel-onboarding') as HTMLElement).style.display = state === 'no-tap'     ? '' : 'none';
  (document.getElementById('panel-tx-pending') as HTMLElement).style.display = state === 'tx-pending' ? '' : 'none';
  (document.getElementById('panel-main')       as HTMLElement).style.display = state === 'ready'      ? '' : 'none';
  (document.getElementById('main-nav')         as HTMLElement).style.display = state === 'ready'      ? '' : 'none';
}

// ─────────────────────────────────────────────────────────────────────────────
// Connect wallet
// ─────────────────────────────────────────────────────────────────────────────

async function connectWallet(): Promise<void> {
  const btns = document.querySelectorAll<HTMLButtonElement>('#connect-wallet-btn, #connect-wallet-main');
  btns.forEach(b => { b.disabled = true; b.textContent = 'Connecting…'; });

  try {
    // getStacksProvider() detects Leather, Xverse, or any SIP-30 browser extension
    const provider = getStacksProvider();
    if (!provider) {
      (document.getElementById('wallet-error') as HTMLElement).innerHTML =
        '<div class="alert alert-warning">No Stacks wallet detected. Install <a href="https://leather.io" target="_blank" style="color:inherit">Leather</a> or <a href="https://xverse.app" target="_blank" style="color:inherit">Xverse</a> and refresh.</div>';
      btns.forEach(b => { b.disabled = false; b.textContent = 'Connect Wallet'; });
      return;
    }

    const addrsResp = await provider.request('stx_getAddresses');
    const accts: Array<{ address: string; publicKey?: string }> =
      (addrsResp as { result?: { addresses?: Array<{ address: string; publicKey?: string }> } })?.result?.addresses
      ?? (addrsResp as { addresses?: Array<{ address: string; publicKey?: string }> })?.addresses
      ?? [];
    const mainnetAcct = accts.find(a => a.address?.startsWith('SP'))
      ?? accts.find(a => a.address?.startsWith('ST'))
      ?? accts[0];

    if (!mainnetAcct?.address) throw new Error('Wallet returned no address.');

    walletAddress = mainnetAcct.address;
    walletPubkey  = mainnetAcct.publicKey ?? null;

    updateWalletUI();
    await onWalletConnected();
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    (document.getElementById('wallet-error') as HTMLElement).innerHTML =
      `<div class="alert alert-error">Connection failed: ${escHtml(msg)}</div>`;
    btns.forEach(b => { b.disabled = false; b.textContent = 'Connect Wallet'; });
  }
}

function disconnectWallet(): void {
  walletAddress = null;
  walletPubkey  = null;
  pipeState     = { myBalance: 0n, serverBalance: 0n, nonce: 0n };
  cachedGetInboxAuth = null;
  cachedGetInboxAuthExpiry = 0;
  updateWalletUI();
  setAppState('no-wallet');
}

function updateWalletUI(): void {
  const chip       = document.getElementById('wallet-chip') as HTMLElement;
  const connectBtn = document.getElementById('connect-wallet-btn') as HTMLButtonElement;
  if (walletAddress) {
    chip.style.display = 'flex';
    connectBtn.style.display = 'none';
    (document.getElementById('wallet-addr-chip') as HTMLElement).textContent =
      walletAddress.slice(0, 8) + '…' + walletAddress.slice(-4);
  } else {
    chip.style.display = 'none';
    connectBtn.style.display = '';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// After wallet connects: check tap, route to state
// ─────────────────────────────────────────────────────────────────────────────

async function onWalletConnected(): Promise<void> {
  setAppState('checking');
  (document.getElementById('checking-label') as HTMLElement).textContent = 'Checking payment channel…';

  const tap = await queryOnChainTap(walletAddress!);

  if (!tap) {
    (document.getElementById('onboarding-addr') as HTMLElement).textContent = walletAddress!;
    setAppState('no-tap');
  } else {
    pipeState = { myBalance: tap.userBalance, serverBalance: tap.reservoirBalance, nonce: tap.nonce };
    updateIdentityUI();
    setAppState('ready');
    showTab('inbox');
    loadStatus();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet auth (SIP-018 structured data)
// ─────────────────────────────────────────────────────────────────────────────

async function buildWalletAuthHeader(action: string, messageId?: string): Promise<string> {
  // Return cached auth for get-inbox (valid for 4 minutes)
  if (action === 'get-inbox' && cachedGetInboxAuth && Date.now() < cachedGetInboxAuthExpiry) {
    return cachedGetInboxAuth;
  }

  const ts         = Date.now();
  const chainId    = (serverStatus.chainId as number | undefined)    ?? CHAIN_ID;
  const authDomain = (serverStatus.authDomain as string | undefined) ?? 'Stackmail';
  const sfVersion  = (serverStatus.sfVersion as string | undefined)  ?? '0.6.0';

  const msgFields: Record<string, { type: string; value: string }> = {
    action:    { type: 'string-ascii', value: action },
    address:   { type: 'principal',   value: walletAddress! },
    timestamp: { type: 'uint',        value: String(ts) },
    ...(messageId ? { messageId: { type: 'string-ascii', value: messageId } } : {}),
  };

  const domain = {
    type: 'tuple',
    data: {
      'chain-id': { type: 'uint',         value: String(chainId) },
      name:       { type: 'string-ascii', value: authDomain },
      version:    { type: 'string-ascii', value: sfVersion },
    },
  };
  const message = { type: 'tuple', data: msgFields };

  const provider = getStacksProvider();
  let resp: unknown;
  try {
    resp = await provider!.request('stx_signStructuredMessage', { message, domain });
  } catch (e) {
    const msg = (e as Error)?.message ?? '';
    if (msg.includes('not supported') || msg.includes('structured')) {
      throw new Error("Your wallet doesn't support structured data signing (SIP-018). Try Leather v6+");
    }
    throw e;
  }
  const signature = (resp as { result?: { signature?: string }; signature?: string })?.result?.signature
    ?? (resp as { signature?: string })?.signature;
  const pubkey    = (resp as { result?: { publicKey?: string }; publicKey?: string })?.result?.publicKey
    ?? (resp as { publicKey?: string })?.publicKey
    ?? walletPubkey;
  if (!signature) throw new Error('Wallet returned no signature');

  const authHeader = btoa(JSON.stringify({ type: 'sip018', pubkey, message: msgFields, signature }));

  if (action === 'get-inbox') {
    cachedGetInboxAuth = authHeader;
    cachedGetInboxAuthExpiry = Date.now() + 4 * 60 * 1000;
  }

  return authHeader;
}

// ─────────────────────────────────────────────────────────────────────────────
// SIP-018 signing for payment proofs — using stx_signStructuredMessage
// ─────────────────────────────────────────────────────────────────────────────

async function sip018SignWithWallet(contractId: string, transferCV: ClarityValue, chainId: number): Promise<string> {
  const domain = {
    type: 'tuple',
    data: {
      'chain-id': { type: 'uint',         value: String(chainId) },
      name:       { type: 'string-ascii', value: contractId },
      version:    { type: 'string-ascii', value: '0.6.0' },
    },
  };

  const msgWalletJson = cvToWalletJson(transferCV);

  const provider = getStacksProvider();
  let resp: unknown;
  try {
    resp = await provider!.request('stx_signStructuredMessage', {
      message: msgWalletJson,
      domain,
    });
  } catch (e) {
    const msg = (e as Error)?.message ?? '';
    if (msg.includes('not supported') || msg.includes('structured')) {
      throw new Error("Your wallet doesn't support structured data signing (SIP-018). Try Leather v6+");
    }
    throw e;
  }
  const sig = (resp as { result?: { signature?: string }; signature?: string })?.result?.signature
    ?? (resp as { signature?: string })?.signature;
  if (!sig) throw new Error('Wallet returned no signature for payment proof');
  return sig;
}

// ─────────────────────────────────────────────────────────────────────────────
// On-chain tap check — queries sm-stackflow via Hiro read-only API
// ─────────────────────────────────────────────────────────────────────────────

interface TapState {
  userBalance: bigint;
  reservoirBalance: bigint;
  nonce: bigint;
  pipeKey: PipeKey;
}

function cvPrincipalHex(addr: string): string {
  // Use serializeCV from @stacks/transactions to get the canonical bytes
  const bytes = serializeCVBytes(principalCV(addr));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function cvTupleHex(fields: Record<string, string>): string {
  const sorted = Object.keys(fields).sort();
  const u32h = (n: number) => n.toString(16).padStart(8, '0');
  const u8h  = (n: number) => n.toString(16).padStart(2, '0');
  let h = '0c' + u32h(sorted.length);
  for (const name of sorted) {
    const nb = new TextEncoder().encode(name);
    h += u8h(nb.length) + Array.from(nb).map(b => b.toString(16).padStart(2, '0')).join('') + fields[name];
  }
  return h;
}

async function queryOnChainTap(userAddr: string): Promise<TapState | null> {
  try {
    const pipeKey = canonicalPipeKey(TOKEN, userAddr, RESERVOIR);
    const tokenCV = cvPrincipalHex(TOKEN); // (some <TOKEN>)
    const someByte = '0a'; // Clarity OptionalSome prefix
    const argHex  = '0x' + cvTupleHex({
      'principal-1': cvPrincipalHex(pipeKey['principal-1']),
      'principal-2': cvPrincipalHex(pipeKey['principal-2']),
      token: someByte + tokenCV,
    });
    const [contractAddr, contractName] = SF_CONTRACT.split('.');
    const r = await fetch(
      `https://api.mainnet.hiro.so/v2/contracts/call-read/${contractAddr}/${contractName}/get-pipe`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sender: userAddr, arguments: [argHex] }),
      },
    );
    if (!r.ok) return null;
    const data = await r.json() as { okay: boolean; result?: string };
    if (!data.okay || !data.result || data.result === '0x09') return null;

    const repr = data.result;
    const b1m  = repr.match(/balance-1 u(\d+)/);
    const b2m  = repr.match(/balance-2 u(\d+)/);
    const ncm  = repr.match(/nonce u(\d+)/);
    if (!b1m) return null;

    const balance1 = BigInt(b1m[1]);
    const balance2 = BigInt(b2m?.[1] ?? '0');
    const nonce    = BigInt(ncm?.[1] ?? '0');
    const userIsP1 = pipeKey['principal-1'] === userAddr;
    return {
      userBalance:      userIsP1 ? balance1 : balance2,
      reservoirBalance: userIsP1 ? balance2 : balance1,
      nonce,
      pipeKey,
    };
  } catch { return null; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Open mailbox — calls sm-reservoir::create-tap-with-borrowed-liquidity
// ─────────────────────────────────────────────────────────────────────────────

async function openMailbox(): Promise<void> {
  const btn     = document.getElementById('open-mailbox-btn') as HTMLButtonElement;
  const errorEl = document.getElementById('open-mailbox-error') as HTMLElement;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Opening…';
  errorEl.innerHTML = '';

  try {
    if (!walletAddress) throw new Error('Wallet not connected');
    const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const borrowFee = ((OPEN_BORROW_AMOUNT * OPEN_BORROW_FEE_BPS) + 9999n) / 10000n;

    // Borrower signs the post-borrow deposit state (action=2, hashed-secret=none).
    const pipeKey = canonicalPipeKey(null, walletAddress, RESERVOIR);
    const borrowStateCV = buildTransferCV({
      pipeKey,
      forPrincipal: walletAddress,
      myBalance: OPEN_TAP_AMOUNT,
      theirBalance: OPEN_BORROW_AMOUNT,
      nonce: OPEN_BORROW_NONCE,
      action: 2n,
      actor: RESERVOIR,
      hashedSecret: null,
      validAfter: null,
    });
    const mySignature = await sip018SignWithWallet(SF_CONTRACT, borrowStateCV, chainId);

    // Request validated params + reservoir signature from server.
    const paramsRes = await apiFetch('/tap/borrow-params', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        borrower: walletAddress,
        tapAmount: OPEN_TAP_AMOUNT.toString(),
        tapNonce: OPEN_TAP_NONCE.toString(),
        borrowAmount: OPEN_BORROW_AMOUNT.toString(),
        borrowFee: borrowFee.toString(),
        myBalance: OPEN_TAP_AMOUNT.toString(),
        reservoirBalance: OPEN_BORROW_AMOUNT.toString(),
        borrowNonce: OPEN_BORROW_NONCE.toString(),
        mySignature,
      }),
    });
    if (!paramsRes.ok) {
      const err = await paramsRes.json().catch(() => ({})) as { error?: string; message?: string };
      throw new Error(err.message || err.error || `Failed to prepare borrowed-liquidity params (${paramsRes.status})`);
    }
    const params = await paramsRes.json() as { reservoirSignature?: string; borrowFee?: string };
    const reservoirSignature = params.reservoirSignature;
    if (!reservoirSignature) throw new Error('Server did not return reservoir signature');
    const finalBorrowFee = BigInt(params.borrowFee ?? borrowFee.toString());

    const txId = await new Promise<string>((resolve, reject) => {
      openContractCall({
        contractAddress: RESERVOIR.split('.')[0],
        contractName:    RESERVOIR.split('.')[1],
        functionName:    'create-tap-with-borrowed-liquidity',
        functionArgs: [
          principalCV(SF_CONTRACT),
          noneCV(),
          uintCV(OPEN_TAP_AMOUNT),
          uintCV(OPEN_TAP_NONCE),
          uintCV(OPEN_BORROW_AMOUNT),
          uintCV(finalBorrowFee),
          uintCV(OPEN_TAP_AMOUNT),
          uintCV(OPEN_BORROW_AMOUNT),
          bufferCV(hexToBytes(mySignature)),
          bufferCV(hexToBytes(reservoirSignature)),
          uintCV(OPEN_BORROW_NONCE),
        ],
        network:         'mainnet',
        postConditionMode: PostConditionMode.Deny,
        postConditions: [
          Pc.principal(walletAddress!).willSendEq(OPEN_TAP_AMOUNT + finalBorrowFee).ustx(),
          Pc.principal(RESERVOIR).willSendEq(OPEN_BORROW_AMOUNT).ustx(),
        ],
        appDetails: { name: 'Stackmail', icon: window.location.origin + '/favicon.ico' },
        onFinish:  (data: { txId?: string; txid?: string; tx_id?: string }) =>
          resolve(data.txId ?? data.txid ?? data.tx_id ?? ''),
        onCancel:  () => reject(new Error('Transaction cancelled')),
      });
    });

    if (!txId) throw new Error('No transaction ID returned from wallet');

    (document.getElementById('tx-explorer-link') as HTMLAnchorElement).href        = `https://explorer.hiro.so/txid/${txId}?chain=mainnet`;
    (document.getElementById('tx-explorer-link') as HTMLElement).textContent = txId.slice(0, 12) + '…' + txId.slice(-8);
    (document.getElementById('tx-status-msg') as HTMLElement).innerHTML = '';
    setAppState('tx-pending');

  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    errorEl.innerHTML = `<div class="alert alert-error">${escHtml(msg)}</div>`;
    btn.disabled = false;
    btn.innerHTML = 'Open Mailbox';
  }
}

async function checkTapAfterTx(): Promise<void> {
  const btn      = document.getElementById('check-tap-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('tx-status-msg') as HTMLElement;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Checking…';

  const tap = await queryOnChainTap(walletAddress!);
  if (tap) {
    pipeState = { myBalance: tap.userBalance, serverBalance: tap.reservoirBalance, nonce: tap.nonce };
    updateIdentityUI();
    setAppState('ready');
    showTab('inbox');
    loadInbox();
    loadStatus();
  } else {
    btn.disabled = false;
    btn.textContent = 'Check Again';
    statusEl.innerHTML = '<div class="alert alert-warning">Channel not found yet — the transaction may still be confirming. Try again in a moment.</div>';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// API helper
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch(path: string, opts: RequestInit = {}): Promise<Response> {
  return fetch(window.location.origin + path, opts);
}

// ─────────────────────────────────────────────────────────────────────────────
// Inbox tab
// ─────────────────────────────────────────────────────────────────────────────

async function loadInbox(): Promise<void> {
  const listEl   = document.getElementById('inbox-list') as HTMLElement;
  const statusEl = document.getElementById('inbox-status') as HTMLElement;
  const claimed  = (document.getElementById('show-claimed-cb') as HTMLInputElement).checked;

  statusEl.innerHTML = '<span class="spinner"></span> Loading…';
  listEl.innerHTML   = '';

  try {
    const auth = await buildWalletAuthHeader('get-inbox');
    const r    = await apiFetch(`/inbox?limit=50${claimed ? '&claimed=true' : ''}`, {
      headers: { 'x-stackmail-auth': auth },
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({})) as { message?: string };
      statusEl.innerHTML = `<div class="alert alert-error">Error: ${escHtml(err.message || String(r.status))}</div>`;
      return;
    }
    const data = await r.json() as { messages?: InboxMessage[] };
    statusEl.innerHTML = '';
    renderInboxMessages(data.messages || []);
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">Failed to load inbox: ${escHtml(msg)}</div>`;
  }
}

interface InboxMessage {
  id: string;
  from: string;
  sentAt: number;
  amount?: number | string;
  claimed?: boolean;
}

function renderInboxMessages(messages: InboxMessage[]): void {
  const listEl   = document.getElementById('inbox-list') as HTMLElement;
  const countEl  = document.getElementById('inbox-count') as HTMLElement;
  const unclaimed = messages.filter(m => !m.claimed);

  countEl.textContent = messages.length
    ? `${unclaimed.length} unclaimed · ${messages.length} total`
    : '';

  if (!messages.length) {
    listEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">📭</div>
        <h3>No messages yet</h3>
        <p>Share your address so others can send you messages:</p>
        <div class="mono" style="margin-top:8px;font-size:12px;color:var(--accent)">${escHtml(walletAddress ?? '')}</div>
      </div>`;
    return;
  }

  listEl.innerHTML = '';
  for (const msg of messages) {
    const el = document.createElement('div');
    el.className = 'msg-item';

    const time  = new Date(msg.sentAt).toLocaleString();
    const badge = msg.claimed
      ? '<span class="badge badge-green">✓ Claimed</span>'
      : '<span class="badge badge-purple">Pending</span>';

    el.innerHTML = `
      <div class="msg-header">
        <div>
          <div class="msg-from">From: ${escHtml(msg.from || '—')}</div>
          <div style="margin-top:4px;font-size:12px;color:var(--muted)">${time}</div>
        </div>
        <div class="msg-meta">
          ${badge}
          <span class="msg-amount">${Number(msg.amount || 0).toLocaleString()} sats</span>
        </div>
      </div>
      <div style="margin-top:10px;display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)">
        <span>🔒</span>
        <span>Message content is encrypted — wallet decryption (ECIES) coming soon</span>
      </div>`;

    listEl.appendChild(el);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compose tab
// ─────────────────────────────────────────────────────────────────────────────

interface RecipientInfo {
  recipientPublicKey: string;
  serverAddress: string;
  amount: string | number;
}

let recipientInfo: RecipientInfo | null = null;

async function lookupRecipientPubkey(addr: string): Promise<string | null> {
  try {
    const url = `https://api.mainnet.hiro.so/extended/v1/address/${encodeURIComponent(addr)}/transactions?limit=5`;
    const r   = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) return null;
    const data = await r.json() as { results?: Array<{ sender_address: string; sender_public_key?: string }> };
    for (const tx of (data.results || [])) {
      if (tx.sender_address !== addr) continue;
      const pk = tx.sender_public_key;
      if (typeof pk === 'string') {
        const hex = pk.replace(/^0x/, '');
        if (/^0[23][0-9a-f]{64}$/i.test(hex)) return hex;
      }
    }
    return null;
  } catch { return null; }
}

async function fetchRecipientInfo(toAddr: string): Promise<void> {
  const el = document.getElementById('recipient-status') as HTMLElement;
  el.innerHTML = '<span class="spinner"></span> Looking up recipient…';

  const resetErr = (msg: string) => {
    el.innerHTML = `<span style="color:var(--red)">✗ ${escHtml(msg)}</span>`;
    recipientInfo = null;
    (document.getElementById('send-btn') as HTMLButtonElement).disabled = true;
    (document.getElementById('payment-panel') as HTMLElement).style.display = 'none';
  };

  try {
    const recipientPublicKey = await lookupRecipientPubkey(toAddr);
    if (!recipientPublicKey) {
      resetErr('No transaction history found — recipient must have sent at least one Stacks transaction to receive mail.');
      return;
    }

    const price      = (serverStatus.messagePriceSats as string | number | undefined) ?? '1000';
    const serverAddr = (serverStatus.serverAddress as string | undefined) ?? '';

    recipientInfo = { recipientPublicKey, serverAddress: serverAddr, amount: price };
    el.innerHTML  = `<span style="color:var(--green)">✓ Public key found — ready to send</span>`;

    (document.getElementById('payment-panel') as HTMLElement).style.display = '';
    (document.getElementById('pay-price') as HTMLElement).textContent   = `${Number(price).toLocaleString()} sats`;
    (document.getElementById('pay-balance') as HTMLElement).textContent = `${pipeState.myBalance.toLocaleString()} sats`;
    (document.getElementById('pay-nonce') as HTMLElement).textContent   = `${pipeState.nonce}`;

    const tap = await queryOnChainTap(walletAddress!);
    if (tap) {
      pipeState = { myBalance: tap.userBalance, serverBalance: tap.reservoirBalance, nonce: tap.nonce };
      (document.getElementById('pay-balance') as HTMLElement).textContent = `${pipeState.myBalance.toLocaleString()} sats`;
      (document.getElementById('pay-nonce') as HTMLElement).textContent   = `${pipeState.nonce}`;
      (document.getElementById('tap-status') as HTMLElement).innerHTML =
        `<span style="color:var(--green)">✓ Channel open — ${pipeState.myBalance.toLocaleString()} sats available</span>`;
    } else {
      (document.getElementById('tap-status') as HTMLElement).innerHTML =
        `<span style="color:var(--red)">✗ No channel found on-chain</span>`;
    }

    (document.getElementById('send-btn') as HTMLButtonElement).disabled = false;

  } catch (e) {
    resetErr(typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error'));
  }
}

async function sendMessage(): Promise<void> {
  const toAddr   = (document.getElementById('to-input') as HTMLInputElement).value.trim();
  const subject  = (document.getElementById('subject-input') as HTMLInputElement).value.trim();
  const body     = (document.getElementById('body-input') as HTMLTextAreaElement).value.trim();
  const statusEl = document.getElementById('send-status') as HTMLElement;
  const sendBtn  = document.getElementById('send-btn') as HTMLButtonElement;

  if (!toAddr || !body) {
    statusEl.innerHTML = '<div class="alert alert-warning">Please fill in To and Message fields.</div>';
    return;
  }
  if (!recipientInfo) {
    statusEl.innerHTML = '<div class="alert alert-warning">Please wait for recipient info to load.</div>';
    return;
  }

  sendBtn.disabled = true;
  sendBtn.innerHTML = '<span class="spinner"></span> Sending…';
  statusEl.innerHTML = '';

  try {
    const chainId    = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const serverAddr = recipientInfo.serverAddress;
    const senderAddr = walletAddress!;

    // Random secret + hash
    const secretBytes     = crypto.getRandomValues(new Uint8Array(32));
    const secretHex       = bytesToHex(secretBytes);
    const hashedSecretHex = bytesToHex(sha256(secretBytes));

    // Encrypt payload
    const encryptedPayload = await encryptMail(
      { v: 1, secret: secretHex, subject: subject || undefined, body },
      recipientInfo.recipientPublicKey,
    );

    // Update pipe state
    const price            = BigInt(recipientInfo.amount || '1000');
    const newServerBalance = pipeState.serverBalance + price;
    const newMyBalance     = pipeState.myBalance - price;
    const newNonce         = pipeState.nonce + 1n;

    // Build canonical pipe key (sender ↔ server, sm-test-token)
    const pipeKey = canonicalPipeKey(TOKEN, senderAddr, serverAddr);

    // Build SIP-018 transfer CV
    const transferCV = buildTransferCV({
      pipeKey,
      forPrincipal: serverAddr,
      myBalance:    newServerBalance,
      theirBalance: newMyBalance,
      nonce:        newNonce,
      action:       1n,
      actor:        senderAddr,
      hashedSecret: hashedSecretHex,
      validAfter:   null,
    });

    // Sign with wallet
    const sig = await sip018SignWithWallet(SF_CONTRACT, transferCV, chainId);

    // Build proof object
    const proof = {
      contractId:    SF_CONTRACT,
      pipeKey,
      forPrincipal:  serverAddr,
      withPrincipal: senderAddr,
      myBalance:     newServerBalance.toString(),
      theirBalance:  newMyBalance.toString(),
      nonce:         newNonce.toString(),
      action:        '1',
      actor:         senderAddr,
      hashedSecret:  hashedSecretHex,
      theirSignature: sig,
    };

    const r = await apiFetch(`/messages/${encodeURIComponent(toAddr)}`, {
      method:  'POST',
      headers: {
        'content-type':        'application/json',
        'x-stackmail-payment': btoa(JSON.stringify(proof)),
      },
      body: JSON.stringify({ from: senderAddr, encryptedPayload }),
    });

    const data = await r.json().catch(() => ({})) as { messageId?: string; message?: string; error?: string };
    if (!r.ok) throw new Error(data.message || data.error || `Send failed: ${r.status}`);

    // Commit state
    pipeState = { myBalance: newMyBalance, serverBalance: newServerBalance, nonce: newNonce };
    (document.getElementById('pay-balance') as HTMLElement).textContent = `${pipeState.myBalance.toLocaleString()} sats`;
    (document.getElementById('pay-nonce') as HTMLElement).textContent   = `${pipeState.nonce}`;

    statusEl.innerHTML = `
      <div class="alert alert-success">
        ✓ Message sent!<br>
        <span class="mono" style="font-size:11px">ID: ${escHtml(data.messageId || '—')}</span>
      </div>`;

    (document.getElementById('body-input') as HTMLTextAreaElement).value    = '';
    (document.getElementById('subject-input') as HTMLInputElement).value = '';

  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">✗ ${escHtml(msg)}</div>`;
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send Message';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Status tab
// ─────────────────────────────────────────────────────────────────────────────

async function loadStatus(): Promise<void> {
  const dot   = document.getElementById('health-dot') as HTMLElement;
  const label = document.getElementById('health-label') as HTMLElement;
  try {
    const r    = await apiFetch('/status');
    const data = await r.json() as Record<string, unknown>;
    serverStatus = data;
    dot.className    = data.ok ? 'dot green' : 'dot red';
    label.textContent = data.ok ? 'Stackmail Server — Online' : 'Server returned error';
    (document.getElementById('s-addr') as HTMLElement).textContent     = String(data.serverAddress || '—');
    (document.getElementById('s-contract') as HTMLElement).textContent = String(data.sfContract    || '—');
    (document.getElementById('s-price') as HTMLElement).textContent    = data.messagePriceSats
      ? `${Number(data.messagePriceSats).toLocaleString()} sats` : '—';
    (document.getElementById('s-network') as HTMLElement).textContent  = data.network
      ? String(data.network).charAt(0).toUpperCase() + String(data.network).slice(1) : '—';
  } catch {
    dot.className    = 'dot red';
    label.textContent = 'Cannot reach server';
  }
}

function updateIdentityUI(): void {
  const addr = walletAddress || '—';
  const pub  = walletPubkey  || '—';
  const el   = document.getElementById('status-wallet-addr');
  const pk   = document.getElementById('status-wallet-pubkey');
  const ia   = document.getElementById('inbox-addr');
  if (el) el.textContent = addr;
  if (pk) pk.textContent = pub;
  if (ia) ia.textContent = addr;

  const tapEl = document.getElementById('status-tap-info');
  if (!tapEl) return;
  if (pipeState.nonce > 0n || pipeState.myBalance > 0n) {
    tapEl.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px">
        <div>
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:2px">Your balance</div>
          <div style="font-size:15px;color:var(--text)">${pipeState.myBalance.toLocaleString()} <span style="font-size:11px">sats</span></div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:2px">Nonce</div>
          <div style="font-size:15px;color:var(--text)">${pipeState.nonce}</div>
        </div>
      </div>`;
  } else {
    tapEl.textContent = 'No channel state loaded.';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab switching
// ─────────────────────────────────────────────────────────────────────────────

function showTab(name: string): void {
  document.querySelectorAll<HTMLElement>('.tab-btn').forEach(b =>
    b.classList.toggle('active', (b as HTMLElement & { dataset: { tab?: string } }).dataset.tab === name));
  document.querySelectorAll<HTMLElement>('#panel-main .tab-panel').forEach(p =>
    p.classList.toggle('active', p.id === `tab-${name}`));
  if (name === 'inbox')  loadInbox();
  if (name === 'status') loadStatus();
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

function escHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function copyToClipboard(text: string): void {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Event wiring
// ─────────────────────────────────────────────────────────────────────────────

document.getElementById('connect-wallet-btn')!.addEventListener('click', connectWallet);
document.getElementById('connect-wallet-main')!.addEventListener('click', connectWallet);
document.getElementById('disconnect-btn')!.addEventListener('click', disconnectWallet);
document.getElementById('open-mailbox-btn')!.addEventListener('click', openMailbox);
document.getElementById('check-tap-btn')!.addEventListener('click', checkTapAfterTx);

document.querySelectorAll<HTMLButtonElement>('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => showTab(btn.dataset.tab ?? ''));
});

document.getElementById('refresh-inbox-btn')!.addEventListener('click', loadInbox);
document.getElementById('show-claimed-cb')!.addEventListener('change', loadInbox);
document.getElementById('send-btn')!.addEventListener('click', sendMessage);

document.getElementById('copy-inbox-addr-btn')!.addEventListener('click', () => {
  copyToClipboard(walletAddress || '');
  const btn = document.getElementById('copy-inbox-addr-btn') as HTMLButtonElement;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
});

document.getElementById('copy-status-addr-btn')!.addEventListener('click', () => {
  copyToClipboard(walletAddress || '');
  const btn = document.getElementById('copy-status-addr-btn') as HTMLButtonElement;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
});

// Auto-fetch recipient info when a valid address is typed
let toDebounceTimer: ReturnType<typeof setTimeout> | null = null;
document.getElementById('to-input')!.addEventListener('input', (e) => {
  const val = (e.target as HTMLInputElement).value.trim();
  recipientInfo = null;
  (document.getElementById('send-btn') as HTMLButtonElement).disabled = true;
  (document.getElementById('payment-panel') as HTMLElement).style.display = 'none';
  (document.getElementById('recipient-status') as HTMLElement).textContent = '';
  if (toDebounceTimer) clearTimeout(toDebounceTimer);
  if (val.startsWith('S') && val.length >= 30) {
    toDebounceTimer = setTimeout(() => fetchRecipientInfo(val), 500);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────────────────────────────────────

setAppState('no-wallet');
