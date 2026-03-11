/**
 * Stackmail server — entry point
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { loadConfig, type Config } from './types.js';
import { SqliteMessageStore } from './store.js';
import { ReservoirService } from './reservoir.js';
import { createMailServer } from './app.js';
import { pubkeyToStxAddress } from './auth.js';

type ServerIdentitySource = 'env' | 'db' | 'generated';

function normalizePrivateKeyHex(value: string): string | null {
  const normalized = value.trim().replace(/^0x/, '').toLowerCase();
  if (!normalized) return null;
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

function normalizePrincipal(value: string): string | null {
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function isStandardPrincipal(value: string): boolean {
  return /^S[PT][0-9A-Z]{39}$/.test(value);
}

function isContractPrincipal(value: string): boolean {
  return /^S[PT][0-9A-Z]{39}\.[a-zA-Z][a-zA-Z0-9-]{0,39}$/.test(value);
}

function isPrincipal(value: string): boolean {
  return isStandardPrincipal(value) || isContractPrincipal(value);
}

function deriveStxAddressFromPrivateKey(privateKeyHex: string, chainId: number): string {
  const pubkey = secp256k1.getPublicKey(privateKeyHex, true);
  const pubkeyHex = Buffer.from(pubkey).toString('hex');
  return pubkeyToStxAddress(pubkeyHex, chainId !== 1);
}

function resolveServerIdentity(
  config: Config,
  db: import('better-sqlite3').Database,
): { privateKey: string; address: string; source: ServerIdentitySource } {
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  const getMetaStmt = db.prepare('SELECT value FROM meta WHERE key = ?');
  const setMetaStmt = db.prepare(`
    INSERT INTO meta (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `);
  const getMeta = (key: string): string | null => {
    const row = getMetaStmt.get(key) as { value: string } | undefined;
    return row?.value ?? null;
  };
  const setMeta = (key: string, value: string): void => {
    setMetaStmt.run(key, value);
  };

  const envKeyRaw = config.serverPrivateKey.trim();
  if (envKeyRaw && !normalizePrivateKeyHex(envKeyRaw)) {
    throw new Error('STACKMAIL_SERVER_PRIVATE_KEY must be a 32-byte hex string');
  }

  const envAddressRaw = config.serverStxAddress.trim();
  const envAddress = normalizePrincipal(envAddressRaw);
  if (envAddress && !isPrincipal(envAddress)) {
    throw new Error('STACKMAIL_SERVER_STX_ADDRESS must be a valid STX principal');
  }

  let source: ServerIdentitySource = 'env';
  let privateKey = normalizePrivateKeyHex(envKeyRaw);
  if (!privateKey) {
    const storedKey = normalizePrivateKeyHex(getMeta('server_private_key') ?? '');
    if (storedKey) {
      privateKey = storedKey;
      source = 'db';
    }
  }
  if (!privateKey) {
    privateKey = Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex');
    source = 'generated';
  }

  const derivedAddress = deriveStxAddressFromPrivateKey(privateKey, config.chainId);

  const storedAddress = normalizePrincipal(getMeta('server_stx_address') ?? '');
  const address = envAddress ?? storedAddress ?? derivedAddress;
  if (!isPrincipal(address)) {
    throw new Error('unable to resolve a valid server STX principal');
  }

  // For standard principals, enforce key/address consistency.
  if (isStandardPrincipal(address) && address !== derivedAddress) {
    throw new Error(
      `server address (${address}) does not match configured signing key-derived address (${derivedAddress})`,
    );
  }

  // Keep identity durable for container restarts.
  setMeta('server_private_key', privateKey);
  setMeta('server_stx_address', address);
  return { privateKey, address, source };
}

async function main(): Promise<void> {
  const baseConfig = loadConfig();
  const config = { ...baseConfig };
  await mkdir(dirname(config.dbFile), { recursive: true });

  const store = new SqliteMessageStore(config.dbFile);
  await store.init();
  console.log('stackmail: database ready');

  // Inline reservoir shares the same SQLite DB as the message store
  const { default: Database } = await import('better-sqlite3');
  const reservoirDb = new Database(config.dbFile);
  reservoirDb.pragma('journal_mode = WAL');
  reservoirDb.pragma('synchronous = NORMAL');

  const identity = resolveServerIdentity(config, reservoirDb);
  config.serverPrivateKey = identity.privateKey;
  config.serverStxAddress = identity.address;
  if (identity.source === 'generated') {
    console.warn(
      `stackmail: generated server key and persisted it to DB meta (address: ${config.serverStxAddress})`,
    );
  } else if (identity.source === 'db') {
    console.warn(
      `stackmail: loaded server key from DB meta (address: ${config.serverStxAddress})`,
    );
  }

  if (!config.sfContractId) {
    console.warn('stackmail: STACKMAIL_SF_CONTRACT_ID not set — outgoing payments disabled');
  }

  const reservoir = new ReservoirService({
    db: reservoirDb,
    serverAddress: config.serverStxAddress,
    serverPrivateKey: config.serverPrivateKey,
    contractId: config.sfContractId,
    chainId: config.chainId,
    minFeeSats: config.minFeeSats,
    messagePriceSats: config.messagePriceSats,
  });

  const server = createMailServer(config, store, reservoir);

  server.listen(config.port, config.host, () => {
    console.log(`stackmail: listening on ${config.host}:${config.port}`);
    console.log(`stackmail: network=${config.chainId === 1 ? 'mainnet' : 'testnet'}, contract=${config.sfContractId || '(none)'}`);
  });
}

main().catch(err => {
  console.error('fatal:', err);
  process.exit(1);
});
