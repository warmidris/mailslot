/**
 * Stackmail server — entry point
 */

import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { loadConfig } from './types.js';
import { SqliteMessageStore } from './store.js';
import { ReservoirService } from './reservoir.js';
import { createMailServer } from './app.js';

async function main(): Promise<void> {
  const config = loadConfig();
  await mkdir(dirname(config.dbFile), { recursive: true });

  const store = new SqliteMessageStore(config.dbFile);
  await store.init();
  console.log('stackmail: database ready');

  if (!config.serverPrivateKey) {
    if (config.allowInsecurePayments) {
      console.warn('stackmail: STACKMAIL_SERVER_PRIVATE_KEY not set — insecure payment verification enabled');
    } else {
      console.warn('stackmail: STACKMAIL_SERVER_PRIVATE_KEY not set — payment verification disabled');
    }
  }
  if (!config.sfContractId) {
    console.warn('stackmail: STACKMAIL_SF_CONTRACT_ID not set — outgoing payments disabled');
  }

  // Inline reservoir shares the same SQLite DB as the message store
  const { default: Database } = await import('better-sqlite3');
  const reservoirDb = new Database(config.dbFile);
  reservoirDb.pragma('journal_mode = WAL');
  reservoirDb.pragma('synchronous = NORMAL');

  const reservoir = new ReservoirService({
    db: reservoirDb,
    serverAddress: config.serverStxAddress,
    serverPrivateKey: config.serverPrivateKey,
    allowInsecurePayments: config.allowInsecurePayments,
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
