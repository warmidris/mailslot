#!/usr/bin/env node

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { getAddressFromPrivateKey, privateKeyToPublic } from '@stacks/transactions';

const clientDistPath = resolve(process.cwd(), 'packages/client/dist/index.js');

if (!existsSync(clientDistPath)) {
  console.error(
    'Missing packages/client/dist/index.js. Run: npm run build --workspace @stackmail/client'
  );
  process.exit(1);
}

const { StackmailClient } = await import(clientDistPath);

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const value = rest[i + 1];
    if (!value || value.startsWith('--')) {
      options[key] = 'true';
      continue;
    }
    options[key] = value;
    i += 1;
  }
  return { command, options };
}

function normalizePrivateKey(input) {
  const trimmed = String(input ?? '').trim().replace(/^0x/i, '');
  if (/^[0-9a-fA-F]{66}$/.test(trimmed) && trimmed.toLowerCase().endsWith('01')) {
    return trimmed.slice(0, 64);
  }
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return trimmed;
  throw new Error('Expected a 64-char hex private key or a 66-char Stacks key ending in 01');
}

function usage() {
  console.log(`Stackmail CLI

Usage:
  node scripts/stackmail-cli.mjs inbox --private-key <hex> [--server <url>] [--claimed true]
  node scripts/stackmail-cli.mjs claim --private-key <hex> --message-id <id> [--server <url>]
  node scripts/stackmail-cli.mjs poll --private-key <hex> [--server <url>] [--limit <n>]
`);
}

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));
  if (!command || command === 'help' || command === '--help') {
    usage();
    return;
  }

  const privateKey = normalizePrivateKey(options['private-key']);
  const serverUrl = options.server ?? process.env.STACKMAIL_SERVER_URL ?? 'http://127.0.0.1:8800';
  const network = options.network ?? process.env.STACKMAIL_STACKS_NETWORK ?? 'mainnet';
  const chainId = network === 'mainnet' ? 1 : 2147483648;
  const address = getAddressFromPrivateKey(privateKey, network);
  const publicKey = privateKeyToPublic(privateKey);

  const client = new StackmailClient({
    serverUrl,
    privateKey,
    publicKey,
    address,
    chainId,
  });

  if (command === 'inbox') {
    const includeClaimed = String(options.claimed ?? '').toLowerCase() === 'true';
    const messages = await client.getInbox({ includeClaimed });
    console.log(JSON.stringify({ address, messages }, null, 2));
    return;
  }

  if (command === 'claim') {
    if (!options['message-id']) throw new Error('--message-id is required for claim');
    const message = await client.claim(options['message-id']);
    console.log(JSON.stringify(message, null, 2));
    return;
  }

  if (command === 'poll') {
    const limit = options.limit ? Number(options.limit) : undefined;
    const result = await client.poll({ limit });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
