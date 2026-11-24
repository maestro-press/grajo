#!/usr/bin/env node
/**
 * Provider-key UNSEAL (design §3.3): put every sealed `providers.api_key` back
 * in the clear, for an instance that must go back to code that reads the column
 * as the key itself.
 *
 *   node scripts/ops/provider-keys-unseal.mjs --crow-home <dir> --yes
 *
 * `--yes` is mandatory: this is the one operation that reduces the protection of
 * the saved keys, and it must never be something a script gets by accident.
 *
 * The pass (servers/gateway/keychain/provider-keys-sweep.js `unsealAllKeys`)
 * takes a verified `crow-pre-unseal-<ts>.db` copy FIRST, writes in one
 * transaction, and leaves `updated_at` and `lamport_ts` alone. A refusal — no key
 * file, a database that belongs to another home, a failed backup — exits 1 and
 * changes nothing.
 *
 * This tool prints counts only: never a key value, an envelope, a key id or a
 * driver message.
 */
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { unsealAllKeys } from "../../servers/gateway/keychain/provider-keys-sweep.js";

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: node scripts/ops/provider-keys-unseal.mjs --crow-home <dir> --yes\n");
  process.exit(2);
}

function parseArgs(argv) {
  const out = { crowHome: null, yes: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--crow-home") out.crowHome = argv[++i] ?? null;
    else if (arg === "--yes") out.yes = true;
    else if (arg === "--help" || arg === "-h") usage();
    else usage(`unexpected argument: ${arg}`);
  }
  if (!out.crowHome) usage("--crow-home is required");
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (!args.yes) {
  process.stderr.write("refused: --yes is required to unseal saved provider keys\n");
  process.exit(1);
}

const crowHome = resolve(args.crowHome);
const dbPath = process.env.CROW_DB_PATH
  ? resolve(process.env.CROW_DB_PATH)
  : [join(crowHome, "data", "crow.db"), join(crowHome, "crow.db")].find((p) => existsSync(p)) ?? join(crowHome, "data", "crow.db");

process.env.CROW_HOME = crowHome;

const outcome = await unsealAllKeys(dbPath, { crowHome, log: () => {} });

if (outcome.deferred) {
  process.stdout.write(`outcome: refused (${outcome.reason})\n`);
  process.stdout.write(`unsealed: 0; keyless: ${outcome.counts.keyless}; unreadable: ${outcome.counts.unreadable}; backups: 0\n`);
  process.exit(1);
}

process.stdout.write(
  `outcome: unsealed\n` +
  `unsealed: ${outcome.counts.unsealed}; keyless: ${outcome.counts.keyless}; ` +
  `unreadable: ${outcome.counts.unreadable}; backups: ${outcome.counts.backup ? 1 : 0}\n`,
);
process.exit(0);