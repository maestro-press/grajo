// scripts/migrations/0040-seal-provider-keys.mjs
//
// Seal every plaintext `providers.api_key` in this instance's crow.db (design §1, §3.1):
// the shared pass in servers/gateway/keychain/provider-keys-sweep.js does the work — the
// key-state decision, the verified pre-seal backup, the consent-fingerprint rewrite and the
// in-transaction round-trip proof — and this file is only the registry entry for it.
//
// The pass has its own safety rails and this migration adds none on top:
//   * it never throws. A missing/invalid key file, a database that belongs to another Crow
//     home, a failed or unverifiable backup, low disk space or a database error all come back
//     as `{deferred: true, reason}` with a fixed-token reason, so the runner retries on a later
//     boot and an operator reads a code — never a driver message, a value or a key id.
//   * it is idempotent: an already-sealed cell is counted (`alreadySealed`) and left alone, so a
//     run whose bookkeeping row was lost (a restore) re-applies to no effect.
//   * `providers` absent is a DEFERRAL, not an applied migration: nothing has ever written a
//     provider row on this store, and recording applied would stop the retry for a store that
//     gains the table later.
//
// rollbackSafe = FALSE: older code reads `providers.api_key` as the key itself, so a rollback
// would send the envelope `pk1:<keyId>:<fp>:<base64url>` upstream as the API key and every
// cloud provider would answer 401 until the keys were re-typed. The sealed form is readable
// only by code that knows the envelope, which is strictly newer code.
//
// `allowVacuum: false`: the registry also runs post-settle, after the listeners are open (the
// post-listen convergence pass), and clearing plaintext out of freed space rebuilds the whole
// file. A residue hit here only persists the residue marker; the gateway's pre-listen seal pass
// (servers/gateway/index.js) is the one pass that may VACUUM.
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { sealPlaintextKeys } from "../../servers/gateway/keychain/provider-keys-sweep.js";

export const id = "0040-seal-provider-keys";

export const rollbackSafe = false;

export async function run({ dbPath, log = () => {} }) {
  const home = resolveCrowHome();
  const outcome = await sealPlaintextKeys(dbPath, { crowHome: home, allowVacuum: false, log });

  if (outcome.deferred) {
    // The pass already wrote its alert (if the refusal was one an operator must see).
    log(`  provider keys: deferred (${outcome.reason})`);
    return { deferred: true, reason: outcome.reason || "seal-refused" };
  }

  const c = outcome.counts;
  const results = [
    `providers.api_key: ${c.sealed} sealed`,
    `${c.alreadySealed} already sealed`,
    `${c.keyless} without a key`,
    `${c.unreadable} unreadable`,
    `${c.consentRewritten} consent rewritten`,
    c.backup ? "pre-seal backup: verified" : "pre-seal backup: not needed",
  ];
  for (const line of results) log(`  ${line}`);
  return { applied: true, results };
}