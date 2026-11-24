/**
 * The gateway boot's first key (§3.2), run BEFORE the provider keyring is
 * installed (review round 1, H2).
 *
 * A fresh install has no `<CROW_HOME>/secrets/keychain.key` at boot. Before this
 * existed, the boot installed a refusing keyring and nothing ever minted, so the
 * instance could never save a provider key at all.
 *
 * The rule is the seal pass's own (design §3.2), and it is deliberately the
 * narrow one: mint ONLY when nothing on this instance could be orphaned —
 * `crow_keychain` has zero rows AND no `providers.api_key` cell holds a `pk1:`
 * envelope. Anything else (an envelope, a keychain row, a damaged key file, a
 * store that cannot be read) leaves the key missing: the refusing keyring stays,
 * the existing `[provider-keys] no usable keychain key` boot line stands, and the
 * seal pass / migration 0040 raise `keychain-key-missing` with the shared
 * refusal sentence when they meet the rows.
 *
 * Nothing here logs or returns a key value, an envelope or a key id: the result
 * is one of a few fixed action tokens.
 */
import { parseStoredKey } from "../../shared/provider-key-shape.js";
import { createKeychainKey, keychainKeyState } from "./key.js";

/**
 * Did this read fail because the table does not exist (yet)? Nothing else counts:
 * a busy or corrupted store is one this boot cannot judge, and a key minted over
 * rows it could not see would orphan every sealed value they hold.
 */
function isMissingTable(err) {
  const messages = [err?.message, err?.cause?.message]
    .filter((m) => typeof m === "string");
  return messages.some((m) => /no such table/i.test(m));
}

/**
 * Mint this instance's first keychain key when it is safe to.
 *
 * @param {{db: {execute: Function}|null, crowHome?: string}} args
 * @returns {Promise<{action: "present"|"minted"|"key-invalid"|"orphan-risk"|"db-error"|"mint-failed"}>}
 */
export async function mintProviderKeyAtBoot({ db = null, crowHome } = {}) {
  const options = crowHome ? { crowHome } : undefined;
  const state = keychainKeyState(options);
  if (state.key) return { action: "present" };
  // A damaged file may still be restorable: never replace it here.
  if (state.state === "invalid") return { action: "key-invalid" };
  if (!db || typeof db.execute !== "function") return { action: "db-error" };

  let keychainRows;
  try {
    ({ rows: keychainRows } = await db.execute({ sql: "SELECT COUNT(*) AS n FROM crow_keychain", args: [] }));
  } catch (err) {
    // No crow_keychain table yet means no keychain entry exists: that half of the
    // rule is satisfied. Any OTHER read failure (SQLITE_BUSY, a corrupt store) is
    // a store this boot cannot judge, so it mints nothing and the refusing keyring
    // stays — the pre-listen seal pass repeats the same judgement.
    if (!isMissingTable(err)) return { action: "db-error" };
    keychainRows = null;
  }
  let envelopeRows;
  try {
    ({ rows: envelopeRows } = await db.execute({ sql: "SELECT api_key FROM providers", args: [] }));
  } catch {
    return { action: "db-error" };
  }
  if (keychainRows && Number(keychainRows[0]?.n ?? 0) > 0) return { action: "orphan-risk" };
  for (const row of envelopeRows || []) {
    if (parseStoredKey(row?.api_key).kind === "envelope") return { action: "orphan-risk" };
  }
  try {
    const key = createKeychainKey(options);
    return key ? { action: "minted" } : { action: "mint-failed" };
  } catch {
    return { action: "mint-failed" };
  }
}