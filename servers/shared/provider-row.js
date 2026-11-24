/**
 * One `providers` DB row -> the provider object the settings panel, the role
 * resolver and every request path use. Pure enough to ride anywhere: the only
 * imports are the key SHAPE (a builtin hash) and the keyring SEAM (no imports
 * at all), so a reader that must not load providers-db.js's graph can still map
 * a row itself, and a bot-reachable module can import this file without
 * reaching the keychain, the key file or the crypto box.
 *
 * What it answers about the key (design §1.2):
 *
 *   apiKey      the PLAINTEXT, when this process can produce it: a `plain` cell
 *               is the plaintext by definition, and a well-formed sealed cell is
 *               opened through the keyring seam (null anywhere before the gateway
 *               installed one). Never an envelope, never a key id.
 *   keyPresent  does the cell hold anything at all — true for a sealed or
 *               malformed cell, so a reader never mistakes "cannot read it" for
 *               "there is no key" and falls through to an unauthenticated call.
 *   keyFp       the `fp16` identity of the key (carried by the envelope, so it
 *               needs no decryption). null when there is no key.
 *   keyState    "none" | "plain" | "sealed" | "unreadable". A malformed cell is
 *               "unreadable", and so is a well-formed envelope that does not
 *               open in a process that HAS a keyring (a damaged key file, another
 *               install's key): fail closed. In a process with no keyring a sealed
 *               cell stays "sealed" with a null apiKey — not this process's fault,
 *               so its senders answer PROVIDER_KEY_NOT_IN_PROCESS instead.
 *   storedKey   the exact stored cell, NON-ENUMERABLE: present for a writer that
 *               must round-trip the cell untouched (a re-enable, a host repair, a
 *               row upgrade), invisible to JSON.stringify, Object.keys and every
 *               log or snapshot that serialises the object.
 */
import { parseStoredKey, providerKeyFp } from "./provider-key-shape.js";
import { keyringOpen, providerKeyringInstalled } from "./provider-keyring.js";

/**
 * @param {object} r a `providers` row (any subset: `api_key` may be absent)
 * @returns {{id:any, baseUrl:any, apiKey:string|null, keyPresent:boolean,
 *            keyFp:string|null, keyState:"none"|"plain"|"sealed"|"unreadable",
 *            host:any, bundleId:any, provider_type:any, description:any,
 *            models:any[], gpuPolicy:any, disabled:boolean, lamport_ts:any,
 *            instance_id:any, created_at:any, updated_at:any}}
 */
export function providerRowToObject(r) {
  const row = r || {};
  let models = [];
  try { models = JSON.parse(row.models || "[]"); } catch {}
  let gpuPolicy = null;
  try { gpuPolicy = row.gpu_policy ? JSON.parse(row.gpu_policy) : null; } catch {}

  const stored = row.api_key;
  const parsed = parseStoredKey(stored);
  const slotId = typeof row.id === "string" ? row.id : "";
  let apiKey = null;
  let keyFp = null;
  let keyState;
  if (parsed.kind === "none") {
    keyState = "none";
  } else if (parsed.kind === "plain") {
    keyState = "plain";
    apiKey = stored;
    keyFp = providerKeyFp(stored);
  } else if (parsed.kind === "malformed") {
    keyState = "unreadable";
  } else {
    keyFp = parsed.fp;
    const opened = keyringOpen(slotId, stored);
    if (typeof opened === "string") {
      keyState = "sealed";
      apiKey = opened;
    } else {
      // Opened nothing: either this process has no keyring (it cannot read ANY
      // sealed key here) or the value genuinely does not open. Fail closed in
      // both cases; only the state tells them apart.
      keyState = providerKeyringInstalled() ? "unreadable" : "sealed";
    }
  }

  const out = {
    id: row.id,
    baseUrl: row.base_url,
    apiKey,
    keyPresent: parsed.kind !== "none",
    keyFp,
    keyState,
    host: row.host,
    bundleId: row.bundle_id,
    provider_type: row.provider_type || null,
    description: row.description,
    models,
    gpuPolicy,
    disabled: !!row.disabled,
    lamport_ts: row.lamport_ts,
    instance_id: row.instance_id,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
  // A writer that spreads this object would lose an enumerable cell; it must ask
  // for it by name (`storedKey`), which is also what keeps it out of every
  // JSON.stringify of a provider object.
  Object.defineProperty(out, "storedKey", {
    value: typeof stored === "string" ? stored : null,
    enumerable: false,
    configurable: true,
    writable: false,
  });
  return out;
}

/**
 * The state a request path should judge before it sends: "none" and "plain" and
 * "sealed" all carry an apiKey or nothing to send; "unreadable" is the refusal.
 * Tolerates an older parsed object with no `keyState` (keyPresent/apiKey only) —
 * and FAILS CLOSED on it: a cell that holds something (`keyPresent`) with no
 * plaintext to send is the refusal, never "none" (round 1, M1).
 *
 * @param {object|null} row
 * @returns {"none"|"plain"|"sealed"|"unreadable"}
 */
export function providerKeyState(row) {
  if (!row || typeof row !== "object") return "none";
  if (typeof row.keyState === "string") return row.keyState;
  if (row.keyPresent === false) return "none";
  if (typeof row.apiKey === "string" && row.apiKey !== "") return "sealed";
  return row.keyPresent === true ? "unreadable" : "none";
}

/**
 * Must a request path REFUSE this provider rather than send it? True for a key
 * this process cannot read (`keyState` "unreadable") and for any row that says
 * it HOLDS a key while carrying no plaintext to send (`keyPresent` with a null
 * apiKey — a sealed cell in a process with no keyring, an envelope under another
 * key). Both are the same refusal to a caller: never dial keyless.
 *
 * @param {object|null} row a provider object (providerRowToObject) or a resolver config
 * @returns {boolean}
 */
export function providerKeyUnreadable(row) {
  if (providerKeyState(row) === "unreadable") return true;
  return row?.keyPresent === true && (typeof row.apiKey !== "string" || row.apiKey === "");
}