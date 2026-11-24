/**
 * The DISPLAY set of saved provider API keys (design §1.2), opened HOST-SIDE.
 *
 * A provider key must be masked in a log, a notification or a transcript, so the
 * masking set includes every sealed `providers.api_key` this home can open. Doing
 * that needs the provider-key box and the keychain key — both host-only — so this
 * module is the host's own door for it, NOT something bot-reachable code imports:
 *
 *   scripts/pi-bots/bridge.mjs      the bot engine, at each spawn
 *   servers/gateway/index.js        the gateway, at boot
 *
 * Both call `installProviderKeyValuesSource()`, which hands the collector to
 * servers/shared/secret-values-collect.js through its host-installed seam (the
 * same shape as the provider-keyring seam) — so that file, which a bot-reachable
 * process loads, never imports the box itself.
 *
 * What counts, and what never does:
 *   - a well-formed `pk1:` envelope is opened with this home's keychain key;
 *   - a PLAINTEXT cell is not collected: a bot can write one, and a planted value
 *     must never be allowed to hide text;
 *   - a cell that does not open (another install's envelope, a damaged key file)
 *     contributes nothing.
 *
 * Display set only: these values mask what is shown. They never join the card set
 * (the payload every bot's pi receives). Nothing here logs or returns a value
 * anywhere but that masking list.
 */
import Database from "better-sqlite3";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { resolveInstanceDataDir } from "../../shared/crow-home.js";
import { anchoredPath } from "../../shared/secret-values.js";
import { isProviderKeyEnvelope } from "../../shared/provider-key-shape.js";
import { setProviderKeyValuesSource } from "../../shared/secret-values-collect.js";
import { loadKeychainKey } from "./key.js";
import { open as openProviderKey } from "./provider-key-box.js";

/**
 * The instance's saved provider API keys, opened on the host side.
 *
 * @param {{dbPath?: string|null, env?: object}} [o]
 * @returns {string[]} the opened values (never logged, never returned elsewhere)
 */
export function providerKeyValues({ dbPath, env = process.env } = {}) {
  const db = dbPath === undefined ? (env.CROW_DB_PATH || join(resolveInstanceDataDir(env), "crow.db")) : dbPath;
  const keyPath = anchoredPath(env, "keychain.key");
  if (!db || !existsSync(db) || !keyPath) return [];
  let handle;
  try {
    handle = new Database(db, { readonly: true, fileMustExist: true });
    handle.pragma("busy_timeout = 2000");
    const key = loadKeychainKey({ path: keyPath });
    if (!key) return [];
    const rows = handle.prepare("SELECT id, api_key FROM providers").all();
    const out = [];
    for (const r of rows) {
      if (!isProviderKeyEnvelope(r.api_key)) continue;
      const opened = openProviderKey({ slotId: String(r.id), stored: r.api_key, key });
      if (typeof opened === "string" && opened !== "") out.push(opened);
    }
    return out;
  } catch {
    return [];
  } finally {
    if (handle) { try { handle.close(); } catch { /* closed */ } }
  }
}

/**
 * Hand this collector to the masking set. Called by the host processes that build
 * it (the bot engine and the gateway); calling it twice is harmless.
 */
export function installProviderKeyValuesSource() {
  setProviderKeyValuesSource(providerKeyValues);
}