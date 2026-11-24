/**
 * Test fixture for the sealed provider-key work (design §1.2): a keyring and a
 * scratch instance.
 *
 * `installTestKeyring()` installs a real keyring — the gateway's own provider-key
 * box, bound to a key that exists only in this process — into the shared seam.
 * That is what a test needs to exercise a gateway read: the box is the only thing
 * that can open an envelope, and its format, AAD and fingerprint rules are the
 * product's, not a test double's.
 *
 * `makeInstance()` builds a scratch crow.db (schema from scripts/init-db.js) and
 * points CROW_DATA_DIR at it, the same harness providers-upsert-noop.test.js
 * uses, so getOrCreateLocalInstanceId writes its instance id there and the real
 * ~/.crow is never touched.
 */
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient } from "@libsql/client";
import { installProviderKeyring, clearProviderKeyring } from "../../servers/shared/provider-keyring.js";
import { open as openKey, seal as sealKey } from "../../servers/gateway/keychain/provider-key-box.js";

/** A keychain key usable by the provider-key box: `{ id: 16 hex, seed: 32 bytes }`. */
export function testKeychainKey() {
  return { id: randomBytes(8).toString("hex"), seed: randomBytes(32) };
}

/**
 * Install a keyring into the shared seam, bound to `key` (a fresh one by default).
 * @returns {{key: {id: string, seed: Buffer}, uninstall: () => void}}
 */
export function installTestKeyring({ key = testKeychainKey() } = {}) {
  installProviderKeyring({
    open: (slotId, stored) => openKey({ slotId, stored, key }),
    seal: (slotId, plaintext) => sealKey({ slotId, plaintext, key }),
  });
  return { key, uninstall: () => clearProviderKeyring() };
}

/**
 * A scratch instance: `{ dir, db, dbPath, cleanup() }`. `cleanup` closes the
 * client, restores CROW_DATA_DIR and removes the directory.
 */
export function makeInstance(prefix = "provider-keys-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe",
    cwd: join(import.meta.dirname, "..", ".."),
  });
  const prevDataDir = process.env.CROW_DATA_DIR;
  process.env.CROW_DATA_DIR = dir;
  const dbPath = join(dir, "crow.db");
  const db = createClient({ url: "file:" + dbPath });
  return {
    dir,
    db,
    dbPath,
    cleanup() {
      clearProviderKeyring();
      if (prevDataDir === undefined) delete process.env.CROW_DATA_DIR;
      else process.env.CROW_DATA_DIR = prevDataDir;
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    },
  };
}