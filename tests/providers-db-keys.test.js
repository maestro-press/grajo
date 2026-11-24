// tests/providers-db-keys.test.js — provider keys at rest (design §1.2).
//
// The one write door (providers-db.js `upsertProvider`) seals a plaintext key,
// passes a well-formed envelope through, keeps the `none` sentinel, and REFUSES
// (`PROVIDER_KEY_SEAL_UNAVAILABLE`, no write at all) in a process with no
// keyring. The one read door (provider-row.js `providerRowToObject`) answers
// apiKey/keyPresent/keyFp/keyState and carries the exact stored cell as a
// NON-enumerable `storedKey`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  upsertProvider,
  seedProvidersFromModelsJson,
  syncProvidersFromModelsJson,
  listProvidersAll,
} from "../servers/shared/providers-db.js";
import { providerRowToObject } from "../servers/shared/provider-row.js";
import { parseStoredKey, providerKeyFp } from "../servers/shared/provider-key-shape.js";
import { clearProviderKeyring, PROVIDER_KEY_SEAL_UNAVAILABLE } from "../servers/shared/provider-keyring.js";
import { mintProviderKeyAtBoot } from "../servers/gateway/keychain/boot-key.js";
import { keychainKeyPath, loadKeychainKey } from "../servers/gateway/keychain/key.js";
import { makeInstance, installTestKeyring } from "./fixtures/provider-keys.mjs";

const KEY = "demo-planted-plaintext-key-0001";

function provider(id, extra = {}) {
  return {
    id,
    baseUrl: "https://api.example.com/v1",
    apiKey: null,
    host: "cloud",
    bundleId: null,
    description: null,
    models: [{ id: "m1" }],
    disabled: false,
    providerType: "openai",
    ...extra,
  };
}

async function storedCell(db, id) {
  const { rows } = await db.execute({ sql: "SELECT api_key FROM providers WHERE id = ?", args: [id] });
  return rows[0]?.api_key ?? null;
}

test("a plaintext key is sealed on the way in and opened on the way out", async () => {
  const inst = makeInstance("providers-db-keys-");
  const { uninstall } = installTestKeyring();
  try {
    await upsertProvider(inst.db, provider("cloud-a", { apiKey: KEY }));
    const cell = await storedCell(inst.db, "cloud-a");
    assert.notEqual(cell, KEY, "the plaintext is not what the row stores");
    assert.equal(parseStoredKey(cell).kind, "envelope");
    assert.equal(parseStoredKey(cell).fp, providerKeyFp(KEY));

    const [row] = await listProvidersAll(inst.db);
    assert.equal(row.apiKey, KEY, "the gateway opens the key");
    assert.equal(row.keyState, "sealed");
    assert.equal(row.keyPresent, true);
    assert.equal(row.keyFp, providerKeyFp(KEY));
    assert.equal(row.storedKey, cell);

    // Serialising a provider object never carries the cell or a key id; apiKey is
    // the OPENED plaintext, which is exactly what a gateway reader needs.
    const json = JSON.stringify(row);
    assert.equal(json.includes(cell), false, "no envelope in JSON");
    assert.equal(json.includes("pk1:"), false, "no key id / envelope prefix in JSON");
    assert.equal(Object.keys(row).includes("storedKey"), false, "storedKey is not enumerable");
    assert.equal(Object.getOwnPropertyDescriptor(row, "storedKey").enumerable, false);
  } finally {
    uninstall();
    inst.cleanup();
  }
});

test("a well-formed envelope passes through unchanged; the none sentinel is kept", async () => {
  const inst = makeInstance("providers-db-keys-");
  const { key, uninstall } = installTestKeyring();
  try {
    const { seal } = await import("../servers/gateway/keychain/provider-key-box.js");
    const env = seal({ slotId: "cloud-b", plaintext: KEY, key });
    await upsertProvider(inst.db, provider("cloud-b", { apiKey: env }));
    assert.equal(await storedCell(inst.db, "cloud-b"), env, "a sealed value is stored as it came");

    await upsertProvider(inst.db, provider("cloud-c", { apiKey: "none" }));
    assert.equal(await storedCell(inst.db, "cloud-c"), "none", "the none sentinel is kept");
    const row = providerRowToObject((await inst.db.execute({ sql: "SELECT * FROM providers WHERE id = 'cloud-c'" })).rows[0]);
    assert.equal(row.keyState, "none");
    assert.equal(row.keyPresent, false);
    assert.equal(row.apiKey, null);
  } finally {
    uninstall();
    inst.cleanup();
  }
});

test("re-saving the same key is a no-op and keeps the stored envelope byte for byte", async () => {
  const inst = makeInstance("providers-db-keys-");
  const { uninstall } = installTestKeyring();
  try {
    await upsertProvider(inst.db, provider("cloud-d", { apiKey: KEY }));
    const first = await storedCell(inst.db, "cloud-d");
    const again = await upsertProvider(inst.db, provider("cloud-d", { apiKey: `  ${KEY}\n` }));
    assert.equal(again.unchanged, true, "same key, no write");
    assert.equal(await storedCell(inst.db, "cloud-d"), first, "no new envelope (no new nonce)");

    const changed = await upsertProvider(inst.db, provider("cloud-d", { apiKey: `${KEY}-other` }));
    assert.equal(changed.unchanged, undefined);
    const second = await storedCell(inst.db, "cloud-d");
    assert.notEqual(second, first);
    assert.equal(providerRowToObject({ id: "cloud-d", api_key: second }).apiKey, `${KEY}-other`);
  } finally {
    uninstall();
    inst.cleanup();
  }
});

test("a round-tripped parsed row (spread + storedKey) keeps the key", async () => {
  const inst = makeInstance("providers-db-keys-");
  const { uninstall } = installTestKeyring();
  try {
    await upsertProvider(inst.db, provider("cloud-e", { apiKey: KEY }));
    const before = await storedCell(inst.db, "cloud-e");
    const [row] = await listProvidersAll(inst.db);
    // The disabled→enabled and host-repair paths do exactly this.
    await upsertProvider(inst.db, { ...row, storedKey: row.storedKey, host: "cloud", disabled: false });
    assert.equal(await storedCell(inst.db, "cloud-e"), before);
  } finally {
    uninstall();
    inst.cleanup();
  }
});

test("without a keyring a plaintext write REFUSES and writes nothing", async () => {
  const inst = makeInstance("providers-db-keys-");
  try {
    clearProviderKeyring();
    await assert.rejects(
      () => upsertProvider(inst.db, provider("cloud-f", { apiKey: KEY })),
      (err) => err.code === PROVIDER_KEY_SEAL_UNAVAILABLE,
    );
    const { rows } = await inst.db.execute({ sql: "SELECT COUNT(*) AS n FROM providers" });
    assert.equal(Number(rows[0].n), 0, "nothing was written");

    // An existing row is not rewritten either (the seal throws before the INSERT).
    const { uninstall } = installTestKeyring();
    await upsertProvider(inst.db, provider("cloud-g", { apiKey: KEY }));
    const cell = await storedCell(inst.db, "cloud-g");
    uninstall();
    await assert.rejects(
      () => upsertProvider(inst.db, provider("cloud-g", { apiKey: `${KEY}-rotated` })),
      (err) => err.code === PROVIDER_KEY_SEAL_UNAVAILABLE,
    );
    assert.equal(await storedCell(inst.db, "cloud-g"), cell, "the old sealed cell is intact");
  } finally {
    inst.cleanup();
  }
});

test("in a process with no keyring a sealed cell reads as 'sealed' with no plaintext, never 'none'", async () => {
  const inst = makeInstance("providers-db-keys-");
  const { uninstall } = installTestKeyring();
  await upsertProvider(inst.db, provider("cloud-h", { apiKey: KEY }));
  uninstall();
  try {
    const row = providerRowToObject((await inst.db.execute({ sql: "SELECT * FROM providers WHERE id = 'cloud-h'" })).rows[0]);
    assert.equal(row.apiKey, null);
    assert.equal(row.keyState, "sealed");
    assert.equal(row.keyPresent, true, "presence is a shape fact, not a read");
    assert.equal(row.keyFp, providerKeyFp(KEY), "the fingerprint needs no decryption");
  } finally {
    inst.cleanup();
  }
});

test("a malformed cell is unreadable: no plaintext, presence kept, the envelope never sent", async () => {
  const inst = makeInstance("providers-db-keys-");
  const { uninstall } = installTestKeyring();
  try {
    await inst.db.execute({
      sql: "INSERT INTO providers (id, base_url, api_key, host, models, disabled, lamport_ts, instance_id) VALUES (?,?,?,?,?,0,1,?)",
      args: ["cloud-i", "https://api.example.com/v1", "pk1:not-an-envelope", "cloud", "[]", "inst"],
    });
    const row = providerRowToObject((await inst.db.execute({ sql: "SELECT * FROM providers WHERE id = 'cloud-i'" })).rows[0]);
    assert.equal(row.keyState, "unreadable");
    assert.equal(row.apiKey, null);
    assert.equal(row.keyPresent, true);
    assert.equal(row.keyFp, null);
  } finally {
    uninstall();
    inst.cleanup();
  }
});

test("a sealed cell under ANOTHER keychain key is unreadable (fail closed)", async () => {
  const inst = makeInstance("providers-db-keys-");
  const other = installTestKeyring();
  try {
    await upsertProvider(inst.db, provider("cloud-j", { apiKey: KEY }));
    // Rotate the install's key: nothing in the row opens any more.
    const fresh = installTestKeyring();
    const row = providerRowToObject((await inst.db.execute({ sql: "SELECT * FROM providers WHERE id = 'cloud-j'" })).rows[0]);
    assert.equal(row.keyState, "unreadable");
    assert.equal(row.apiKey, null);
    fresh.uninstall();
  } finally {
    other.uninstall();
    inst.cleanup();
  }
});

test("H2: the boot mints this instance's first key when nothing can be orphaned", async () => {
  const home = mkdtempSync(join(tmpdir(), "providers-db-keys-boot-"));
  const inst = makeInstance("providers-db-keys-boot-");
  try {
    assert.deepEqual(await mintProviderKeyAtBoot({ db: inst.db, crowHome: home }), { action: "minted" });
    assert.ok(loadKeychainKey({ crowHome: home }), "the key exists after the boot");
    // A second boot finds it and mints nothing.
    assert.deepEqual(await mintProviderKeyAtBoot({ db: inst.db, crowHome: home }), { action: "present" });
  } finally {
    inst.cleanup();
    rmSync(home, { recursive: true, force: true });
  }
});

test("H2: an envelope or a keychain row blocks the boot mint, and no key file appears", async () => {
  const home = mkdtempSync(join(tmpdir(), "providers-db-keys-boot-env-"));
  const inst = makeInstance("providers-db-keys-boot-env-");
  try {
    await inst.db.execute({
      sql: "INSERT INTO providers (id, base_url, api_key, host, models, disabled, lamport_ts, instance_id) VALUES (?,?,?,?,?,0,1,?)",
      args: ["cloud-a", "https://api.example.com/v1", "pk1:0123456789abcdef:0123456789abcdef:AAAA", "cloud", "[]", "inst"],
    });
    assert.deepEqual(await mintProviderKeyAtBoot({ db: inst.db, crowHome: home }), { action: "orphan-risk" });
    assert.equal(loadKeychainKey({ crowHome: home }), null, "nothing was minted over a sealed value");
  } finally {
    inst.cleanup();
    rmSync(home, { recursive: true, force: true });
  }

  const home2 = mkdtempSync(join(tmpdir(), "providers-db-keys-boot-kc-"));
  const inst2 = makeInstance("providers-db-keys-boot-kc-");
  try {
    await inst2.db.execute({
      sql: "INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin) VALUES ('extension', 'x', 'b', 'E', 'blob', ?, 'typed')",
      args: ["fedcba9876543210"],
    });
    assert.deepEqual(await mintProviderKeyAtBoot({ db: inst2.db, crowHome: home2 }), { action: "orphan-risk" });
    assert.equal(loadKeychainKey({ crowHome: home2 }), null);
  } finally {
    inst2.cleanup();
    rmSync(home2, { recursive: true, force: true });
  }
});

test("H2: a damaged key file is never replaced at boot, and an unreadable store mints nothing", async () => {
  const home = mkdtempSync(join(tmpdir(), "providers-db-keys-boot-bad-"));
  const inst = makeInstance("providers-db-keys-boot-bad-");
  const damaged = "{\"v\":1,\"id\":\"short\",\"key\":\"AAAA\"}\n";
  try {
    mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
    writeFileSync(keychainKeyPath(home), damaged, { mode: 0o600 });
    assert.deepEqual(await mintProviderKeyAtBoot({ db: inst.db, crowHome: home }), { action: "key-invalid" });
    assert.equal(readFileSync(keychainKeyPath(home), "utf8"), damaged, "a restorable file is left alone");
    // No database at all: the boot cannot judge what a new key would orphan.
    assert.deepEqual(await mintProviderKeyAtBoot({ db: null, crowHome: home }), { action: "key-invalid" });
  } finally {
    inst.cleanup();
    rmSync(home, { recursive: true, force: true });
  }
  const bare = mkdtempSync(join(tmpdir(), "providers-db-keys-boot-nodb-"));
  try {
    assert.deepEqual(await mintProviderKeyAtBoot({ db: null, crowHome: bare }), { action: "db-error" });
    assert.equal(loadKeychainKey({ crowHome: bare }), null);
  } finally {
    rmSync(bare, { recursive: true, force: true });
  }
});

test("H2/L2: the boot mints ONLY when crow_keychain reads clean — a busy or broken store mints nothing", async () => {
  const home = mkdtempSync(join(tmpdir(), "providers-db-keys-boot-busy-"));
  try {
    // Any read failure that is NOT "no such table" is a store this boot cannot
    // judge: a key minted over rows it could not see would orphan them.
    for (const err of [
      Object.assign(new Error("SQLITE_BUSY: database is locked"), { code: "SQLITE_BUSY" }),
      Object.assign(new Error("database disk image is malformed"), { code: "SQLITE_CORRUPT" }),
      Object.assign(new Error("read failed"), { cause: new Error("SQLITE_IOERR: disk I/O error") }),
    ]) {
      const db = {
        async execute({ sql }) {
          if (/crow_keychain/i.test(sql)) throw err;
          return { rows: [] };
        },
      };
      assert.deepEqual(await mintProviderKeyAtBoot({ db, crowHome: home }), { action: "db-error" }, err.message);
      assert.equal(loadKeychainKey({ crowHome: home }), null, "the refusing keyring stays");
    }

    // "No such table" is the one failure that satisfies that half of the rule: a
    // fresh store with nothing to orphan mints its first key.
    const empty = {
      async execute({ sql }) {
        if (/crow_keychain/i.test(sql)) throw new Error("SQLITE_UNKNOWN: SQLite error: no such table: crow_keychain");
        return { rows: [] };
      },
    };
    assert.deepEqual(await mintProviderKeyAtBoot({ db: empty, crowHome: home }), { action: "minted" });
    assert.ok(loadKeychainKey({ crowHome: home }), "the key exists after the mint");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("the models.json seed seals through the keyring, and skips (never writes plaintext) without one", async () => {
  const dir = mkdtempSync(join(tmpdir(), "providers-db-keys-models-"));
  const prevPath = process.env.CROW_PI_MODELS_SYNC_PATH;
  const prevHome = process.env.HOME;
  const prevCrow = process.env.CROW_HOME;
  const prevModels = process.env.CROW_MODELS_JSON;
  const inst = makeInstance("providers-db-keys-seed-");
  const modelsJson = join(dir, "models.json");
  writeFileSync(modelsJson, JSON.stringify({
    providers: {
      "seed-a": { baseUrl: "https://api.example.com/v1", apiKey: KEY, models: [{ id: "m1" }] },
    },
  }));
  process.env.CROW_PI_MODELS_SYNC_PATH = modelsJson;
  process.env.CROW_MODELS_JSON = modelsJson;
  try {
    clearProviderKeyring();
    const skipped = await seedProvidersFromModelsJson(inst.db);
    assert.equal(skipped.seeded, 0);
    assert.equal(skipped.skipped_key_unavailable, 1);
    const { rows } = await inst.db.execute({ sql: "SELECT api_key FROM providers" });
    assert.deepEqual(rows, [], "nothing written without a keyring");

    const { uninstall } = installTestKeyring();
    const seeded = await seedProvidersFromModelsJson(inst.db);
    uninstall();
    assert.equal(seeded.seeded, 1);
    const cell = await storedCell(inst.db, "seed-a");
    assert.equal(parseStoredKey(cell).kind, "envelope");
    assert.equal(String(cell).includes(KEY), false);
    // The same rule on the reconcile path.
    assert.equal(typeof readFileSync(modelsJson, "utf8"), "string");
  } finally {
    if (prevPath === undefined) delete process.env.CROW_PI_MODELS_SYNC_PATH; else process.env.CROW_PI_MODELS_SYNC_PATH = prevPath;
    if (prevModels === undefined) delete process.env.CROW_MODELS_JSON; else process.env.CROW_MODELS_JSON = prevModels;
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevCrow === undefined) delete process.env.CROW_HOME; else process.env.CROW_HOME = prevCrow;
    inst.cleanup();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the reconcile path counts a key it cannot seal and writes nothing in the clear", async () => {
  const dir = mkdtempSync(join(tmpdir(), "providers-db-keys-reconcile-"));
  const prevPath = process.env.CROW_PI_MODELS_SYNC_PATH;
  const prevModels = process.env.CROW_MODELS_JSON;
  const inst = makeInstance("providers-db-keys-reconcile-");
  const modelsJson = join(dir, "models.json");
  writeFileSync(modelsJson, JSON.stringify({
    providers: { "seed-b": { baseUrl: "https://api.example.com/v1", apiKey: KEY, models: [{ id: "m1" }] } },
  }));
  process.env.CROW_PI_MODELS_SYNC_PATH = modelsJson;
  process.env.CROW_MODELS_JSON = modelsJson;
  try {
    clearProviderKeyring();
    const res = await syncProvidersFromModelsJson(inst.db, { force: true });
    assert.equal(res.skipped_key_unavailable, 1);
    const { rows } = await inst.db.execute({ sql: "SELECT api_key FROM providers" });
    assert.deepEqual(rows, [], "no plaintext row was created");
  } finally {
    if (prevPath === undefined) delete process.env.CROW_PI_MODELS_SYNC_PATH; else process.env.CROW_PI_MODELS_SYNC_PATH = prevPath;
    if (prevModels === undefined) delete process.env.CROW_MODELS_JSON; else process.env.CROW_MODELS_JSON = prevModels;
    inst.cleanup();
    rmSync(dir, { recursive: true, force: true });
  }
});