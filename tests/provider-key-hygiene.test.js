// tests/provider-key-hygiene.test.js — no key VALUE escapes (design §5).
//
// Sealing changes where the secret lives, not what may be printed. This file
// plants a distinctive plaintext value and asserts it appears in none of the
// places a failure usually leaks it: a log line, a notification, a thrown
// error, a conflict snapshot, or a JSON serialisation of a provider object —
// and that the stored cell is carried only as a NON-enumerable `storedKey`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { upsertProvider, listProvidersAll, syncProvidersFromModelsJson } from "../servers/shared/providers-db.js";
import { providerRowToObject } from "../servers/shared/provider-row.js";
import { stripConflictSnapshot } from "../servers/sharing/instance-sync.js";
import { clearProviderKeyring } from "../servers/shared/provider-keyring.js";
import { installTestKeyring, makeInstance } from "./fixtures/provider-keys.mjs";

const KEY = "demo-hygiene-canary-value-9f3a2b1c";
const BASE = "https://api.example.com/v1";

/** Capture everything a run writes to the console. */
async function captureConsole(fn) {
  const lines = [];
  const saved = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(saved)) console[k] = (...args) => { lines.push(args.map(String).join(" ")); };
  try { return { out: await fn(), lines }; } finally { Object.assign(console, saved); }
}

const leaks = (haystack) => {
  const text = Array.isArray(haystack) ? haystack.join("\n") : String(haystack);
  return text.includes(KEY) || text.includes("pk1:");
};

test("a key never reaches a log line: the seal write, the read, and the no-keyring skip", async () => {
  const inst = makeInstance("provider-key-hygiene-");
  const { uninstall } = installTestKeyring();
  try {
    const { lines } = await captureConsole(async () => {
      await upsertProvider(inst.db, { id: "p1", baseUrl: BASE, apiKey: KEY, host: "cloud", models: [], providerType: "openai" });
      await listProvidersAll(inst.db);
      const row = providerRowToObject((await inst.db.execute({ sql: "SELECT * FROM providers WHERE id = 'p1'" })).rows[0]);
      assert.equal(row.apiKey, KEY, "the value exists in memory, which is the point of the test");
    });
    assert.equal(leaks(lines), false, `a log line carried the key or an envelope:\n${lines.join("\n")}`);
  } finally {
    uninstall();
    inst.cleanup();
  }
});

test("a key never reaches a thrown error (the seal refusal names no value)", async () => {
  const inst = makeInstance("provider-key-hygiene-err-");
  try {
    clearProviderKeyring();
    const err = await upsertProvider(inst.db, { id: "p2", baseUrl: BASE, apiKey: KEY, host: "cloud", models: [], providerType: "openai" })
      .then(() => null, (e) => e);
    assert.ok(err, "the write was refused");
    assert.equal(err.code, "PROVIDER_KEY_SEAL_UNAVAILABLE");
    assert.equal(String(err.message).includes(KEY), false, "the message names no value");
    assert.equal(String(err.stack).includes(KEY), false, "the stack carries no value");
  } finally {
    inst.cleanup();
  }
});

test("a key never reaches the reconcile's degraded log line, and the row is not written", async () => {
  const dir = mkdtempSync(join(tmpdir(), "provider-key-hygiene-models-"));
  const prev = process.env.CROW_MODELS_JSON;
  const inst = makeInstance("provider-key-hygiene-reconcile-");
  const modelsJson = join(dir, "models.json");
  writeFileSync(modelsJson, JSON.stringify({
    providers: { p3: { baseUrl: BASE, apiKey: KEY, models: [{ id: "m" }] } },
  }));
  process.env.CROW_MODELS_JSON = modelsJson;
  try {
    clearProviderKeyring();
    const { lines } = await captureConsole(() => syncProvidersFromModelsJson(inst.db, { force: true }));
    const skipLine = lines.find((l) => l.includes("a saved provider key cannot be sealed in this process"));
    assert.ok(skipLine, `the fixed skip line was logged:\n${lines.join("\n")}`);
    assert.equal(leaks(lines), false, "no value or envelope in the log");
    const { rows } = await inst.db.execute({ sql: "SELECT api_key FROM providers" });
    assert.deepEqual(rows, [], "nothing was written in the clear");
  } finally {
    if (prev === undefined) delete process.env.CROW_MODELS_JSON; else process.env.CROW_MODELS_JSON = prev;
    inst.cleanup();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a conflict snapshot never carries the cell, and a provider object serialises without it", async () => {
  const inst = makeInstance("provider-key-hygiene-json-");
  const { uninstall } = installTestKeyring();
  try {
    await upsertProvider(inst.db, { id: "p4", baseUrl: BASE, apiKey: KEY, host: "cloud", models: [], providerType: "openai" });
    const raw = (await inst.db.execute({ sql: "SELECT * FROM providers WHERE id = 'p4'" })).rows[0];
    const cell = raw.api_key;
    assert.equal(typeof cell, "string");

    // A conflict snapshot built from a raw row (what an old build stored).
    const stripped = stripConflictSnapshot("providers", JSON.stringify(raw));
    assert.equal(stripped.includes("api_key"), false, "the local-only column is gone");
    assert.equal(leaks(stripped), false, "and the value with it");

    const row = providerRowToObject(raw);
    const json = JSON.stringify(row);
    assert.equal(json.includes("pk1:"), false, "no envelope in a serialised provider");
    assert.equal(json.includes("storedKey"), false, "the stored cell is not an enumerable field");
    assert.equal(row.storedKey, cell, "but a writer can still ask for it by name");
    assert.equal(Object.getOwnPropertyDescriptor(row, "storedKey").enumerable, false);

    // The fingerprint identities are fingerprints, never the key.
    assert.match(row.keyFp, /^[0-9a-f]{16}$/);
    assert.equal(row.keyFp.includes(KEY), false);
  } finally {
    uninstall();
    inst.cleanup();
  }
});