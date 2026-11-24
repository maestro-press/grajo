// tests/provider-key-readers.test.js — every reader sends the OPENED key (design §1.2).
//
//   - the model door forwards the plaintext (and never the stored envelope);
//   - an unreadable key answers 503 PROVIDER_KEY_UNREADABLE with ZERO upstream
//     requests, never a "none" fallback, and raises the existing key-needed bell;
//   - the door's addressing (models/door-resolve.js) and pi's models.json entries
//     refuse an unreadable row instead of sending it unauthenticated;
//   - presence answers (provider-key-need) and the pick-check stamp are unchanged
//     by sealing.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Readable } from "node:stream";
import { createHmac } from "node:crypto";
import express from "express";

import { upsertProvider, listProvidersAll, loadProvidersFromDb } from "../servers/shared/providers-db.js";
import { resolveDoorTarget } from "../servers/gateway/models/door-resolve.js";
import { providerRowToObject } from "../servers/shared/provider-row.js";
import { parseStoredKey, providerKeyFp, sealedConsentFingerprint, CONSENT_FP_PREFIX } from "../servers/shared/provider-key-shape.js";
import { PROVIDER_KEY_UNREADABLE } from "../servers/shared/provider-keyring.js";
import { noticeProviderKeyNeeded, providerKeyNoticeSource, KEY_ENTERED_METADATA_KEY } from "../servers/shared/provider-key-need.js";
import { checkStamp } from "../servers/shared/pick-checks.js";
import { buildManagedEntries } from "../servers/shared/pi-models-sync.js";
import { installTestKeyring, makeInstance } from "./fixtures/provider-keys.mjs";

const KEY = "demo-readers-planted-key-0001";
const ROW = "sealprov";
const ROW_BAD = "sealprov-bad";
const BASE = "http://fake.example.test:8099/v1";

// ONE instance for both router tests: the router's own `db()` is a module-level
// singleton, so a second scratch home in the same process would leave it pointed
// at the first (deleted) one.
let inst = null;
function instance() {
  if (!inst) inst = makeInstance("provider-key-readers-");
  return inst;
}

after(() => { try { inst?.cleanup(); } catch { /* already cleaned */ } });

async function routerApp(deps) {
  const { default: llmRouterRouter } = await import("../servers/gateway/routes/llm-router.js");
  const router = llmRouterRouter({
    acquireFn: async () => true,
    probeReadyFn: async () => true,
    warmFn: async () => true,
    loadProvidersFn: () => ({ providers: {} }),
    remoteAddressFn: () => "127.0.0.1",
    doorAuthFn: async () => false,
    resolveVoiceKeysFn: async () => ({ fast: `${ROW}/m1`, escalate: `${ROW}/m1` }),
    // A name target so the forward is NOT this box (an own-host forward drops the
    // Authorization header by design, and this test is about what a NON-own
    // forward carries). Callback-shaped, like dns.lookup.
    lookupFn: (_host, _options, cb) => cb(null, [{ address: "203.0.113.10", family: 4 }]),
    ...deps,
  });
  const app = express();
  app.use(router);
  const srv = http.createServer(app);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { srv, url: `http://127.0.0.1:${srv.address().port}` };
}

function chat(url) {
  return fetch(`${url}/llm/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "m1", messages: [{ role: "user", content: "hi" }] }),
  });
}

test("the model door forwards the OPENED plaintext, never the stored envelope", async () => {
  const home = instance();
  installTestKeyring();
  await upsertProvider(home.db, {
    id: ROW, baseUrl: BASE, apiKey: KEY, host: "cloud", models: [{ id: "m1" }],
    disabled: false, providerType: "openai",
  });
  const cell = (await home.db.execute({ sql: "SELECT api_key FROM providers WHERE id = ?", args: [ROW] })).rows[0].api_key;
  assert.equal(parseStoredKey(cell).kind, "envelope");

  const seen = [];
  const { resolveDirectKeyFrom } = await import("../servers/gateway/routes/llm-router.js");
  const { srv, url } = await routerApp({
    resolveKeyFn: resolveDirectKeyFrom(home.db),
    requestFn: async (target, opts) => {
      seen.push({ target, headers: opts.headers });
      return { status: 200, headers: { "content-type": "application/json" }, stream: Readable.from([JSON.stringify({ ok: true })]) };
    },
  });
  try {
    const res = await chat(url);
    const text = await res.text();
    assert.equal(res.status, 200, text);
    assert.equal(seen.length, 1, "exactly one upstream request");
    assert.equal(seen[0].headers.Authorization, `Bearer ${KEY}`, "the forward carries the plaintext key");
    assert.equal(JSON.stringify(seen[0].headers).includes("pk1:"), false, "the envelope never leaves the box");
  } finally {
    srv.close();
  }
});

test("an unreadable key: 503, zero upstream requests, and the key-needed bell (once, no body)", async () => {
  const home = instance();
  installTestKeyring();
  await upsertProvider(home.db, {
    id: ROW_BAD, baseUrl: BASE, apiKey: KEY, host: "cloud", models: [{ id: "m1" }],
    disabled: false, providerType: "openai",
  });
  // Corrupt the stored cell: present, but nothing can open it.
  await home.db.execute({ sql: "UPDATE providers SET api_key = 'pk1:corrupt' WHERE id = ?", args: [ROW_BAD] });

  let upstreamHits = 0;
  const { resolveDirectKeyFrom } = await import("../servers/gateway/routes/llm-router.js");
  const { srv, url } = await routerApp({
    resolveKeyFn: async (key) => {
      const cfg = await resolveDirectKeyFrom(home.db)(key);
      return { ...cfg, model: "m1" };
    },
    resolveVoiceKeysFn: async () => ({ fast: `${ROW_BAD}/m1`, escalate: `${ROW_BAD}/m1` }),
    requestFn: async () => { upstreamHits++; throw new Error("must not be called"); },
  });
  try {
    const res = await chat(url);
    const text = await res.text();
    assert.equal(res.status, 503, text);
    const body = JSON.parse(text);
    assert.equal(body.error.code, PROVIDER_KEY_UNREADABLE);
    assert.equal(body.error.provider, ROW_BAD);
    assert.equal(upstreamHits, 0, "nothing was sent upstream");

    // The bell: raised once, by name, with no body.
    const source = providerKeyNoticeSource(ROW_BAD);
    let rows = [];
    for (let i = 0; i < 60; i++) {
      ({ rows } = await home.db.execute({
        sql: "SELECT title, body, action_url FROM notifications WHERE source = ?",
        args: [source],
      }));
      if (rows.length) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(rows.length, 1, "one notice for this provider id");
    assert.match(rows[0].title, /needs an API key on this device/);
    assert.equal(rows[0].body, null, "no body: the answer is the same either way");
    assert.equal(rows[0].action_url, "/dashboard/settings?section=llm&tab=providers");

    // A second refusal does not ring again.
    assert.equal((await chat(url)).status, 503);
    await new Promise((r) => setTimeout(r, 150));
    ({ rows } = await home.db.execute({
      sql: "SELECT id FROM notifications WHERE source = ?",
      args: [source],
    }));
    assert.equal(rows.length, 1, "still one notice");
  } finally {
    srv.close();
  }
});

test("door addressing: a sealed row forwards the plaintext; an unreadable row is a 503 with no request", async () => {
  const inst = makeInstance("provider-key-readers-door-");
  installTestKeyring();
  await upsertProvider(inst.db, {
    id: ROW, baseUrl: "http://127.0.0.1:9/v1", apiKey: KEY, host: "local",
    bundleId: "some-bundle", models: [{ id: "m1" }], disabled: false, providerType: "openai-compat",
  });
  try {
    const cfg = await loadProvidersFromDb(inst.db);
    const ok = resolveDoorTarget({ providers: cfg.providers, providerHeader: ROW, model: "m1" });
    assert.equal(ok.kind, "forward");
    assert.equal(ok.apiKey, KEY, "the door target carries the opened key");
    assert.equal(ok.keyState, "sealed");

    await inst.db.execute({ sql: "UPDATE providers SET api_key = 'pk1:corrupt' WHERE id = ?", args: [ROW] });
    const cfg2 = await loadProvidersFromDb(inst.db);
    const bad = resolveDoorTarget({ providers: cfg2.providers, providerHeader: ROW, model: "m1" });
    assert.equal(bad.kind, "error");
    assert.equal(bad.status, 503);
    assert.equal(bad.code, PROVIDER_KEY_UNREADABLE);
  } finally {
    inst.cleanup();
  }
});

test("pi models.json: a sealed row's entry carries the `none` sentinel through the door, never the opened key", async () => {
  const inst = makeInstance("provider-key-readers-pi-");
  installTestKeyring();
  await upsertProvider(inst.db, {
    id: ROW, baseUrl: "http://127.0.0.1:9/v1", apiKey: KEY, host: "local",
    models: [{ id: "m1" }], disabled: false, providerType: "openai",
  });
  try {
    const rows = await listProvidersAll(inst.db);
    const entries = buildManagedEntries(rows, { cloudAllow: [ROW], doorBase: "http://127.0.0.1:3001/llm/v1" });
    assert.ok(entries[ROW], "the row has an entry");
    // H1: pi's models.json is read by pi and by every bot, so an OPENED sealed key
    // never lands in it. A keyed row is pointed at the provider door (round 2, L3),
    // which carries the real key.
    assert.equal(entries[ROW].apiKey, "none", "the sentinel, not the opened key");
    assert.equal(entries[ROW].baseUrl, "http://127.0.0.1:3001/llm/p/sealprov/v1", "the door carries the key");
    assert.equal(JSON.stringify(entries).includes(KEY), false, "the plaintext is nowhere in the entries");

    await inst.db.execute({ sql: "UPDATE providers SET api_key = 'pk1:corrupt' WHERE id = ?", args: [ROW] });
    const badEntries = buildManagedEntries(await listProvidersAll(inst.db), { cloudAllow: [ROW], doorBase: "http://127.0.0.1:3001/llm/v1", log: () => {} });
    assert.equal(badEntries[ROW], undefined, "an unreadable row is not handed to pi at all");
  } finally {
    inst.cleanup();
  }
});

// ─── M1: every adapter path refuses a key it cannot read ───────────────

test("providerKeyState fails closed: a row that HOLDS a key with no plaintext is 'unreadable', never 'none'", async () => {
  const { providerKeyState, providerKeyUnreadable } = await import("../servers/shared/provider-row.js");
  // The shape an older parsed object has (keyPresent/apiKey, no keyState).
  assert.equal(providerKeyState({ keyPresent: true, apiKey: null }), "unreadable");
  assert.equal(providerKeyUnreadable({ keyPresent: true, apiKey: null }), true);
  assert.equal(providerKeyState({ keyPresent: true, apiKey: "" }), "unreadable");
  assert.equal(providerKeyState({ keyPresent: true, apiKey: "sk-opened" }), "sealed");
  assert.equal(providerKeyUnreadable({ keyPresent: true, apiKey: "sk-opened", keyState: "sealed" }), false);
  assert.equal(providerKeyState({ keyPresent: false, apiKey: null }), "none");
  assert.equal(providerKeyUnreadable({ keyPresent: false, apiKey: null }), false, "a keyless local row is dialled as before");
  assert.equal(providerKeyState({ keyState: "unreadable", keyPresent: true, apiKey: null }), "unreadable");
  assert.equal(providerKeyUnreadable(null), false);
});

test("createAdapterFromProfile refuses an unreadable key, and a sealed one with no plaintext, before any request", async () => {
  const inst = makeInstance("provider-key-readers-adapter-");
  const { uninstall } = installTestKeyring();
  try {
    await upsertProvider(inst.db, {
      id: "adapter-bad", baseUrl: BASE, apiKey: KEY, host: "cloud", models: [{ id: "m1" }],
      disabled: false, providerType: "openai",
    });
    await inst.db.execute({ sql: "UPDATE providers SET api_key = 'pk1:corrupt' WHERE id = 'adapter-bad'" });
    const { createAdapterFromProfile } = await import("../servers/gateway/ai/provider.js");
    const refused = await createAdapterFromProfile({ provider_id: "adapter-bad", model_id: "m1" }, null, inst.db)
      .then(() => null, (err) => err);
    assert.ok(refused, "no adapter was created");
    assert.equal(refused.code, PROVIDER_KEY_UNREADABLE);

    // A well-sealed row in a process with NO keyring: keyState "sealed" with no
    // plaintext is the same refusal — never a keyless request to the server.
    uninstall();
    const sealedErr = await createAdapterFromProfile({ provider_id: "adapter-bad", model_id: "m1" }, null, inst.db)
      .then(() => null, (err) => err);
    assert.equal(sealedErr?.code, PROVIDER_KEY_UNREADABLE);
  } finally {
    uninstall();
    inst.cleanup();
  }
});

test("presence: a sealed key answers has-key (no notice) without being opened", async () => {
  const inst = makeInstance("provider-key-readers-need-");
  installTestKeyring();
  await upsertProvider(inst.db, {
    id: ROW, baseUrl: "https://api.openai.com/v1", apiKey: KEY, host: "cloud",
    models: [{ id: "m1" }], disabled: false, providerType: "openai",
  });
  try {
    // A process with NO keyring: it cannot open the cell, and still knows there
    // is a key here, so it never nags the operator for one.
    const { clearProviderKeyring } = await import("../servers/shared/provider-keyring.js");
    clearProviderKeyring();
    assert.equal(await noticeProviderKeyNeeded(inst.db, ROW), "has-key");
    const row = providerRowToObject((await inst.db.execute({ sql: "SELECT * FROM providers WHERE id = ?", args: [ROW] })).rows[0]);
    assert.equal(row.keyState, "sealed");
    assert.equal(row.keyPresent, true);
  } finally {
    inst.cleanup();
  }
});

test("checkStamp: the fingerprint is the same value before and after sealing", async () => {
  const plain = { baseUrl: "https://api.openai.com/v1", apiKey: KEY };
  const sealedRow = { baseUrl: "https://api.openai.com/v1", apiKey: null, keyFp: providerKeyFp(KEY), keyPresent: true, keyState: "sealed" };
  assert.equal(checkStamp(plain).fp, providerKeyFp(KEY));
  assert.equal(checkStamp(sealedRow).fp, checkStamp(plain).fp, "one key, one identity, sealed or not");
  assert.equal(checkStamp({ baseUrl: plain.baseUrl, apiKey: null }).fp, "", "no key, no fingerprint");
});

test("consent fingerprints use the sealed form (fp1:) and agree with a plaintext expectation", () => {
  const salt = "a".repeat(64);
  const fp16 = providerKeyFp(KEY);
  assert.equal(sealedConsentFingerprint(salt, fp16), sealedConsentFingerprint(salt, fp16));
  assert.equal(CONSENT_FP_PREFIX, "fp1:");
  const legacy = createHmac("sha256", Buffer.from(salt, "hex")).update(KEY).digest("hex").slice(0, 16);
  assert.notEqual(sealedConsentFingerprint(salt, fp16), legacy, "the two forms never collide");
  assert.ok(KEY_ENTERED_METADATA_KEY);
});