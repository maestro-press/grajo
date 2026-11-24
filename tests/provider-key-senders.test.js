// tests/provider-key-senders.test.js — a no-keyring sender stops BEFORE its request.
//
// servers/memory/{embeddings,rerank}.js run in their own process (the memory
// server), which never installs a keyring. A row whose key is stored but cannot
// be produced here must not be sent unauthenticated and must not be sent with the
// stored cell: both senders answer PROVIDER_KEY_NOT_IN_PROCESS (a sealed cell) or
// PROVIDER_KEY_UNREADABLE (a cell nothing can open) before any request, and the
// callers keep degrading as they already did.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { upsertProvider } from "../servers/shared/providers-db.js";
import { clearProviderKeyring, PROVIDER_KEY_NOT_IN_PROCESS, PROVIDER_KEY_UNREADABLE } from "../servers/shared/provider-keyring.js";
import { embedText } from "../servers/memory/embeddings.js";
import { rerank } from "../servers/memory/rerank.js";
import { installTestKeyring, makeInstance } from "./fixtures/provider-keys.mjs";

const KEY = "demo-senders-planted-key-0001";
const ROW = "prov-embed";
const RERANK_ROW = "prov-rerank";

async function counter() {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push(req.headers.authorization || null);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [{ embedding: [1, 0] }] }));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { srv, hits, url: `http://127.0.0.1:${srv.address().port}/v1` };
}

async function seed(url) {
  const server = await counter();
  const inst = makeInstance("provider-key-senders-");
  installTestKeyring();
  await upsertProvider(inst.db, {
    id: ROW, baseUrl: server.url, apiKey: KEY, host: "local", models: [{ id: "m-embed", task: "embedding" }],
    disabled: false, providerType: "openai-compat",
  });
  await upsertProvider(inst.db, {
    id: RERANK_ROW, baseUrl: server.url, apiKey: KEY, host: "local", models: [{ id: "m-rerank", task: "rerank" }],
    disabled: false, providerType: "openai-compat",
  });
  // The memory server has NO keyring.
  clearProviderKeyring();
  return { inst, server };
}

test("embeddings: a sealed key stops the sender before any request", async () => {
  const { inst, server } = await seed();
  try {
    await assert.rejects(
      () => embedText("hello", { providerName: ROW }),
      (err) => err.code === PROVIDER_KEY_NOT_IN_PROCESS,
    );
    assert.deepEqual(server.hits, [], "no request left this process");
  } finally {
    server.srv.close();
    inst.cleanup();
  }
});

test("embeddings: a cell nothing can open answers PROVIDER_KEY_UNREADABLE, still no request", async () => {
  const { inst, server } = await seed();
  try {
    await inst.db.execute({ sql: "UPDATE providers SET api_key = 'pk1:corrupt' WHERE id = ?", args: [ROW] });
    await assert.rejects(
      () => embedText("hello", { providerName: ROW }),
      (err) => err.code === PROVIDER_KEY_UNREADABLE,
    );
    assert.deepEqual(server.hits, []);
  } finally {
    server.srv.close();
    inst.cleanup();
  }
});

test("rerank: a sealed key degrades to identity order without a request", async () => {
  const { inst, server } = await seed();
  try {
    const candidates = [{ id: 1, text: "a" }, { id: 2, text: "b" }];
    const out = await rerank("q", candidates, { providerName: RERANK_ROW, topK: 2 });
    assert.deepEqual(out.map((c) => c.id), [1, 2], "the candidates come back in their own order");
    assert.equal(out.some((c) => "relevance" in c), false);
    assert.deepEqual(server.hits, [], "no request left this process");
  } finally {
    server.srv.close();
    inst.cleanup();
  }
});

test("a plaintext cell still works in the memory process (nothing to seal was ever written)", async () => {
  const server = await counter();
  const inst = makeInstance("provider-key-senders-plain-");
  try {
    // A row written by an older build: a legacy plaintext cell, readable here.
    await inst.db.execute({
      sql: "INSERT INTO providers (id, base_url, api_key, host, models, disabled, lamport_ts, instance_id) VALUES (?,?,?,?,?,0,1,?)",
      args: [ROW, server.url, KEY, "local", JSON.stringify([{ id: "m-embed", task: "embedding" }]), "inst"],
    });
    clearProviderKeyring();
    await embedText("hello", { providerName: ROW });
    // The request leaves (the own-host adapter guard strips the credential by
    // ITS own rule — that is not what this test is about); what matters is that a
    // legacy plain cell still resolves and no stored cell is ever sent.
    assert.equal(server.hits.length, 1, "the request left this process");
    assert.equal(server.hits.every((h) => !String(h).includes("pk1:")), true, "never the stored cell");
  } finally {
    server.srv.close();
    inst.cleanup();
  }
});