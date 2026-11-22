/**
 * The Coinbase engine client: the MAC it signs with, the results it shapes and
 * the secrets it keeps out of them.  Every call here answers through a local
 * fake fetch; nothing opens a socket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bodySha256Hex, macHeaders, macSignature } from "../bundles/coinbase/server/mac.js";
import {
  createEngineClient,
  readEngineToken,
  readInstallToken,
} from "../bundles/coinbase/server/engine-client.js";

const VECTORS = JSON.parse(
  readFileSync(
    new URL("../bundles/coinbase/engine/tests/fixtures/mac-vectors.json", import.meta.url),
    "utf8",
  ),
);

const TOKEN = "test-engine-token-0123456789abcdef";
const OWNER_KEY = "owner-signing-key-0123456789abcdef";
const INSTALL_KEY = "install-signing-key-0123456789abcdef";
const APPROVE_SECRET = "approve-secret-0123456789abcdef";
const PRIVATE_KEY = "private-key-material-0123456789abcdef0123456789abcdef";

function respond(status, body, headers = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers,
    text: async () => text,
  };
}

function fakeFetch(responder) {
  const calls = [];
  async function impl(url, init) {
    calls.push({ url, init });
    return responder(url, init, calls.length);
  }
  impl.calls = calls;
  return impl;
}

function signatureOf(call, pathWithQuery, key) {
  const headers = call.init.headers;
  return macSignature({
    key,
    method: call.init.method,
    pathWithQuery,
    ts: headers["X-Crow-Timestamp"],
    nonce: headers["X-Crow-Nonce"],
    body: call.init.body === undefined ? "" : call.init.body,
  });
}

// ---------------------------------------------------------------- the MAC

test("mac_vectors", () => {
  assert.ok(Array.isArray(VECTORS.vectors));
  assert.ok(VECTORS.vectors.length > 0);
  for (const vector of VECTORS.vectors) {
    const digest = bodySha256Hex(vector.body);
    assert.equal(digest, vector.body_sha256, `${vector.name}: body hash`);
    const text = [vector.method, vector.path_with_query, vector.ts, vector.nonce, digest].join("\n");
    assert.equal(text, vector.string_to_sign, `${vector.name}: string to sign`);
    const signature = macSignature({
      key: VECTORS.key,
      method: vector.method,
      pathWithQuery: vector.path_with_query,
      ts: vector.ts,
      nonce: vector.nonce,
      body: vector.body,
    });
    assert.equal(signature, vector.signature, `${vector.name}: signature`);
  }
});

test("mac_headers_shape", () => {
  const headers = macHeaders({ key: VECTORS.key, method: "post", pathWithQuery: "/lease", body: "" });
  const stamp = headers["X-Crow-Timestamp"];
  assert.ok(Number.isInteger(Number(stamp)), stamp);
  assert.equal(String(Math.floor(Number(stamp))), stamp);
  assert.match(headers["X-Crow-Nonce"], /^[A-Za-z0-9_-]{16,128}$/);
  assert.equal(headers["X-Crow-Nonce"].length, 24);
  assert.match(headers["X-Crow-Signature"], /^[0-9a-f]{64}$/);

  const pinned = macHeaders({
    key: VECTORS.key,
    method: "POST",
    pathWithQuery: "/lease",
    body: "",
    ts: "1700000000",
    nonce: "abcdefghijklmnop0001",
  });
  assert.equal(pinned["X-Crow-Signature"], VECTORS.vectors[0].signature);

  assert.throws(
    () => macSignature({ key: "", method: "POST", pathWithQuery: "/lease", ts: "1", nonce: "n", body: "" }),
    (error) => {
      assert.equal(String(error.message).includes(VECTORS.key), false);
      return true;
    },
  );
  assert.throws(() => macHeaders({ key: null, method: "POST", pathWithQuery: "/lease" }));
});

// ---------------------------------------------------------------- transport failures

test("timeout_is_engine_unreachable", async () => {
  const fetchImpl = (url, init) =>
    new Promise((resolve, reject) => {
      const fail = () => reject(new Error("the request took too long"));
      if (init.signal.aborted) fail();
      else init.signal.addEventListener("abort", fail, { once: true });
    });
  const client = createEngineClient({ token: TOKEN, fetchImpl, timeoutMs: 30 });
  const result = await client.status();
  assert.deepEqual(result, {
    ok: false,
    status: 0,
    code: "ENGINE_UNREACHABLE",
    message: "The trading engine is not responding",
  });
});

test("credentials_push_waits_thirty_seconds", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const aborted = [];
  const hanging = (url, init) =>
    new Promise((resolve, reject) => {
      init.signal.addEventListener(
        "abort",
        () => {
          aborted.push(url);
          reject(new Error("the request took too long"));
        },
        { once: true },
      );
    });
  const drain = () => new Promise((resolve) => setImmediate(resolve));

  const pushClient = createEngineClient({
    token: TOKEN,
    fetchImpl: hanging,
    now: () => 1_700_000_000_000,
    secretProvider: async () => INSTALL_KEY,
  });
  const pushing = pushClient.pushCredentials(
    { key_name: "organizations/a/apiKeys/b", private_key: PRIVATE_KEY, approve_secret: APPROVE_SECRET },
    { keyKind: "install" },
  );
  await drain();
  t.mock.timers.tick(29_000);
  assert.equal(aborted.length, 0, "the credentials push is still waiting at 29 s");
  t.mock.timers.tick(2_000);
  await drain();
  assert.deepEqual(aborted, ["http://127.0.0.1:3062/credentials"]);
  assert.deepEqual(await pushing, {
    ok: false,
    status: 0,
    code: "ENGINE_UNREACHABLE",
    message: "The trading engine is not responding",
  });

  // Every other call keeps the ten second default.
  const plainClient = createEngineClient({ token: TOKEN, fetchImpl: hanging });
  const waiting = plainClient.status();
  await drain();
  t.mock.timers.tick(9_000);
  assert.equal(aborted.length, 1, "the ordinary call is still waiting at 9 s");
  t.mock.timers.tick(2_000);
  await drain();
  assert.equal(aborted.length, 2);
  assert.equal((await waiting).code, "ENGINE_UNREACHABLE");
});

test("network_error_is_unreachable", async () => {
  const client = createEngineClient({
    token: TOKEN,
    fetchImpl: async () => {
      throw new Error(`connect failed while sending ${TOKEN}`);
    },
  });
  const result = await client.balances();
  assert.equal(result.ok, false);
  assert.equal(result.status, 0);
  assert.equal(result.code, "ENGINE_UNREACHABLE");
  assert.equal(result.message, "The trading engine is not responding");
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});

// ---------------------------------------------------------------- results and refusals

test("401_is_engine_auth", async () => {
  const fetchImpl = fakeFetch(() => respond(401, { detail: "unauthorized" }));
  const client = createEngineClient({ token: TOKEN, fetchImpl });
  const result = await client.status();
  assert.deepEqual(result, {
    ok: false,
    status: 401,
    code: "ENGINE_AUTH",
    message: "The engine did not accept Crow's token",
  });
});

test("error_shapes", async () => {
  let next = null;
  const fetchImpl = fakeFetch(() => next);
  const client = createEngineClient({ token: TOKEN, fetchImpl });

  next = respond(403, { code: "APPROVAL_INVALID", message: "the approval was refused" });
  let result = await client.status();
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
  assert.equal(result.code, "APPROVAL_INVALID");
  assert.equal(result.message, "the approval was refused");

  next = respond(409, { detail: "ORDER_TOO_LARGE" });
  result = await client.status();
  assert.equal(result.code, "ORDER_TOO_LARGE");
  assert.equal(result.message, "ORDER_TOO_LARGE");

  next = respond(409, { detail: "ORDER_TOO_LARGE: over the cap" });
  result = await client.status();
  assert.equal(result.code, "ORDER_TOO_LARGE");
  assert.equal(result.message, "over the cap");

  next = respond(422, { code: "INVALID", fields: ["product", "size"] });
  result = await client.status();
  assert.equal(result.code, "INVALID");
  assert.deepEqual(result.fields, ["product", "size"]);

  next = respond(429, { detail: "RATE_LIMITED" }, { "Retry-After": "7" });
  result = await client.status();
  assert.equal(result.code, "RATE_LIMITED");
  assert.equal(result.retryAfterS, 7);

  next = respond(429, { code: "LOCKOUT" });
  result = await client.status();
  assert.equal(result.code, "LOCKOUT");
  assert.equal(result.retryAfterS, 60);

  next = respond(500, "<html>this is not json</html>");
  result = await client.status();
  assert.equal(result.ok, false);
  assert.equal(result.status, 500);
  assert.equal(result.code, "HTTP_500");
  assert.equal(typeof result.message, "string");
  assert.equal(result.message.includes("this is not json"), false);
});

test("test_failure_keeps_halted_flag", async () => {
  let next = null;
  const fetchImpl = fakeFetch(() => next);
  const client = createEngineClient({ token: TOKEN, fetchImpl });

  // Only a body that says halted:true means trading stopped while orders may still rest.
  next = respond(502, { detail: "x", halted: true });
  const partial = await client.kill();
  assert.equal(partial.ok, false);
  assert.equal(partial.status, 502);
  assert.equal(partial.halted, true);

  // A 500 that never said so keeps no flag at all.
  next = respond(500, { detail: "x" });
  const failed = await client.kill();
  assert.equal(failed.ok, false);
  assert.equal(failed.status, 500);
  assert.equal(failed.halted, undefined);

  // Neither does a refused token.
  next = respond(401, { detail: "unauthorized" });
  const unauthorized = await client.kill();
  assert.equal(unauthorized.ok, false);
  assert.equal(unauthorized.status, 401);
  assert.equal(unauthorized.halted, undefined);

  // The flag never brings a secret with it.
  next = respond(502, { detail: `the sweep failed for ${TOKEN}`, halted: true });
  const leaked = await client.kill();
  assert.equal(leaked.halted, true);
  assert.equal(JSON.stringify(leaked).includes(TOKEN), false);
});

test("ok_returns_data", async () => {
  const payload = { bots: [], total: 2 };
  const fetchImpl = fakeFetch(() => respond(200, payload));
  const client = createEngineClient({ token: TOKEN, fetchImpl });
  const result = await client.bots();
  assert.deepEqual(result, { ok: true, data: payload });
});

test("health_503_body_is_an_answer", async () => {
  const stale = {
    ok: false,
    live_enabled: true,
    heartbeat_age_s: 121,
    credentials: "ready",
    pinned: true,
  };
  const fetchImpl = fakeFetch(() => respond(503, stale));
  const client = createEngineClient({ token: TOKEN, fetchImpl });
  assert.deepEqual(await client.health(), { ok: true, data: stale });

  // A 503 with no boolean `ok` in it is still a failure.
  const textOnly = fakeFetch(() => respond(503, "<html>the engine is restarting</html>"));
  const refused = await createEngineClient({ token: TOKEN, fetchImpl: textOnly }).health();
  assert.equal(refused.ok, false);
  assert.equal(refused.status, 503);

  // And another route keeps a 503 as a failure, body or no body.
  const onStatus = fakeFetch(() => respond(503, stale));
  const status = await createEngineClient({ token: TOKEN, fetchImpl: onStatus }).status();
  assert.equal(status.ok, false);
  assert.equal(status.status, 503);
  assert.equal(status.code, "HTTP_503");
});

// ---------------------------------------------------------------- fail closed

test("unstringifiable_body_fails_closed_without_a_fetch", async () => {
  const fetchImpl = fakeFetch(() => respond(200, {}));
  const client = createEngineClient({ token: TOKEN, fetchImpl });

  const circular = { product: "BTC-USDC" };
  circular.self = circular;
  const bodies = [circular, { size: 10n }];

  for (const body of bodies) {
    const result = await client.createBot(body);
    assert.equal(result.ok, false);
    assert.equal(result.status, 0);
    assert.equal(result.code, "INVALID");
    assert.equal(typeof result.message, "string");
    assert.ok(result.message.length > 0);
  }
  assert.equal(fetchImpl.calls.length, 0);
});

test("response_without_a_numeric_status_is_unreachable", async () => {
  const fetchImpl = fakeFetch(() => ({ ok: true, headers: {}, text: async () => JSON.stringify({ bots: [] }) }));
  const client = createEngineClient({ token: TOKEN, fetchImpl });
  assert.deepEqual(await client.bots(), {
    ok: false,
    status: 0,
    code: "ENGINE_UNREACHABLE",
    message: "The trading engine is not responding",
  });
});

test("ids_in_a_path_are_checked_before_any_fetch", async () => {
  const fetchImpl = fakeFetch(() => respond(200, {}));
  const client = createEngineClient({
    token: TOKEN,
    fetchImpl,
    secretProvider: async (kind) => (kind === "install" ? INSTALL_KEY : OWNER_KEY),
  });
  const refused = { ok: false, status: 0, code: "INVALID", message: "That id is not valid" };
  const calls = [
    (id) => client.botFills(id),
    (id) => client.botPause(id),
    (id) => client.botStop(id),
    (id) => client.botResume(id, { acknowledge_rebase: true }),
    (id) => client.botRecenter(id, { center: "1" }),
    (id) => client.setMode(id, { mode: "dry" }),
    (id) => client.aiReject(id),
    (id) => client.aiCancel(id),
    (id) => client.approve(id, "hash"),
  ];
  const badIds = ["../x", "a/b", "", ".", "..", "a b", "a?b", "a#b", "a%2Fb", "a\\b"];
  for (const [index, call] of calls.entries()) {
    for (const id of badIds) {
      assert.deepEqual(await call(id), refused, `call ${index}, id ${JSON.stringify(id)}`);
    }
  }
  assert.equal(fetchImpl.calls.length, 0, "no refused id ever reached the engine");

  // A legal id still goes through.
  await client.botFills("bot-1.2_a:b");
  assert.equal(fetchImpl.calls.length, 1);
  assert.ok(fetchImpl.calls[0].url.startsWith("http://127.0.0.1:3062/bots/bot-1.2"));
  assert.ok(fetchImpl.calls[0].url.endsWith("/fills"));
});

// ---------------------------------------------------------------- redaction

test("no_secret_in_results", async () => {
  const cases = [
    {
      secrets: [TOKEN, APPROVE_SECRET, PRIVATE_KEY],
      message: `push owner ${TOKEN} ${APPROVE_SECRET} ${PRIVATE_KEY}`,
      run: (client) =>
        client.pushCredentials(
          { key_name: "organizations/a/apiKeys/b", private_key: PRIVATE_KEY, approve_secret: APPROVE_SECRET },
          { keyKind: "owner" },
        ),
    },
    {
      secrets: [TOKEN, INSTALL_KEY, PRIVATE_KEY, APPROVE_SECRET],
      message: `push install ${TOKEN} ${INSTALL_KEY} ${PRIVATE_KEY} ${APPROVE_SECRET}`,
      run: (client) =>
        client.pushCredentials(
          { key_name: "organizations/a/apiKeys/b", private_key: PRIVATE_KEY, approve_secret: APPROVE_SECRET },
          { keyKind: "install" },
        ),
    },
    {
      secrets: [TOKEN, INSTALL_KEY, PRIVATE_KEY],
      message: `check ${TOKEN} ${INSTALL_KEY} ${PRIVATE_KEY}`,
      run: (client) =>
        client.checkCredentials({ key_name: "organizations/a/apiKeys/b", private_key: PRIVATE_KEY }, { keyKind: "install" }),
    },
    {
      secrets: [TOKEN, OWNER_KEY],
      message: `mode ${TOKEN} ${OWNER_KEY}`,
      run: (client) => client.setMode("grid-1", { mode: "dry" }),
    },
    {
      secrets: [TOKEN, OWNER_KEY],
      message: `lease ${TOKEN} ${OWNER_KEY}`,
      run: (client) => client.lease("holder-1", { keyKind: "owner" }),
    },
  ];

  const fetchImpl = fakeFetch((url, init, count) =>
    respond(403, { code: "REFUSED", message: cases[count - 1].message }),
  );
  const client = createEngineClient({
    token: TOKEN,
    fetchImpl,
    secretProvider: async (kind) => (kind === "install" ? INSTALL_KEY : OWNER_KEY),
  });

  for (const [index, item] of cases.entries()) {
    const result = await item.run(client);
    assert.equal(result.ok, false, `case ${index}`);
    assert.equal(result.code, "REFUSED", `case ${index}`);
    assert.equal(result.message.includes("[hidden]"), true, `case ${index}`);
    const blob = JSON.stringify(result);
    for (const secret of item.secrets) {
      assert.equal(blob.includes(secret), false, `case ${index} leaks a known secret`);
    }
  }
});

// ---------------------------------------------------------------- signing

test("privileged_signed", async () => {
  const calls = fakeFetch(() => respond(200, { ok: true }));
  const client = createEngineClient({
    token: TOKEN,
    fetchImpl: calls,
    now: () => 1_700_000_000_000,
    secretProvider: async (kind) => (kind === "install" ? INSTALL_KEY : OWNER_KEY),
  });

  const modeBody = { mode: "dry", capital_quote: "10", capital_base: "0", acknowledge_live: false };
  assert.equal((await client.setMode("grid-1", modeBody)).ok, true);
  const modeCall = calls.calls[0];
  assert.equal(modeCall.url, "http://127.0.0.1:3062/bots/grid-1/mode");
  assert.equal(modeCall.init.method, "POST");
  assert.equal(modeCall.init.body, JSON.stringify(modeBody));
  assert.equal(modeCall.init.headers["X-Crow-Timestamp"], "1700000000");
  assert.equal(
    modeCall.init.headers["X-Crow-Signature"],
    signatureOf(modeCall, "/bots/grid-1/mode", OWNER_KEY),
  );

  const credentialsBody = {
    key_name: "organizations/a/apiKeys/b",
    private_key: PRIVATE_KEY,
    approve_secret: APPROVE_SECRET,
  };
  assert.equal((await client.pushCredentials(credentialsBody, { keyKind: "install" })).ok, true);
  const installCall = calls.calls[1];
  assert.equal(installCall.init.body, JSON.stringify(credentialsBody));
  assert.equal(
    installCall.init.headers["X-Crow-Signature"],
    signatureOf(installCall, "/credentials", INSTALL_KEY),
  );

  const ownerCalls = fakeFetch(() => respond(200, { ok: true }));
  const ownerClient = createEngineClient({
    token: TOKEN,
    fetchImpl: ownerCalls,
    now: () => 1_700_000_000_000,
  });
  assert.equal((await ownerClient.pushCredentials(credentialsBody, { keyKind: "owner" })).ok, true);
  const ownerCall = ownerCalls.calls[0];
  assert.equal(ownerCall.init.body, JSON.stringify(credentialsBody));
  assert.equal(
    ownerCall.init.headers["X-Crow-Signature"],
    signatureOf(ownerCall, "/credentials", APPROVE_SECRET),
  );
});

test("forget_credentials_signed", async () => {
  const calls = fakeFetch(() => respond(200, { state: "missing", pinned: false }));
  const client = createEngineClient({
    token: TOKEN,
    fetchImpl: calls,
    now: () => 1_700_000_000_000,
    secretProvider: async (kind) => (kind === "install" ? INSTALL_KEY : OWNER_KEY),
  });

  assert.deepEqual(await client.forgetCredentials(), {
    ok: true,
    data: { state: "missing", pinned: false },
  });
  assert.equal(calls.calls.length, 1);
  const call = calls.calls[0];
  assert.equal(call.url, "http://127.0.0.1:3062/credentials/forget");
  assert.equal(call.init.method, "POST");
  // No body at all: the MAC is over the empty string the engine reads.
  assert.equal(call.init.body, undefined);
  assert.equal(call.init.headers["Content-Type"], undefined);
  assert.equal(call.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(call.init.headers["X-Crow-Timestamp"], "1700000000");
  assert.equal(
    call.init.headers["X-Crow-Signature"],
    signatureOf(call, "/credentials/forget", OWNER_KEY),
  );

  // Without a secret provider there is no owner's key to sign with: refused
  // before any fetch, exactly as the disconnect is.
  const bareFetch = fakeFetch(() => respond(200, {}));
  const unkeyed = createEngineClient({ token: TOKEN, fetchImpl: bareFetch });
  assert.deepEqual(await unkeyed.forgetCredentials(), {
    ok: false,
    status: 0,
    code: "NOT_ALLOWED",
    message: "This client cannot make that change",
  });
  assert.equal(bareFetch.calls.length, 0);

  // A provider with no key is the not-connected answer, and no fetch either.
  const emptyFetch = fakeFetch(() => respond(200, {}));
  const keyless = createEngineClient({
    token: TOKEN,
    fetchImpl: emptyFetch,
    secretProvider: async () => null,
  });
  assert.deepEqual(await keyless.forgetCredentials(), {
    ok: false,
    status: 0,
    code: "NOT_CONNECTED",
    message: "Trading is not connected",
  });
  assert.equal(emptyFetch.calls.length, 0);

  // A refusal from the engine is shaped like any other privileged one, and the
  // owner's key never comes back in it.
  const refusedFetch = fakeFetch(() => respond(403, { detail: "APPROVAL_INVALID" }));
  const refused = await createEngineClient({
    token: TOKEN,
    fetchImpl: refusedFetch,
    secretProvider: async () => OWNER_KEY,
  }).forgetCredentials();
  assert.equal(refused.ok, false);
  assert.equal(refused.status, 403);
  assert.equal(refused.code, "APPROVAL_INVALID");
  assert.equal(JSON.stringify(refused).includes(OWNER_KEY), false);
});

test("not_allowed_without_secret_provider", async () => {
  const fetchImpl = fakeFetch(() => respond(200, {}));
  const client = createEngineClient({ token: TOKEN, fetchImpl });
  const calls = [
    () => client.setMode("b1", { mode: "dry" }),
    () => client.setSwitches({ live_enabled: true }),
    () => client.setCaps({ C: "1" }),
    () => client.clearHalt(),
    () => client.approve("p1", "hash"),
    () => client.clearCredentials(),
    () => client.lease("holder-1"),
    () => client.leaseCursor("holder-1", 3),
    () => client.checkCredentials({ key_name: "k", private_key: PRIVATE_KEY }),
    () =>
      client.pushCredentials(
        { key_name: "k", private_key: PRIVATE_KEY, approve_secret: APPROVE_SECRET },
        { keyKind: "install" },
      ),
  ];
  for (const call of calls) {
    assert.deepEqual(await call(), {
      ok: false,
      status: 0,
      code: "NOT_ALLOWED",
      message: "This client cannot make that change",
    });
  }
  assert.equal(fetchImpl.calls.length, 0);

  const result = await client.status();
  assert.equal(result.ok, true);
  assert.equal(fetchImpl.calls.length, 1);
});

test("not_connected_when_provider_has_no_key", async () => {
  const fetchImpl = fakeFetch(() => respond(200, {}));
  const expected = {
    ok: false,
    status: 0,
    code: "NOT_CONNECTED",
    message: "Trading is not connected",
  };
  const empty = createEngineClient({ token: TOKEN, fetchImpl, secretProvider: () => null });
  const calls = [
    () => empty.setMode("b1", { mode: "dry" }),
    () => empty.setSwitches({ live_enabled: true }),
    () => empty.setCaps({ C: "1" }),
    () => empty.clearHalt(),
    () => empty.approve("p1", "hash"),
    () => empty.clearCredentials(),
    () => empty.lease("holder-1"),
    () => empty.leaseCursor("holder-1", 3),
    () => empty.checkCredentials({ key_name: "k", private_key: PRIVATE_KEY }),
    () =>
      empty.pushCredentials(
        { key_name: "k", private_key: PRIVATE_KEY, approve_secret: APPROVE_SECRET },
        { keyKind: "install" },
      ),
  ];
  for (const call of calls) assert.deepEqual(await call(), expected);
  assert.equal(fetchImpl.calls.length, 0);

  const broken = createEngineClient({
    token: TOKEN,
    fetchImpl,
    secretProvider: async () => {
      throw new Error("the key store is locked");
    },
  });
  assert.deepEqual(await broken.setMode("b1", { mode: "dry" }), expected);
  assert.equal(fetchImpl.calls.length, 0);
});

// ---------------------------------------------------------------- headers

test("source_header_on_every_call", async () => {
  const fetchImpl = fakeFetch(() => respond(200, {}));
  const client = createEngineClient({
    token: TOKEN,
    fetchImpl,
    source: "mcp",
    secretProvider: async () => OWNER_KEY,
  });
  const calls = [
    () => client.health(),
    () => client.status(),
    () => client.events({ after: 5, limit: 10 }),
    () => client.balances(),
    () => client.caps(),
    () => client.bots(),
    () => client.botFills("bot-1"),
    () => client.pnl(),
    () => client.aiPreviews({ state: "pending" }),
    () => client.createBot({ id: "b1" }),
    () => client.botPause("b1"),
    () => client.botStop("b1"),
    () => client.kill(),
    () => client.aiPreview({ product: "BTC-USDC" }),
    () => client.aiReject("p1"),
    () => client.aiCancel("c1"),
    () => client.botResume("b1", { acknowledge_rebase: true }),
    () => client.botRecenter("b1", { center: "1" }),
    () => client.setMode("b1", { mode: "dry" }),
    () => client.setSwitches({ live_enabled: true }),
    () => client.setCaps({ C: "1" }),
    () => client.clearHalt(),
    () => client.approve("p1", "hash"),
    () => client.clearCredentials(),
    () => client.lease("holder-1"),
    () => client.leaseCursor("holder-1", 3),
    () => client.checkCredentials({ key_name: "k", private_key: PRIVATE_KEY }),
    () =>
      client.pushCredentials({
        key_name: "k",
        private_key: PRIVATE_KEY,
        approve_secret: APPROVE_SECRET,
      }),
  ];
  for (const call of calls) await call();
  assert.equal(fetchImpl.calls.length, calls.length);
  for (const call of fetchImpl.calls) {
    assert.equal(call.init.headers["X-Crow-Source"], "mcp");
  }
  assert.equal(fetchImpl.calls[2].url, "http://127.0.0.1:3062/events?after=5&limit=10");

  const quiet = fakeFetch(() => respond(200, {}));
  const bare = createEngineClient({ token: TOKEN, fetchImpl: quiet });
  await bare.status();
  assert.equal("X-Crow-Source" in quiet.calls[0].init.headers, false);
});

test("health_has_no_authorization", async () => {
  const fetchImpl = fakeFetch(() => respond(200, { ok: true }));
  const client = createEngineClient({ token: TOKEN, fetchImpl });
  assert.equal((await client.health()).ok, true);
  assert.equal("Authorization" in fetchImpl.calls[0].init.headers, false);
  await client.status();
  assert.equal(fetchImpl.calls[1].init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(fetchImpl.calls[1].init.headers["Content-Type"], undefined);
});

// ---------------------------------------------------------------- the price read

test("price_route", async () => {
  const fetchImpl = fakeFetch(() =>
    respond(200, { product: "BTC-USDC", price: "60000.5", ts: 1700000000.5 }),
  );
  const client = createEngineClient({ token: TOKEN, fetchImpl, source: "mcp" });
  assert.equal(typeof client.getPrice, "function", "the client has a price read");

  const result = await client.getPrice("BTC-USDC");
  assert.deepEqual(result, {
    ok: true,
    data: { product: "BTC-USDC", price: "60000.5", ts: 1700000000.5 },
  });
  assert.equal(fetchImpl.calls.length, 1);
  const call = fetchImpl.calls[0];
  assert.equal(call.url, "http://127.0.0.1:3062/price?product=BTC-USDC");
  assert.equal(call.init.method, "GET");
  assert.equal(call.init.body, undefined);
  assert.equal(call.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(call.init.headers["X-Crow-Source"], "mcp", "the price read is tagged for the audit trail");
  assert.equal("X-Crow-Signature" in call.init.headers, false, "a read is bearer only, never signed");
  assert.equal("X-Crow-Timestamp" in call.init.headers, false);

  // The engine's refusal is shaped like any other, its own sentence and all.
  const refusedFetch = fakeFetch(() =>
    respond(400, { detail: "That product is not one this engine trades." }),
  );
  const refused = await createEngineClient({ token: TOKEN, fetchImpl: refusedFetch }).getPrice("BTC-USDC");
  assert.equal(refused.ok, false);
  assert.equal(refused.status, 400);
  assert.equal(refused.message, "That product is not one this engine trades.");

  // An unpriceable product is a failure too, not an answer.
  const unpriceableFetch = fakeFetch(() => respond(503, { detail: "PRICE_UNAVAILABLE" }));
  const unpriceable = await createEngineClient({
    token: TOKEN,
    fetchImpl: unpriceableFetch,
  }).getPrice("BTC-USDC");
  assert.equal(unpriceable.ok, false);
  assert.equal(unpriceable.status, 503);

  // Anything that is not a trading pair is refused here, before any fetch.
  const badFetch = fakeFetch(() => respond(200, {}));
  const badClient = createEngineClient({ token: TOKEN, fetchImpl: badFetch });
  const answers = [];
  for (const product of ["BTC/USDC", "../x", ""]) {
    const answer = await badClient.getPrice(product);
    answers.push(answer);
    assert.equal(answer.ok, false, `product ${JSON.stringify(product)}`);
    assert.equal(answer.status, 0, `product ${JSON.stringify(product)}`);
    assert.equal(answer.code, "INVALID", `product ${JSON.stringify(product)}`);
    assert.equal(typeof answer.message, "string", `product ${JSON.stringify(product)}`);
    assert.ok(answer.message.length > 0, `product ${JSON.stringify(product)}`);
  }
  assert.equal(badFetch.calls.length, 0, "no refused product ever reached the engine");
  // One refusal for every shape of bad product, not one per shape.
  for (const answer of answers) assert.deepEqual(answer, answers[0]);
});

// ---------------------------------------------------------------- the token files

test("read_engine_token", () => {
  const home = mkdtempSync(join(tmpdir(), "crow-coinbase-engine-token-"));
  mkdirSync(join(home, "bundles", "coinbase"), { recursive: true });
  const envPath = join(home, "bundles", "coinbase", ".env");

  writeFileSync(
    envPath,
    ["# generated", "CROW_COINBASE_ENGINE_TOKEN=plain-engine-token-1", "CROW_COINBASE_LIVE=true", ""].join("\n"),
  );
  assert.equal(readEngineToken(home), "plain-engine-token-1");

  writeFileSync(envPath, 'export CROW_COINBASE_ENGINE_TOKEN="quoted-engine-token-2"\n');
  assert.equal(readEngineToken(home), "quoted-engine-token-2");

  writeFileSync(envPath, "CROW_COINBASE_ENGINE_TOKEN='single-quoted-token-3'\n");
  assert.equal(readEngineToken(home), "single-quoted-token-3");

  writeFileSync(envPath, "OTHER_SETTING=do-not-leak-me\n");
  assert.throws(
    () => readEngineToken(home),
    (error) => {
      assert.equal(error.message, "Coinbase engine token not found");
      assert.equal(error.message.includes("do-not-leak-me"), false);
      return true;
    },
  );

  const bare = mkdtempSync(join(tmpdir(), "crow-coinbase-engine-token-empty-"));
  assert.throws(() => readEngineToken(bare), /Coinbase engine token not found/);
});

test("read_install_token", () => {
  const home = mkdtempSync(join(tmpdir(), "crow-coinbase-install-token-"));
  mkdirSync(join(home, "coinbase", "install"), { recursive: true });
  const path = join(home, "coinbase", "install", "install_token");

  writeFileSync(path, "  install-token-value\n");
  assert.equal(readInstallToken(home), "install-token-value");

  writeFileSync(path, "   \n");
  assert.throws(() => readInstallToken(home), /Coinbase install token not found/);

  const bare = mkdtempSync(join(tmpdir(), "crow-coinbase-install-token-empty-"));
  assert.throws(() => readInstallToken(bare), /Coinbase install token not found/);
});

// ---------------------------------------------------------------- the open orders read

test("orders_route", async () => {
  const fetchImpl = fakeFetch(() => respond(200, []));
  const client = createEngineClient({ token: TOKEN, fetchImpl });
  assert.equal(typeof client.orders, "function", "the client has an open-orders read");

  const result = await client.orders({ book: "live" });
  assert.deepEqual(result, { ok: true, data: [] });
  assert.equal(fetchImpl.calls.length, 1);
  const call = fetchImpl.calls[0];
  assert.equal(call.url, "http://127.0.0.1:3062/orders?book=live");
  assert.equal(call.init.method, "GET");
  assert.equal(call.init.body, undefined);
  assert.equal(call.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal("X-Crow-Signature" in call.init.headers, false, "a read is bearer only, never signed");
  assert.equal("X-Crow-Timestamp" in call.init.headers, false);

  // No book named: the engine's own answer for every book.
  const all = fakeFetch(() => respond(200, []));
  await createEngineClient({ token: TOKEN, fetchImpl: all }).orders();
  assert.equal(all.calls[0].url, "http://127.0.0.1:3062/orders");

  // A book the engine does not have is refused here, before any fetch.
  const refused = { ok: false, status: 0, code: "INVALID", message: "That request body cannot be sent" };
  for (const book of ["paper", "both", "LIVE", "dry book"]) {
    const calls = fakeFetch(() => respond(200, []));
    const answer = await createEngineClient({ token: TOKEN, fetchImpl: calls }).orders({ book });
    assert.equal(answer.ok, false, `book ${JSON.stringify(book)}`);
    assert.equal(answer.status, 0, `book ${JSON.stringify(book)}`);
    assert.equal(answer.code, refused.code, `book ${JSON.stringify(book)}`);
    assert.equal(typeof answer.message, "string");
    assert.ok(answer.message.length > 0);
    assert.equal(calls.calls.length, 0, `book ${JSON.stringify(book)} never reached the engine`);
  }
});