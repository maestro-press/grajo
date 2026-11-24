/**
 * The engine client's three Tiingo calls, per the stock-prices contract: the two POSTs are
 * signed with the owner's MAC over their body, the DELETE is signed with the owner's MAC over
 * the empty string and carries no body at all, a client with no owner secret never reaches the
 * engine, and the pasted token is never repeated in a result.
 *
 * A local fake fetch answers every call; nothing opens a socket. The signature each request was
 * signed with is recomputed here from the request's own headers through the bundle's MAC
 * helpers, the same way the engine-client tests check a signature. Every token below is
 * synthetic and built at run time; the engine's answers echo one back on purpose, in a body, a
 * header, a code, a refused field and a thrown message, so redaction is what the test measures.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { macSignature } from "../bundles/coinbase/server/mac.js";
import { createEngineClient } from "../bundles/coinbase/server/engine-client.js";

const TOKEN = "test-engine-token-0123456789abcdef";
const OWNER_KEY = "owner-signing-key-0123456789abcdef";
// One synthetic Tiingo token, and the one the fake engine echoes back at Crow.
const TINGO = "t" + randomBytes(16).toString("hex");
const CANARY = "c" + randomBytes(16).toString("hex");

const UNREACHABLE = {
  ok: false,
  status: 0,
  code: "ENGINE_UNREACHABLE",
  message: "The trading engine is not responding",
};
const NOT_CONNECTED = {
  ok: false,
  status: 0,
  code: "NOT_CONNECTED",
  message: "Trading is not connected",
};
const NOT_ALLOWED = {
  ok: false,
  status: 0,
  code: "NOT_ALLOWED",
  message: "This client cannot make that change",
};

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

/** The signature the request itself carries, recomputed from its headers. */
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

/** A client whose owner secret is there, and which records every key kind it was asked for. */
function ownerClient(fetchImpl, kinds = []) {
  return createEngineClient({
    token: TOKEN,
    fetchImpl,
    now: () => 1_700_000_000_000,
    secretProvider: async (kind) => {
      kinds.push(kind);
      return OWNER_KEY;
    },
  });
}

// ---------------------------------------------------------------- the check

test("tiingo_check_is_an_owner_signed_post", async () => {
  const calls = fakeFetch(() => respond(200, { state: "ok" }));
  const kinds = [];
  const client = ownerClient(calls, kinds);

  assert.equal(typeof client.checkTiingo, "function", "the client has a Tiingo check");
  const result = await client.checkTiingo({ token: TINGO });
  assert.deepEqual(result, { ok: true, data: { state: "ok" } });
  assert.deepEqual(kinds, ["owner"], "the check is signed with the owner's key, never the install token");

  assert.equal(calls.calls.length, 1);
  const call = calls.calls[0];
  assert.equal(call.url, "http://127.0.0.1:3062/tiingo/check");
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.body, JSON.stringify({ token: TINGO }));
  assert.equal(call.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(call.init.headers["Content-Type"], "application/json");
  assert.equal(call.init.headers["X-Crow-Timestamp"], "1700000000");
  assert.equal(
    call.init.headers["X-Crow-Signature"],
    signatureOf(call, "/tiingo/check", OWNER_KEY),
    "the MAC covers the request the engine reads",
  );
  assert.equal(call.url.includes(TINGO), false, "the token never rides in the URL");

  // The engine's own refusal is a 200 body, and every field of it reaches the caller unchanged.
  const refusedCalls = fakeFetch(() =>
    respond(200, {
      state: "refused",
      code: "TOKEN_REJECTED",
      message: "Tiingo did not accept the token.",
    }),
  );
  const refused = await ownerClient(refusedCalls).checkTiingo({ token: TINGO });
  assert.deepEqual(refused, {
    ok: true,
    data: {
      state: "refused",
      code: "TOKEN_REJECTED",
      message: "Tiingo did not accept the token.",
    },
  });
});

// ---------------------------------------------------------------- the save

test("tiingo_set_is_an_owner_signed_post", async () => {
  const calls = fakeFetch(() => respond(200, { state: "connected" }));
  const kinds = [];
  const client = ownerClient(calls, kinds);

  assert.equal(typeof client.setTiingo, "function", "the client can store the token");
  const result = await client.setTiingo({ token: TINGO });
  assert.deepEqual(result, { ok: true, data: { state: "connected" } });
  assert.deepEqual(kinds, ["owner"]);

  assert.equal(calls.calls.length, 1);
  const call = calls.calls[0];
  assert.equal(call.url, "http://127.0.0.1:3062/tiingo");
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.body, JSON.stringify({ token: TINGO }));
  assert.equal(call.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(call.init.headers["X-Crow-Timestamp"], "1700000000");
  assert.equal(call.init.headers["X-Crow-Signature"], signatureOf(call, "/tiingo", OWNER_KEY));
  assert.equal(call.url.includes(TINGO), false, "the token never rides in the URL");

  // The engine's refusal keeps its own shape and its own sentence.
  const refusalCalls = fakeFetch(() =>
    respond(200, { state: "refused", code: "TOKEN_SHAPE", message: "The Tiingo token must be one line of letters and digits." }),
  );
  const refused = await ownerClient(refusalCalls).setTiingo({ token: TINGO });
  assert.equal(refused.ok, true, "the engine answers a refusal in a 200 body");
  assert.equal(refused.data.state, "refused");
  assert.equal(refused.data.code, "TOKEN_SHAPE");
});

// ---------------------------------------------------------------- the forget

test("tiingo_clear_is_an_owner_signed_delete_with_no_body", async () => {
  const calls = fakeFetch(() => respond(200, { state: "missing" }));
  const kinds = [];
  const client = ownerClient(calls, kinds);

  assert.equal(typeof client.clearTiingo, "function", "the client can forget the token");
  const result = await client.clearTiingo();
  assert.deepEqual(result, { ok: true, data: { state: "missing" } });
  assert.deepEqual(kinds, ["owner"]);

  assert.equal(calls.calls.length, 1);
  const call = calls.calls[0];
  assert.equal(call.url, "http://127.0.0.1:3062/tiingo");
  assert.equal(call.init.method, "DELETE");
  // No body at all: the MAC is over the empty string the engine reads, as for a Disconnect.
  assert.equal(call.init.body, undefined);
  assert.equal(call.init.headers["Content-Type"], undefined);
  assert.equal(call.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(call.init.headers["X-Crow-Timestamp"], "1700000000");
  assert.equal(call.init.headers["X-Crow-Signature"], signatureOf(call, "/tiingo", OWNER_KEY));
});

// ---------------------------------------------------------------- fail closed

test("tiingo_calls_never_reach_the_engine_without_a_key", async () => {
  const keylessCalls = fakeFetch(() => respond(200, {}));
  const keyless = createEngineClient({
    token: TOKEN,
    fetchImpl: keylessCalls,
    secretProvider: async () => null,
  });
  const keylessAnswers = [
    await keyless.checkTiingo({ token: TINGO }),
    await keyless.setTiingo({ token: TINGO }),
    await keyless.clearTiingo(),
  ];
  for (const answer of keylessAnswers) assert.deepEqual(answer, NOT_CONNECTED);
  assert.equal(keylessCalls.calls.length, 0, "no owner secret, no fetch");

  const bareCalls = fakeFetch(() => respond(200, {}));
  const bare = createEngineClient({ token: TOKEN, fetchImpl: bareCalls });
  const bareAnswers = [
    await bare.checkTiingo({ token: TINGO }),
    await bare.setTiingo({ token: TINGO }),
    await bare.clearTiingo(),
  ];
  for (const answer of bareAnswers) assert.deepEqual(answer, NOT_ALLOWED);
  assert.equal(bareCalls.calls.length, 0, "a client that cannot sign makes no call");

  const brokenCalls = fakeFetch(() => respond(200, {}));
  const broken = createEngineClient({
    token: TOKEN,
    fetchImpl: brokenCalls,
    secretProvider: async () => {
      throw new Error("the key store is locked");
    },
  });
  assert.deepEqual(await broken.setTiingo({ token: TINGO }), NOT_CONNECTED);
  assert.equal(brokenCalls.calls.length, 0);

  // A body JSON cannot carry is refused before any fetch, and the token never comes back in it.
  const circular = { token: TINGO };
  circular.self = circular;
  const invalidCalls = fakeFetch(() => respond(200, {}));
  const invalid = await ownerClient(invalidCalls).setTiingo(circular);
  assert.equal(invalid.ok, false);
  assert.equal(invalid.status, 0);
  assert.equal(invalid.code, "INVALID");
  assert.equal(JSON.stringify(invalid).includes(TINGO), false);
  assert.equal(invalidCalls.calls.length, 0);
});

// ---------------------------------------------------------------- redaction

test("the_token_is_never_in_a_result", async () => {
  const cases = [
    {
      name: "a 200 body that echoes it",
      answer: () => respond(200, { state: "connected", echo: CANARY, nested: { also: CANARY } }),
      run: (client) => client.setTiingo({ token: CANARY }),
      check: (result) => {
        assert.equal(result.ok, true);
        assert.equal(JSON.stringify(result).includes(CANARY), false, "a plain answer carries no token");
        assert.equal(result.data.echo, "[hidden]", "the echoed value is replaced, not dropped");
      },
    },
    {
      name: "a refusal body and a refusal header",
      answer: () => respond(403, { code: "REFUSED", message: `refused for ${CANARY}` }, { "x-echo": CANARY }),
      run: (client) => client.checkTiingo({ token: CANARY }),
      check: (result) => {
        assert.equal(result.ok, false);
        assert.equal(result.status, 403);
        assert.equal(result.code, "REFUSED");
        assert.equal(result.message.includes("[hidden]"), true, "the token is replaced in the sentence");
      },
    },
    {
      name: "the token used as the machine code and a refused field",
      answer: () => respond(422, { code: CANARY, fields: ["token", CANARY] }),
      run: (client) => client.checkTiingo({ token: CANARY }),
      check: (result) => {
        assert.equal(result.ok, false);
        assert.equal(result.code, "[hidden]");
        assert.deepEqual(result.fields, ["token", "[hidden]"]);
      },
    },
    {
      name: "a 429 whose Retry-After header echoes it",
      answer: () => respond(429, { detail: `RATE_LIMITED ${CANARY}` }, { "Retry-After": CANARY }),
      run: (client) => client.checkTiingo({ token: CANARY }),
      check: (result) => {
        assert.equal(result.ok, false);
        assert.equal(result.code, "RATE_LIMITED");
        assert.equal(result.retryAfterS, 60, "an unreadable header falls back, and nothing of it leaks");
      },
    },
    {
      name: "a thrown message that carries it",
      answer: () => {
        throw new Error(`connect failed while sending ${CANARY}`);
      },
      run: (client) => client.setTiingo({ token: CANARY }),
      check: (result) => {
        assert.deepEqual(result, UNREACHABLE);
      },
    },
    {
      name: "a response body that throws the token",
      answer: () => ({
        ok: true,
        status: 200,
        headers: {},
        text: async () => {
          throw new Error(`the body could not be read: ${CANARY}`);
        },
      }),
      run: (client) => client.setTiingo({ token: CANARY }),
      check: (result) => {
        assert.deepEqual(result, UNREACHABLE);
      },
    },
  ];

  for (const item of cases) {
    const calls = fakeFetch(item.answer);
    const guard = [];
    const client = createEngineClient({
      token: TOKEN,
      fetchImpl: calls,
      secretProvider: async (kind) => {
        guard.push(kind);
        // The owner secret is not the token: only a result that echoed the token can leak it.
        return OWNER_KEY;
      },
    });
    let result;
    let thrown = null;
    try {
      result = await item.run(client);
    } catch (err) {
      thrown = err;
    }
    assert.equal(thrown, null, `${item.name}: no call throws`);
    item.check(result);
    assert.equal(JSON.stringify(result).includes(CANARY), false, `${item.name}: the result carries no token`);
    assert.equal(
      JSON.stringify(result).includes(OWNER_KEY),
      false,
      `${item.name}: the result carries no owner key either`,
    );
  }
});