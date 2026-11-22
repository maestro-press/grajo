/**
 * Containment PR 6: a relayed socket never authenticates as the operator.
 *
 * A contained bot has crow.db bound read-write (Phase 1), so it can write
 * mcp_local_token_hash and then present its own value as the operator's full
 * local token on /board/mcp — a door. localTokenAuthMiddleware therefore skips
 * validateLocalToken entirely for a socket carrying the relay mark
 * (127.0.77.1); only the path-scoped board, phone, artifacts and secrets
 * tokens may authenticate a relayed request.
 *
 * The middleware is driven directly with fake req objects; the DB is a stub
 * whose settings make one full token and one board token valid.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { localTokenAuthMiddleware } from "../servers/gateway/local-token.js";
import { RELAY_SOURCE_V4 } from "../servers/shared/bot-doors.js";

const FULL = "test-full-local-token";
const BOARD = "test-board-token";
const SECRETS = "test-secrets-token";
const SHARING_BOT = "test-sharing-bot-token";
const REPORTS = "test-reports-token";
const sha256 = (t) => createHash("sha256").update(t).digest("hex");

/** The settings registry reads `{rows:[{value}]}`; a known key answers with its hash. */
const HASHES = {
  mcp_local_token_hash: sha256(FULL),
  mcp_board_token_hash: sha256(BOARD),
  mcp_secrets_token_hash: sha256(SECRETS),
  mcp_sharing_bot_token_hash: sha256(SHARING_BOT),
  mcp_reports_token_hash: sha256(REPORTS),
};
const db = {
  execute: async ({ sql, args }) => {
    const key = args && args[0];
    const known = Object.prototype.hasOwnProperty.call(HASHES, key);
    if (!known) return { rows: [] };
    // The per-instance override lookup comes first; the same value is fine.
    return { rows: [{ value: HASHES[key] }] };
  },
};

const RELAY = RELAY_SOURCE_V4;
const LOOPBACK = "127.0.0.1";

function fakeReq({ remoteAddress, path, token }) {
  return {
    socket: { remoteAddress },
    path,
    headers: token ? { authorization: "Bearer " + token } : {},
  };
}

async function run(req) {
  let nexted = 0;
  await localTokenAuthMiddleware(db)(req, {}, () => { nexted++; });
  assert.equal(nexted, 1, "the middleware always yields, never hard-rejects");
  return req;
}

test("the full local token on a relayed socket does not authenticate (crow.db is bot-writable)", async () => {
  const req = await run(fakeReq({ remoteAddress: RELAY, path: "/board/mcp", token: FULL }));
  assert.equal(req.localTokenAuth, undefined, "no local-token auth from a relayed socket");
  assert.equal(req.auth, undefined, "and no synthesized operator auth");
});

test("the path-scoped board token still authenticates a relayed socket", async () => {
  const req = await run(fakeReq({ remoteAddress: RELAY, path: "/board/mcp", token: BOARD }));
  assert.deepEqual(req.localTokenAuth, { token: "local-mcp", scope: "board" });
});

test("the full local token from a plain loopback socket keeps its full access", async () => {
  const req = await run(fakeReq({ remoteAddress: LOOPBACK, path: "/board/mcp", token: FULL }));
  assert.deepEqual(req.localTokenAuth, { token: "local-mcp" }, "the operator's own token, no scope");
  const v4mapped = await run(fakeReq({ remoteAddress: "::ffff:" + RELAY, path: "/board/mcp", token: FULL }));
  assert.equal(v4mapped.localTokenAuth, undefined, "the mark is recognised in its v4-mapped spelling too");
});

test("a board token is still useless off the board paths", async () => {
  const req = await run(fakeReq({ remoteAddress: RELAY, path: "/memory/mcp", token: BOARD }));
  assert.equal(req.localTokenAuth, undefined, "the board token stays path-scoped");
});

test("the path-scoped secrets token authenticates a relayed /secrets/mcp socket, and the full local token never does", async () => {
  const req = await run(fakeReq({ remoteAddress: RELAY, path: "/secrets/mcp", token: SECRETS }));
  assert.deepEqual(req.localTokenAuth, { token: "local-mcp", scope: "secrets" });
  const full = await run(fakeReq({ remoteAddress: RELAY, path: "/secrets/mcp", token: FULL }));
  assert.equal(full.localTokenAuth, undefined, "crow.db is bot-writable: the full local token is never the operator on a relayed socket");
  const off = await run(fakeReq({ remoteAddress: RELAY, path: "/memory/mcp", token: SECRETS }));
  assert.equal(off.localTokenAuth, undefined, "the secrets token opens nothing but its own mount");
});

test("the path-scoped sharing-bot token authenticates a relayed /sharing-bot/mcp socket, and nothing else", async () => {
  // The bot sharing door is called FROM a contained bot, so a relayed socket must be able to present
  // its own token — and only on its own mount.
  const req = await run(fakeReq({ remoteAddress: RELAY, path: "/sharing-bot/mcp", token: SHARING_BOT }));
  assert.deepEqual(req.localTokenAuth, { token: "local-mcp", scope: "sharing-bot" });
  const full = await run(fakeReq({ remoteAddress: RELAY, path: "/sharing-bot/mcp", token: FULL }));
  assert.equal(full.localTokenAuth, undefined, "the full local token is never the operator on a relayed socket");
  for (const path of ["/sharing/mcp", "/memory/mcp", "/board/mcp"]) {
    const elsewhere = await run(fakeReq({ remoteAddress: RELAY, path, token: SHARING_BOT }));
    assert.equal(elsewhere.localTokenAuth, undefined, `the sharing-bot token opens nothing but its own mount (${path})`);
  }
});

test("the path-scoped reports token authenticates a relayed /reports/mcp socket, and nothing else", async () => {
  // The reports door is called FROM a contained bot too, so a relayed socket must be able to present
  // its own token — and only on its own mount.
  const req = await run(fakeReq({ remoteAddress: RELAY, path: "/reports/mcp", token: REPORTS }));
  assert.deepEqual(req.localTokenAuth, { token: "local-mcp", scope: "reports" });
  const full = await run(fakeReq({ remoteAddress: RELAY, path: "/reports/mcp", token: FULL }));
  assert.equal(full.localTokenAuth, undefined, "the full local token is never the operator on a relayed socket");
  for (const path of ["/reports/sse", "/reports/messages"]) {
    const transport = await run(fakeReq({ remoteAddress: RELAY, path, token: REPORTS }));
    assert.deepEqual(transport.localTokenAuth, { token: "local-mcp", scope: "reports" }, path);
  }
  for (const path of ["/reports/mcp-x", "/reports", "/memory/mcp", "/board/mcp", "/sharing-bot/mcp"]) {
    const elsewhere = await run(fakeReq({ remoteAddress: RELAY, path, token: REPORTS }));
    assert.equal(elsewhere.localTokenAuth, undefined, `the reports token opens nothing but its own mount (${path})`);
  }
  const crossed = await run(fakeReq({ remoteAddress: RELAY, path: "/reports/mcp", token: SHARING_BOT }));
  assert.equal(crossed.localTokenAuth, undefined, "and no other family's token opens it");
});