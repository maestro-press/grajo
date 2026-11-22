/**
 * The reports door's plumbing (no tool code lives here): its path-scoped token, the middleware branch
 * that scopes it to /reports/(mcp|sse|messages), and the signed `reports` actor kind.
 *
 * What is pinned: the token rotates at boot and opens its own mount only (never another family's, and
 * no other family's token opens it), req.localTokenAuth carries scope "reports" on exactly the three
 * transport paths, and the `reports` MAC domain shares nothing with the artifacts, sharing or generic
 * "bot" kinds in either direction.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  REPORTS_TOKEN, ensureReportsToken, SHARING_BOT_TOKEN, SECRETS_TOKEN, validateBoardToken, validatePhoneToken,
  localTokenAuthMiddleware,
} from "../servers/gateway/local-token.js";
import {
  initGatewayActorKey, _resetActorKeyForTest, signReportsActor, verifyReportsActorSig,
  signArtifactsActor, verifyArtifactsActorSig, signSharingActor, verifySharingActorSig, signActor, verifyActorSig,
} from "../scripts/pi-bots/actor-sig.mjs";

const HOME = mkdtempSync(join(tmpdir(), "crow-reports-plumbing-"));
const SAVED_HOME = process.env.CROW_HOME;
process.env.CROW_HOME = HOME;

after(() => {
  if (SAVED_HOME === undefined) delete process.env.CROW_HOME; else process.env.CROW_HOME = SAVED_HOME;
  _resetActorKeyForTest();
  rmSync(HOME, { recursive: true, force: true });
});

const TOKEN_FILE = join(HOME, "secrets", "reports-token");
const sha256 = (t) => createHash("sha256").update(t).digest("hex");

/**
 * The two settings shapes a path-scoped rotation and its read use, held in memory. A real crow.db is
 * not needed for the question this file asks (which key holds which hash), and the per-instance
 * override is the row the rotation writes.
 */
function fakeDb(seed = {}) {
  const overrides = new Map(Object.entries(seed));
  return {
    overrides,
    async execute({ sql, args }) {
      if (/^\s*SELECT value FROM dashboard_settings_overrides/i.test(sql)) {
        return { rows: overrides.has(args[0]) ? [{ value: overrides.get(args[0]) }] : [] };
      }
      if (/^\s*INSERT INTO dashboard_settings_overrides/i.test(sql)) {
        overrides.set(args[0], args[2]);
        return { rows: [] };
      }
      if (/^\s*DELETE FROM dashboard_settings_overrides/i.test(sql)) {
        overrides.delete(args[0]);
        return { rows: [] };
      }
      return { rows: [] };
    },
    close() {},
  };
}

// ---- 1. the token ----

test("REPORTS_TOKEN rotates: a fresh value every time, 0600 under secrets/, and only the current one validates", async () => {
  const db = fakeDb();
  const first = await REPORTS_TOKEN.rotate(db);
  assert.match(first, /^[0-9a-f]{64}$/);
  assert.equal(readFileSync(TOKEN_FILE, "utf8").trim(), first, "the raw value is what the bot catalog reads");
  assert.equal(statSync(TOKEN_FILE).mode & 0o777, 0o600);
  assert.equal(statSync(join(HOME, "secrets")).mode & 0o777, 0o700);
  assert.equal(await REPORTS_TOKEN.validate(db, first), true);

  // A second rotation is a different token, and the previous one stops validating.
  const second = await REPORTS_TOKEN.rotate(db);
  assert.notEqual(second, first);
  assert.equal(await REPORTS_TOKEN.validate(db, first), false);
  assert.equal(await REPORTS_TOKEN.validate(db, second), true);
  for (const junk of ["", "f".repeat(64), first.toUpperCase() + "x", "Bearer " + second, null, undefined, 42]) {
    assert.equal(await REPORTS_TOKEN.validate(db, junk), false, String(junk));
  }
});

test("ensureReportsToken is the boot-mint name for that same rotation", async () => {
  const db = fakeDb();
  const before = readFileSync(TOKEN_FILE, "utf8").trim();
  assert.deepEqual(await ensureReportsToken(db), { minted: true });
  const after = readFileSync(TOKEN_FILE, "utf8").trim();
  assert.notEqual(after, before, "a rotation, never a no-op");
  assert.equal(await REPORTS_TOKEN.validate(db, after), true);
});

test("no family's token opens another family: the reports key and hash are its own", async () => {
  const db = fakeDb();
  const reports = await REPORTS_TOKEN.rotate(db);
  const sharing = "a".repeat(64);
  const secrets = "b".repeat(64);
  const board = "c".repeat(64);
  const phone = "d".repeat(64);
  db.overrides.set("mcp_sharing_bot_token_hash", sha256(sharing));
  db.overrides.set("mcp_secrets_token_hash", sha256(secrets));
  db.overrides.set("mcp_board_token_hash", sha256(board));
  db.overrides.set("mcp_phone_token_hash", sha256(phone));

  for (const t of [sharing, secrets, board, phone]) {
    assert.equal(await REPORTS_TOKEN.validate(db, t), false, "a foreign token never validates as reports");
  }
  assert.equal(await SHARING_BOT_TOKEN.validate(db, reports), false);
  assert.equal(await SECRETS_TOKEN.validate(db, reports), false);
  assert.equal(await validateBoardToken(db, reports), false);
  assert.equal(await validatePhoneToken(db, reports), false);
  assert.equal(await REPORTS_TOKEN.validate(db, reports), true, "and its own does");
});

// ---- 2. the middleware branch ----

/** The settings registry reads `{rows:[{value}]}`; a known key answers with its hash. */
function hashDb(tokens) {
  return {
    async execute({ sql, args }) {
      const key = args && args[0];
      if (!Object.prototype.hasOwnProperty.call(tokens, key)) return { rows: [] };
      if (!/^\s*SELECT value FROM dashboard_settings_overrides/i.test(sql)) return { rows: [] };
      return { rows: [{ value: tokens[key] }] };
    },
  };
}

const FULL = "test-full-local-token";
const REPORTS = "test-reports-token";
const OTHER = { sharing: "test-sharing-bot-token", secrets: "test-secrets-token", board: "test-board-token", phone: "test-phone-token" };
const db = hashDb({
  mcp_local_token_hash: sha256(FULL),
  mcp_reports_token_hash: sha256(REPORTS),
  mcp_sharing_bot_token_hash: sha256(OTHER.sharing),
  mcp_secrets_token_hash: sha256(OTHER.secrets),
  mcp_board_token_hash: sha256(OTHER.board),
  mcp_phone_token_hash: sha256(OTHER.phone),
});

const fakeReq = ({ path, token, remoteAddress = "127.0.0.1" }) => ({
  socket: { remoteAddress }, path, headers: token ? { authorization: "Bearer " + token } : {},
});

async function run(req) {
  let nexted = 0;
  await localTokenAuthMiddleware(db)(req, {}, () => { nexted++; });
  assert.equal(nexted, 1, "the middleware always yields, never hard-rejects");
  return req;
}

test("the middleware scopes the reports token to /reports/(mcp|sse|messages) and to nothing else", async () => {
  for (const path of ["/reports/mcp", "/reports/sse", "/reports/messages"]) {
    const req = await run(fakeReq({ path, token: REPORTS }));
    assert.deepEqual(req.localTokenAuth, { token: "local-mcp", scope: "reports" }, path);
  }
  for (const path of ["/reports", "/reports/api", "/reports/mcpx", "/reports/mcp/x", "/memory/mcp", "/board/mcp", "/sharing-bot/mcp"]) {
    const req = await run(fakeReq({ path, token: REPORTS }));
    assert.equal(req.localTokenAuth, undefined, path);
  }
});

test("the reports mount admits no other family's token, and the reports token opens no other mount", async () => {
  for (const [name, token] of Object.entries(OTHER)) {
    const req = await run(fakeReq({ path: "/reports/mcp", token }));
    assert.equal(req.localTokenAuth, undefined, name);
  }
  for (const path of ["/sharing-bot/mcp", "/secrets/mcp", "/board/mcp", "/phone/mcp"]) {
    const req = await run(fakeReq({ path, token: REPORTS }));
    assert.equal(req.localTokenAuth, undefined, path);
  }
});

// ---- 3. the actor kind ----

test("signReportsActor / verifyReportsActorSig round trip on the exact tuple", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const tuple = { botId: "hank", threadId: "perch-1", gatewayType: "perch" };
  const sig = signReportsActor(tuple);
  assert.match(sig, /^[0-9a-f]{64}$/);
  assert.equal(verifyReportsActorSig({ ...tuple, sig }), true);
  assert.equal(verifyReportsActorSig({ ...tuple, botId: "otto", sig }), false, "wrong bot");
  assert.equal(verifyReportsActorSig({ ...tuple, threadId: "perch-2", sig }), false, "wrong thread");
  assert.equal(verifyReportsActorSig({ ...tuple, gatewayType: "gmail", sig }), false, "wrong gateway");
  assert.equal(verifyReportsActorSig({ ...tuple, sig: undefined }), false);
  assert.equal(verifyReportsActorSig({ ...tuple, sig: "not-hex" }), false);
  assert.equal(signReportsActor({ threadId: "perch-1" }), null, "no bot id, no signature");
});

test("no key in this process: nothing is signed and nothing verifies", () => {
  _resetActorKeyForTest();
  try {
    assert.equal(signReportsActor({ botId: "hank", threadId: "perch-1" }), null);
    assert.equal(verifyReportsActorSig({ botId: "hank", threadId: "perch-1", sig: "a".repeat(64) }), false);
  } finally {
    initGatewayActorKey();
  }
});

test("a reports signature replays as no other kind, and no other kind's replays as reports", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const tuple = { botId: "hank", threadId: "perch-1", gatewayType: "perch" };
  const reports = signReportsActor(tuple);
  const artifacts = signArtifactsActor(tuple);
  const sharing = signSharingActor(tuple);
  const phone = signActor({ kind: "bot", ...tuple });
  assert.ok(reports && artifacts && sharing && phone);
  assert.equal(new Set([reports, artifacts, sharing, phone]).size, 4, "four distinct MAC domains");

  // Reports outward: no other verifier accepts it.
  assert.equal(verifyArtifactsActorSig({ ...tuple, sig: reports }), false);
  assert.equal(verifySharingActorSig({ ...tuple, sig: reports }), false);
  assert.equal(verifyActorSig({ kind: "bot", ...tuple, sig: reports }), false);

  // Every other kind inward: the reports verifier accepts none of them.
  for (const sig of [artifacts, sharing, phone]) {
    assert.equal(verifyReportsActorSig({ ...tuple, sig }), false);
  }
  assert.equal(verifyReportsActorSig({ ...tuple, sig: reports }), true, "its own still verifies");
});