import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The keyed verifier for `crow_instances.auth_token_hash` (family `peer:inbound`) is installed by
// loading its host module: `validateInstanceToken` calls the seam (servers/shared/peer-bearer.js)
// so the bot-reachable instance-registry never imports the key. A process without the
// implementation refuses every peer rather than falling back to sha256(token).
import "../servers/gateway/peer-inbound-token.js";
import { validateInstanceToken } from "../servers/gateway/instance-registry.js";
import { ensureKey, macToken } from "../servers/shared/token-mac.js";
import { rmScratch } from "./helpers/safe-rm.js";

const TOKEN = "ab".repeat(32); // 64 hex chars
// This file's own home, so the verifier it seeds is minted under a key nobody else touches. A
// fixture seeded with the PRE-conversion form would only pass while the family happened to be
// unconverted in whatever home the process inherited.
const HOME = mkdtempSync(join(tmpdir(), "crow-instance-token-"));
mkdirSync(join(HOME, "data"), { recursive: true });
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = join(HOME, "data");
delete process.env.CROW_DB_PATH;
ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });

test.after(() => rmScratch(HOME));

const HASH = macToken("peer:inbound", TOKEN);
const PEER_ROW = { id: "peer-1", name: "host-b", status: "active", trusted: 1, auth_token_hash: HASH };

// A db stub whose execute returns the supplied rows, recording the args used.
function dbReturning(rows, sink) {
  return {
    execute: async (stmt) => {
      if (sink) sink.push(stmt);
      return { rows };
    },
    close() {},
  };
}

// A db stub whose execute always throws (simulates a wedged/corrupt connection).
function dbThrowing(message = "database disk image is malformed") {
  return {
    execute: async () => { throw new Error(message); },
    close() {},
  };
}

test("returns the matching instance for a known token", async () => {
  const sink = [];
  const row = await validateInstanceToken(dbReturning([PEER_ROW], sink), TOKEN);
  assert.equal(row.id, "peer-1");
  // Queried by a STORED FORM of the bearer (`h1.…` under this key, plus the legacy sha256), never
  // by the raw token itself. (A key-less install also runs its once-per-process era scan first, so
  // the lookup is not necessarily the first statement.)
  const lookup = sink.find((stmt) => /auth_token_hash IN /.test(stmt.sql));
  assert.ok(lookup, "the row is looked up by its stored verifier");
  assert.equal(lookup.args.includes(HASH), true, "the keyed verifier is one of the lookup values");
  assert.equal(lookup.args.includes(TOKEN), false, "the raw bearer is never a lookup value");
  assert.equal(lookup.args.length, 2, "exactly the two stored forms are tried, in one query");
});

test("returns null for an unknown token (no DB error)", async () => {
  const row = await validateInstanceToken(dbReturning([]), TOKEN);
  assert.equal(row, null);
});

test("returns null for an empty token without touching the DB", async () => {
  let touched = false;
  const db = { execute: async () => { touched = true; return { rows: [] }; }, close() {} };
  assert.equal(await validateInstanceToken(db, ""), null);
  assert.equal(touched, false);
});

test("REGRESSION: a DB error retries on a fresh client instead of silently rejecting the peer", async () => {
  // The captured client throws (the 2026-06-14 corruption signature); the fresh
  // client reads the intact crow_instances pages and authenticates the peer.
  let freshMade = 0;
  const freshClient = () => { freshMade++; return dbReturning([PEER_ROW]); };
  const row = await validateInstanceToken(dbThrowing(), TOKEN, { _freshClient: freshClient });
  assert.equal(freshMade, 1, "should have opened exactly one fresh client");
  assert.equal(row.id, "peer-1", "valid peer must NOT be rejected just because the captured client errored");
});

test("returns null only when BOTH the captured and the fresh client fail", async () => {
  let freshMade = 0, freshClosed = 0;
  const freshClient = () => {
    freshMade++;
    return { execute: async () => { throw new Error("still corrupt"); }, close() { freshClosed++; } };
  };
  const row = await validateInstanceToken(dbThrowing(), TOKEN, { _freshClient: freshClient });
  assert.equal(row, null);
  assert.equal(freshMade, 1);
  assert.equal(freshClosed, 1, "the fresh client must be closed even on failure");
});
