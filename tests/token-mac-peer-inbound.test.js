/**
 * §1b / §8 PR 4 of the keyed-token-hashes design: the PAIRED-INSTANCE bearer
 * (`crow_instances.auth_token_hash`) becomes a keyed verifier, and the re-pair proof (design D4)
 * keeps working across the conversion.
 *
 * The store used to hold `sha256(bearer)` — a plain function of the secret — so anything with
 * WRITE access to crow.db (a contained bot has it) could plant the value it computed and then
 * present the matching bearer as a trusted peer. The stored value is now an `h1.` MAC in the
 * family domain `peer:inbound` under `<CROW_HOME>/secrets/token-hmac.key`. This file pins, against
 * the real schema, store and validators:
 *
 *   - the pre-listen boot converts every legacy value, records the pre-conversion hash the re-pair
 *     proof is keyed by (D4), keeps the raw bearer working, and leaves a NULL (revoked) row alone;
 *   - a crash re-run converts ONLY its snapshot's rows: a post-snapshot legacy write is refused
 *     and alarmed, never laundered;
 *   - after conversion a planted `sha256(own token)` is refused by BOTH verifiers
 *     (`validateInstanceToken` and the cross-host signed-call middleware) and audited as
 *     `token_legacy_form`; a value copied from ANOTHER family never verifies (the family is inside
 *     the MAC); a bot INSERTing a trusted row with a legacy hash does not authenticate;
 *   - every writer stores the keyed MAC (the enroll route, the pairing CLI's write half,
 *     `rotateAuthToken`, the self row of `crow_register_instance`) and the peer's raw bearer still
 *     authenticates afterwards;
 *   - a re-pair proof still succeeds — against a converted target AND an unconverted one — and an
 *     `h1.` value is NEVER fed into `repairProofKey`;
 *   - `auth_token_hash` is never emitted by instance sync, and `inbound_bearer_sha256` is never a
 *     verifier anywhere.
 *
 * No user-visible text anywhere: the alarm is a console line plus an audit row.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer, request } from "node:http";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";

import { createDbClient } from "../servers/db.js";
import { readSetting } from "../servers/gateway/dashboard/settings/registry.js";
import {
  ensureKey, forgetTokenMacAlarms, forgetTokenMacKey, macToken, markConverted, readState, tokenMacKeyPath,
} from "../servers/shared/token-mac.js";
import {
  PEER_INBOUND_FAMILY, findPeerByBearer, forgetForcedPeerLegacyRefusal, forgetPeerInboundEvidence,
  isLegacyStored, legacyStoredHash, mintPeerInbound, verifyPeerBearer,
} from "../servers/gateway/peer-inbound-token.js";
import { repairProofSecret, instanceEnrollRouter } from "../servers/gateway/routes/instance-enroll.js";
import { PEER_ROLLBACK_PREFIX, runPeerTokenHmacBoot } from "../servers/gateway/boot/token-hmac-peers.js";
import { getPeerCreds, setPeerCreds } from "../servers/shared/peer-credentials.js";
import { generateEnrollOtc, repairProof, repairProofKey } from "../servers/shared/enroll-guard.js";
import { validateInstanceToken, rotateAuthToken } from "../servers/gateway/instance-registry.js";
import { crossHostVerifyMiddleware, signRequest, _resetNonceCache } from "../servers/shared/cross-host-auth.js";
import { trustedProxyList } from "../servers/shared/peer-class.js";
import { actAsServe } from "./fixtures/serve-peer.mjs";
import { EXCLUDED_COLUMNS, shouldSyncRow } from "../servers/sharing/instance-sync.js";
import { rmScratch } from "./helpers/safe-rm.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (value) => createHash("sha256").update(String(value)).digest("hex");
const H1 = /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/;
const OLD = "o".repeat(64);       // the pre-conversion bearer of the fixture peer
const SIGNING = "s".repeat(64);   // the pair's shared signing key
const NEW = "n".repeat(64);       // the bearer a re-pair presents

// The Serve stand-ins below run in this process, so this process plays tailscaled's uid.
actAsServe();

const roots = [];
after(() => {
  for (const root of roots) {
    try { rmScratch(root); } catch { /* best effort */ }
  }
});

const SAVED = {};
for (const key of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH", "CROW_PEER_TOKENS_PATH", "CROW_ENROLL_ENABLED", "CROW_ENROLL_OTC", "PORT", "CROW_PEER_GATEWAY_URL"]) {
  SAVED[key] = process.env[key];
}
after(() => {
  for (const [key, value] of Object.entries(SAVED)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/**
 * A fresh scratch instance: its own home, data dir and real schema (init-db), and every
 * in-process cache forgotten (the key, the alarm window, the era scan, the §M2 refusal).
 */
function scratch() {
  const home = mkdtempSync(join(tmpdir(), "crow-token-peer-"));
  roots.push(home);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true });
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
  // The gateway writes `<data dir>/instance-id` on its first boot; every read of it here is the
  // same file the real gateway and the enroll route use.
  writeFileSync(join(dataDir, "instance-id"), "0123456789abcdef0123456789abcdef", { mode: 0o600 });
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = join(dataDir, "crow.db");
  delete process.env.CROW_PEER_TOKENS_PATH;
  delete process.env.CROW_PEER_GATEWAY_URL;
  process.env.PORT = "3001";
  forgetTokenMacKey();
  forgetTokenMacAlarms();
  forgetPeerInboundEvidence();
  forgetForcedPeerLegacyRefusal();
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: process.env, cwd: ROOT, stdio: "pipe", timeout: 120_000,
  });
  const db = createDbClient(process.env.CROW_DB_PATH);
  return {
    home,
    dataDir,
    db,
    close: () => { try { db.close(); } catch { /* closed */ } },
  };
}

/** A trusted, active peer row with an explicit stored verifier. */
async function addPeer(db, id, stored, { trusted = 1, status = "active", gatewayUrl = "http://100.64.5.5:3001" } = {}) {
  await db.execute({
    sql: `INSERT INTO crow_instances (id, name, crow_id, gateway_url, tailscale_ip, auth_token_hash, status, trusted)
          VALUES (?, ?, ?, ?, '100.64.5.5', ?, ?, ?)`,
    args: [id, id, id, gatewayUrl, stored, status, trusted],
  });
}

const storedOf = async (db, id) => (await db.execute({
  sql: "SELECT auth_token_hash AS stored FROM crow_instances WHERE id = ?", args: [id],
})).rows[0]?.stored ?? null;

const legacyAudits = async (db) => (await db.execute({
  sql: "SELECT details FROM audit_log WHERE event_type = 'token_legacy_form'", args: [],
})).rows;

/** The alarm's audit row is written fire-and-forget, so wait for it instead of racing it. */
async function auditCountAtLeast(db, n, ms = 2_000) {
  const deadline = Date.now() + ms;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop -- a bounded poll
    const count = (await legacyAudits(db)).length;
    if (count >= n || Date.now() > deadline) return count;
    // eslint-disable-next-line no-await-in-loop -- a bounded poll
    await new Promise((r) => { setTimeout(r, 20); });
  }
}

const snapshotFiles = (home) => {
  try {
    return readdirSync(join(home, "secrets")).filter((n) => n.startsWith(PEER_ROLLBACK_PREFIX));
  } catch {
    return [];
  }
};

// ─── the converter (§3.2 / §3.3) ──────────────────────────────────────────

test("the boot converts every legacy peer verifier, records the D4 hash, marks the era, and a second boot is a no-op", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    await addPeer(s.db, "peerB", sha256("p".repeat(64)));
    // Already keyed: someone already converted this one (or it was paired by this version).
    const key = ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    await addPeer(s.db, "peerC", macToken(PEER_INBOUND_FAMILY, "c".repeat(64)));
    // The re-pair proof needs this peer's signing key stored BEFORE the conversion records the hash.
    setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });

    const boot = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(boot.key, "ok");
    assert.equal(boot.family.state, "converted");
    assert.equal(boot.converted, 2, "only the two legacy rows were rewritten");
    assert.equal(boot.alarms, 0, "no false alarm on the conversion boot");

    // Every stored value is the keyed MAC, and every raw bearer still authenticates.
    assert.equal(await storedOf(s.db, "peerA"), macToken(PEER_INBOUND_FAMILY, OLD));
    assert.match(await storedOf(s.db, "peerA"), H1);
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA", "the raw bearer still works");
    assert.equal((await validateInstanceToken(s.db, "p".repeat(64)))?.id, "peerB");
    assert.equal((await validateInstanceToken(s.db, "c".repeat(64)))?.id, "peerC", "an already-keyed row is untouched");
    assert.equal(await storedOf(s.db, "peerC"), macToken(PEER_INBOUND_FAMILY, "c".repeat(64)));

    // D4: the pre-conversion hash is recorded beside the peer's signing key, and the re-pair proof
    // key computed from it is EXACTLY the one computed from the legacy stored value.
    const creds = getPeerCreds("peerA");
    assert.equal(creds.inbound_bearer_sha256, sha256(OLD));
    assert.equal(creds.signing_key, SIGNING, "the store entry keeps its signing key");
    assert.equal(
      repairProofKey(creds.inbound_bearer_sha256, creds.signing_key),
      repairProofKey(sha256(OLD), SIGNING),
      "the re-pair proof key is unchanged by the conversion",
    );

    // The era: the secrets-side state file AND the local-scope DB mirror.
    assert.ok(readState().families[PEER_INBOUND_FAMILY]?.converted_at, "marked converted in secrets/");
    assert.ok(await readSetting(s.db, `token_hmac_era:${PEER_INBOUND_FAMILY}`), "mirrored into the DB");

    // One 0600 snapshot carrying the PRE-conversion values (hashes only).
    const files = snapshotFiles(s.home);
    assert.equal(files.length, 1);
    const body = JSON.parse(readFileSync(join(s.home, "secrets", files[0]), "utf8"));
    assert.equal(body.v, 1);
    assert.equal(body.family, PEER_INBOUND_FAMILY);
    assert.equal(body.key_id, key.id);
    assert.deepEqual(body.rows.map((r) => r.id).sort(), ["peerA", "peerB"]);
    for (const row of body.rows) assert.match(row.token, /^[0-9a-f]{64}$/);

    // A second boot converts NOTHING again (add-only era) and writes no second snapshot.
    const second = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(second.converted, 0, "never re-converted");
    assert.equal(second.alarms, 0);
    assert.equal(snapshotFiles(s.home).length, files.length, "no second snapshot");
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA");
  } finally {
    s.close();
  }
});

test("the conversion leaves a NULL (revoked) row alone, and a revoked row is not revived by it", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "gone", null, { status: "revoked", trusted: 0 });
    await addPeer(s.db, "peerA", sha256(OLD));
    const boot = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(boot.converted, 1);
    assert.equal(await storedOf(s.db, "gone"), null, "a revoked row keeps its NULL");
    assert.equal((await s.db.execute({ sql: "SELECT status FROM crow_instances WHERE id = 'gone'", args: [] })).rows[0].status, "revoked");
  } finally {
    s.close();
  }
});

test("a crash re-run converts only its snapshot's rows — a post-snapshot legacy write is refused, not laundered", async () => {
  const s = scratch();
  try {
    const LA = sha256("a".repeat(64));
    const LB = sha256("b".repeat(64));
    await addPeer(s.db, "snapRow", LA);
    await addPeer(s.db, "planted", LB);
    // The key the interrupted run minted, and the snapshot it wrote before it died.
    const key = ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const name = `${PEER_ROLLBACK_PREFIX}2026-01-01T00-00-00-000Z.json`;
    writeFileSync(join(s.home, "secrets", name), JSON.stringify({
      v: 1, family: PEER_INBOUND_FAMILY, key_id: key.id,
      created_at: "2026-01-01T00:00:00.000Z", rows: [{ id: "snapRow", token: LA }],
    }), { mode: 0o600 });

    const boot = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(boot.converted, 1, "only the snapshot's row is converted");
    assert.equal(await storedOf(s.db, "snapRow"), macToken(PEER_INBOUND_FAMILY, "a".repeat(64)));
    assert.equal(boot.alarms, 1, "the row written AFTER the snapshot is reported");
    assert.equal(await storedOf(s.db, "planted"), LB, "and left exactly as written");
    // The era is now recorded, so that row is not a credential any more.
    forgetTokenMacAlarms();
    assert.equal(await findPeerByBearer(s.db, "b".repeat(64)), null, "the post-snapshot value is refused");
    assert.equal((await legacyAudits(s.db)).some((row) => JSON.parse(row.details).family === PEER_INBOUND_FAMILY), true,
      "the refusal is audited");
    assert.equal(snapshotFiles(s.home).filter((f) => f === name).length, 1, "the resumed snapshot is reused");
  } finally {
    s.close();
  }
});

test("an EMPTY snapshot is still pending: a legacy row written after it is refused, not converted, and the family is marked", async () => {
  const s = scratch();
  try {
    // No legacy row at snapshot time → the snapshot lists nothing → the process dies before the
    // era marker. What a restart must NOT do is treat the empty file as "no snapshot" and convert
    // a row something wrote in between (that row's writer knows its bearer).
    const key = ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const name = `${PEER_ROLLBACK_PREFIX}2026-01-04T00-00-00-000Z.json`;
    writeFileSync(join(s.home, "secrets", name), JSON.stringify({
      v: 1, family: PEER_INBOUND_FAMILY, key_id: key.id,
      created_at: "2026-01-04T00:00:00.000Z", rows: [],
    }), { mode: 0o600 });
    const PLANTED = sha256("planted-after-an-empty-snapshot");
    await addPeer(s.db, "plantedAfterEmpty", PLANTED);

    forgetTokenMacAlarms();
    const boot = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(boot.family.state, "converted");
    assert.equal(boot.converted, 0, "the snapshot lists nothing, so nothing is converted");
    assert.equal(boot.alarms, 1, "the row written since the snapshot is reported");
    assert.equal(await storedOf(s.db, "plantedAfterEmpty"), PLANTED, "and left exactly as written");
    assert.equal(snapshotFiles(s.home).filter((f) => f === name).length, 1, "the empty snapshot is reused, not replaced");
    assert.ok(readState().families[PEER_INBOUND_FAMILY]?.converted_at, "the family is marked converted now");
    forgetTokenMacAlarms();
    assert.equal(await findPeerByBearer(s.db, "planted-after-an-empty-snapshot"), null,
      "the post-snapshot value is refused, never a credential");
  } finally {
    s.close();
  }
});

test("a family the boot could not convert refuses legacy values for the rest of the process", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    const boot = await runPeerTokenHmacBoot({
      db: s.db,
      runTransaction: () => { throw new Error("disk I/O error"); },
    });
    assert.equal(boot.family.state, "failed");
    assert.equal(readState().families[PEER_INBOUND_FAMILY], undefined, "no era is recorded");
    assert.equal(await readSetting(s.db, `token_hmac_era:${PEER_INBOUND_FAMILY}`), null);
    forgetTokenMacAlarms();
    assert.equal(await findPeerByBearer(s.db, OLD), null, "a bare sha256 is REFUSED in this process");
    assert.equal(await validateInstanceToken(s.db, OLD), null);
    assert.equal(await storedOf(s.db, "peerA"), sha256(OLD), "and nothing was rewritten");
  } finally {
    s.close();
  }
});

test("an unwritable secrets/ SKIPS the family (no era): legacy stays accepted rather than locking the box out", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    const boot = await runPeerTokenHmacBoot({
      db: s.db,
      writeSnapshot: () => { throw Object.assign(new Error("denied"), { code: "EACCES" }); },
    });
    assert.equal(boot.family.state, "skipped");
    assert.equal(readState().families[PEER_INBOUND_FAMILY], undefined);
    assert.equal((await findPeerByBearer(s.db, OLD))?.id, "peerA", "still accepted, unprotected");
  } finally {
    s.close();
  }
});

test("a lost key refuses every peer bearer (fail closed) instead of falling back to sha256", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    await runPeerTokenHmacBoot({ db: s.db });
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA", "positive control while the key is present");
    const expected = await storedOf(s.db, "peerA");
    assert.match(expected, H1);
    // The key file is gone (a restore of crow.db without secrets/): the process must refuse,
    // never re-derive a verifier or accept the old sha256.
    unlinkSync(tokenMacKeyPath());
    forgetTokenMacKey();
    forgetPeerInboundEvidence();
    forgetTokenMacAlarms();
    assert.equal(await validateInstanceToken(s.db, OLD), null);
    assert.equal(await findPeerByBearer(s.db, OLD), null);
    assert.equal(await storedOf(s.db, "peerA"), expected, "nothing was rewritten");
  } finally {
    s.close();
  }
});

// ─── forgery (the headline) ───────────────────────────────────────────────

test("after conversion a planted sha256 of a bot's own token is refused by BOTH verifiers and audited", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });
    await runPeerTokenHmacBoot({ db: s.db });
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA", "positive control");

    // The forgery: write access to crow.db lets a bot compute sha256(its own token) and plant it
    // on a TRUSTED row. Before this PR that made the row a credential.
    const botToken = "bot-chosen-bearer";
    await s.db.execute({
      sql: "UPDATE crow_instances SET auth_token_hash = ? WHERE id = 'peerA'",
      args: [sha256(botToken)],
    });
    forgetTokenMacAlarms();
    assert.equal(await validateInstanceToken(s.db, botToken), null, "validateInstanceToken refuses the forged row");
    assert.ok((await legacyAudits(s.db)).some((row) => {
      const d = JSON.parse(row.details);
      return d.family === PEER_INBOUND_FAMILY && d.row === "peerA";
    }), "the refusal is audited as token_legacy_form, naming the row");
    assert.equal(await storedOf(s.db, "peerA"), sha256(botToken), "nothing was changed by the refusal");

    // The SAME row through the cross-host signed-call middleware (the second verifier).
    const app = express();
    app.use(express.json());
    app.get("/x", crossHostVerifyMiddleware(s.db, { audit: "peer.pr4", emptyBodyString: "" }), (req, res) => res.json({ reached: true }));
    const srv = createServer(app);
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${srv.address().port}`;
    try {
      const signed = (bearer) => {
        _resetNonceCache();
        return signRequest({ method: "GET", path: "/x", body: "", authToken: bearer, signingKey: SIGNING, sourceInstanceId: "peerA" });
      };
      const forged = await fetch(`${base}/x`, { headers: signed(botToken) });
      assert.equal(forged.status, 401, "the HMAC is valid but the bearer is not a credential");
      assert.deepEqual(await forged.json(), { error: "peer_auth_failed" });
      const audit = (await s.db.execute({
        sql: "SELECT error FROM cross_host_calls WHERE source_instance_id = 'peerA' AND direction = 'inbound' ORDER BY id DESC LIMIT 1",
        args: [],
      })).rows[0];
      assert.equal(audit?.error, "bearer_mismatch");

      // Positive control on the same wiring: the row's real bearer passes the bearer binding.
      await s.db.execute({ sql: "UPDATE crow_instances SET auth_token_hash = ? WHERE id = 'peerA'", args: [macToken(PEER_INBOUND_FAMILY, OLD)] });
      const ok = await fetch(`${base}/x`, { headers: signed(OLD) });
      assert.equal(ok.status, 200);
    } finally {
      srv.closeAllConnections?.();
      await new Promise((r) => srv.close(r));
    }
  } finally {
    s.close();
  }
});

test("a value copied from ANOTHER family's store never verifies here (the family is inside the MAC)", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    // A real `h1.` value, minted under the SAME key but for a different domain — exactly what a
    // bot that can read crow.db (a settings verifier, an oauth row) could copy.
    const foreign = macToken("mcp_models_token_hash", "copied-token");
    assert.match(foreign, H1);
    await addPeer(s.db, "peerA", foreign);
    await runPeerTokenHmacBoot({ db: s.db });
    forgetTokenMacAlarms();
    assert.equal(await findPeerByBearer(s.db, "copied-token"), null, "the copied value is not a peer credential");
    assert.equal(await validateInstanceToken(s.db, "copied-token"), null);
    assert.equal(await validateInstanceToken(s.db, OLD), null);
    // And it is not refused as a LEGACY row either: it is a well-formed MAC that does not match.
    assert.equal((await legacyAudits(s.db)).length, 0, "no legacy alarm: the value has the right SHAPE");
  } finally {
    s.close();
  }
});

test("a bot INSERTing a trusted row with a legacy hash after conversion does not authenticate", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    await runPeerTokenHmacBoot({ db: s.db });
    const planted = "planted-row-bearer";
    await addPeer(s.db, "plantedRow", sha256(planted));
    forgetTokenMacAlarms();
    assert.equal(await validateInstanceToken(s.db, planted), null, "the verifier refuses the inserted row");
    assert.equal(await findPeerByBearer(s.db, planted), null);
    assert.ok((await legacyAudits(s.db)).some((row) => JSON.parse(row.details).row === "plantedRow"),
      "and the inserted row is reported");
    assert.equal(await storedOf(s.db, "plantedRow"), sha256(planted), "the row is left as written");
  } finally {
    s.close();
  }
});

// ─── the lookup prefers the keyed row ───────────────────────

test("a legacy twin planted beside the real converted row never shadows it (no rows[0] answer)", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    await runPeerTokenHmacBoot({ db: s.db });
    // The SAME pre-conversion value in a second trusted row: it matches the very same lookup
    // (both stored forms are queried), so whichever row the store answers first used to decide.
    await addPeer(s.db, "twin", sha256(OLD));
    forgetTokenMacAlarms();
    const row = await findPeerByBearer(s.db, OLD);
    assert.equal(row?.id, "peerA", "the row holding the keyed verifier answers");
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA");
    assert.equal(await storedOf(s.db, "twin"), sha256(OLD), "the twin is left as written");
  } finally {
    s.close();
  }
});

test("an UPPERCASE 64-hex stored value is legacy too: the converter rewrites it, the scan alarms it", async () => {
  const s = scratch();
  try {
    // `verifyStored`'s 64-hex test is case-insensitive, so this IS a working legacy credential.
    assert.equal(isLegacyStored(sha256("AAAA").toUpperCase()), true, "the converter's test is case-insensitive");
    const UPPER = sha256("upper-case-legacy-value").toUpperCase();
    await addPeer(s.db, "peerUpper", UPPER);
    const boot = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(boot.converted, 1, "converted, not left behind as an unrecognized value");
    assert.equal(boot.alarms, 0);
    assert.equal(await storedOf(s.db, "peerUpper"), macToken(PEER_INBOUND_FAMILY, "upper-case-legacy-value"));
    assert.equal((await validateInstanceToken(s.db, "upper-case-legacy-value"))?.id, "peerUpper", "its bearer still works");

    // …and after the conversion an uppercase old-style row is reported by the BOOT SCAN, exactly
    // like a lowercase one (the validator's lookup cannot even find it: it searches the lowercase
    // hash, so the scan is the only place it becomes visible).
    const PLANTED = sha256("planted-uppercase").toUpperCase();
    await addPeer(s.db, "plantedUpper", PLANTED);
    forgetTokenMacAlarms();
    const scan = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(scan.family.scan, true, "the family is already converted");
    assert.equal(scan.alarms, 1, "the uppercase row is alarmed by the scan, not silently ignored");
    assert.equal(await storedOf(s.db, "plantedUpper"), PLANTED, "and left exactly as written");
    assert.ok((await legacyAudits(s.db)).some((row) => JSON.parse(row.details).row === "plantedUpper"));
  } finally {
    s.close();
  }
});

test("a converted row with no credential record is REPORTED — one line, a count, no id — and still converted", async () => {
  const s = scratch();
  const realWarn = console.warn;
  const lines = [];
  try {
    await addPeer(s.db, "peerNoCreds", sha256(OLD));
    console.warn = (msg) => { lines.push(String(msg)); };
    let boot;
    try {
      boot = await runPeerTokenHmacBoot({ db: s.db });
    } finally {
      console.warn = realWarn;
    }
    assert.equal(boot.converted, 1, "the row converts: the verifier needs no credential record");
    assert.equal(boot.noCredential, 1, "and is reported as having none");
    const report = lines.filter((l) => l.includes("no credential record"));
    assert.equal(report.length, 1, "exactly one boot line");
    assert.match(report[0], /: 1 converted row\(s\) have no credential record/);
    assert.equal(report[0].includes("peerNoCreds"), false, "no peer id in the line");
    assert.equal(/[0-9a-f]{64}/.test(report[0]), false, "no hash in the line");
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerNoCreds", "the peer still authenticates");
  } finally {
    console.warn = realWarn;
    s.close();
  }
});

// ─── writers: every one stores the keyed MAC ──────────────────────────────

/** An in-process enroll target: the REAL route, an allowed (Serve-shaped) caller. */
async function enrollPeer(s) {
  Object.assign(process.env, {
    CROW_HOME: s.home,
    CROW_DATA_DIR: s.dataDir,
    CROW_DB_PATH: join(s.dataDir, "crow.db"),
    CROW_ENROLL_ENABLED: "1",
    PORT: "3001",
  });
  delete process.env.CROW_PEER_TOKENS_PATH;
  delete process.env.CROW_PEER_GATEWAY_URL;
  delete process.env.CROW_DASHBOARD_PUBLIC;
  const app = express();
  app.use(instanceEnrollRouter(s.db, { execFileSyncImpl: () => { throw new Error("no tailscale in tests"); } }));
  app.set("trust proxy", trustedProxyList());
  const srv = createServer(app);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return {
    port: srv.address().port,
    close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }),
  };
}

/** POST to the enroll route as a tailnet client behind Serve. */
function post(port, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = request({
      host: "127.0.0.1", port, path: "/instance/enroll-request", method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
        "X-Forwarded-For": "100.64.200.1",
        "X-Forwarded-Host": "crow.example.ts.net:8444",
      },
    }, (res) => {
      let buf = "";
      res.on("data", (c) => { buf += c; });
      res.on("end", () => { let j = null; try { j = JSON.parse(buf); } catch { j = buf; } resolve({ status: res.statusCode, body: j }); });
    });
    req.on("error", reject);
    req.end(data);
  });
}

const enrollBody = (id, extra = {}) => ({
  source_instance_id: id,
  source_name: id,
  source_gateway_url: "http://100.64.5.5:3001",
  source_tailscale_ip: "100.64.5.5",
  source_sync_port: 3001,
  source_outbound_bearer: NEW,
  shared_signing_key: "k".repeat(64),
  ...extra,
});

test("the enroll route stores the keyed MAC, records inbound_bearer_sha256, and the peer's raw bearer authenticates", async () => {
  const s = scratch();
  try {
    const otc = generateEnrollOtc();
    process.env.CROW_ENROLL_OTC = otc;
    const peer = await enrollPeer(s);
    try {
      const r = await post(peer.port, enrollBody("peerNew", { otc }));
      assert.equal(r.status, 200, JSON.stringify(r.body));
    } finally {
      await peer.close();
    }
    assert.equal(await storedOf(s.db, "peerNew"), macToken(PEER_INBOUND_FAMILY, NEW));
    assert.match(await storedOf(s.db, "peerNew"), H1);
    assert.equal((await validateInstanceToken(s.db, NEW))?.id, "peerNew", "the peer authenticates with its raw bearer");
    assert.equal(getPeerCreds("peerNew").inbound_bearer_sha256, sha256(NEW), "D4: the legacy hash is recorded");
  } finally {
    s.close();
  }
});

test("the pairing CLI's write half stores the keyed MAC (and the raw bearer authenticates)", async () => {
  const s = scratch();
  try {
    const { storePeerCredsLocally } = await import("../scripts/cli/instance-pair.js");
    const raw = "cli-peer-bearer".padEnd(64, "x");
    await storePeerCredsLocally(s.db, {
      peerId: "peerCli",
      peerName: "cli",
      peerCrowId: "peerCli",
      peerGatewayUrl: "http://100.64.5.9:3001",
      pinOrigin: null,
      peerTailscaleIp: null,
      peerSyncPort: 3001,
      auth_token: "t".repeat(64),
      signing_key: SIGNING,
      peerOutboundBearerHash: await mintPeerInbound(s.db, raw),
      inboundBearerSha256: legacyStoredHash(raw),
    });
    assert.equal(await storedOf(s.db, "peerCli"), macToken(PEER_INBOUND_FAMILY, raw));
    assert.equal((await validateInstanceToken(s.db, raw))?.id, "peerCli");
    assert.equal(getPeerCreds("peerCli").inbound_bearer_sha256, sha256(raw));
  } finally {
    s.close();
  }
});

test("rotateAuthToken stores the keyed MAC, and the token it returns authenticates", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    await runPeerTokenHmacBoot({ db: s.db });
    const token = await rotateAuthToken(s.db, "peerA");
    assert.match(await storedOf(s.db, "peerA"), H1);
    assert.notEqual(await storedOf(s.db, "peerA"), sha256(token), "never the legacy form");
    assert.equal((await validateInstanceToken(s.db, token))?.id, "peerA");
    assert.equal(await validateInstanceToken(s.db, OLD), null, "the previous bearer is dead");
  } finally {
    s.close();
  }
});

test("the self row (crow_register_instance) stores the keyed MAC, and its bearer authenticates", async () => {
  const s = scratch();
  try {
    const { registerInstancesTools } = await import("../servers/sharing/tools/instances.js");
    const handlers = {};
    registerInstancesTools(
      { tool: (name, _description, _schema, fn) => { handlers[name] = fn; } },
      { db: s.db, identity: { crowId: "crow-pr4-self" } },
    );
    const res = await handlers.crow_register_instance({ name: "PR4 self" });
    const text = res.content.map((c) => c.text).join("\n");
    const token = /Auth token: ([0-9a-f]{64})/.exec(text)?.[1];
    assert.ok(token, "the tool still returns the token it minted");
    const selfId = (await s.db.execute({
      sql: "SELECT id FROM crow_instances WHERE crow_id = 'crow-pr4-self' OR name = 'PR4 self' LIMIT 1", args: [],
    })).rows[0]?.id;
    assert.ok(selfId, "the self row was written");
    assert.match(await storedOf(s.db, selfId), H1, "stored as the keyed MAC");
    assert.equal(await storedOf(s.db, selfId), macToken(PEER_INBOUND_FAMILY, token));
    // The stored verifier accepts the raw bearer (the self row is not a TRUSTED peer, so the lookup
    // is the wrong door for it — the predicate, not the verifier, is what declines there).
    const selfRow = (await s.db.execute({ sql: "SELECT * FROM crow_instances WHERE id = ?", args: [selfId] })).rows[0];
    assert.equal(await verifyPeerBearer(s.db, selfRow, token), true);
    assert.equal(await verifyPeerBearer(s.db, selfRow, "not-the-bearer"), false);
  } finally {
    s.close();
  }
});

// ─── D4: the re-pair proof ────────────────────────────────────────────────

test("a re-pair proof succeeds against a CONVERTED target (keyed by the recorded hash)", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });
    const boot = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(boot.converted, 1);
    assert.equal(getPeerCreds("peerA").inbound_bearer_sha256, sha256(OLD));

    const otc = generateEnrollOtc();
    process.env.CROW_ENROLL_OTC = otc;
    const localId = "0123456789abcdef0123456789abcdef";
    // The proof the PEER sends: keyed by sha256(its current bearer) + the shared signing key —
    // exactly as before this PR, because the value it computes never changed.
    const body = enrollBody("peerA", { otc });
    const proof = repairProof(repairProofKey(sha256(OLD), SIGNING), body, { targetId: localId, otcDigest: sha256(otc) });
    const peer = await enrollPeer(s);
    try {
      const r = await post(peer.port, { ...body, repair_proofs: [proof] });
      assert.equal(r.status, 200, JSON.stringify(r.body));
    } finally {
      await peer.close();
    }
    // Re-keyed: the new bearer's verifier, and the D4 record follows it.
    assert.equal(await storedOf(s.db, "peerA"), macToken(PEER_INBOUND_FAMILY, NEW));
    assert.equal(getPeerCreds("peerA").inbound_bearer_sha256, sha256(NEW));
    assert.equal((await validateInstanceToken(s.db, NEW))?.id, "peerA");
    assert.equal(await validateInstanceToken(s.db, OLD), null, "the old bearer is not a credential any more");
  } finally {
    s.close();
  }
});

test("a re-pair proof succeeds when the target is still unconverted (fallback to the legacy stored verifier)", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });
    const otc = generateEnrollOtc();
    process.env.CROW_ENROLL_OTC = otc;
    const body = enrollBody("peerA", { otc });
    const proof = repairProof(repairProofKey(sha256(OLD), SIGNING), body, {
      targetId: "0123456789abcdef0123456789abcdef", otcDigest: sha256(otc),
    });
    const peer = await enrollPeer(s);
    try {
      const r = await post(peer.port, { ...body, repair_proofs: [proof] });
      assert.equal(r.status, 200, JSON.stringify(r.body));
    } finally {
      await peer.close();
    }
    assert.equal(await storedOf(s.db, "peerA"), macToken(PEER_INBOUND_FAMILY, NEW), "the writer still stores the MAC");
  } finally {
    s.close();
  }
});

test("an h1 value is NEVER fed into repairProofKey: a converted row with no recorded hash refuses the proof path", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const keyed = macToken(PEER_INBOUND_FAMILY, OLD);
    await addPeer(s.db, "peerA", keyed);
    // No `inbound_bearer_sha256` record: the shape of an install whose store was restored, or a
    // pair made by a version that did not write one.
    setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });
    assert.equal(await repairProofSecret(s.db, { id: "peerA", auth_token_hash: keyed }), null, "an h1 value never becomes the proof key");

    const otc = generateEnrollOtc();
    process.env.CROW_ENROLL_OTC = otc;
    const targetId = "0123456789abcdef0123456789abcdef";
    const body = enrollBody("peerA", { otc });
    // Every proof a caller could DERIVE from the stored value is refused, including the plausible
    // "hash the MAC again" fix — the key must come from a value the peer itself can compute.
    const proofs = [
      repairProof(repairProofKey(keyed, SIGNING), body, { targetId, otcDigest: sha256(otc) }),
      repairProof(repairProofKey(sha256(keyed), SIGNING), body, { targetId, otcDigest: sha256(otc) }),
    ];
    const peer = await enrollPeer(s);
    try {
      for (const proof of proofs) {
        // eslint-disable-next-line no-await-in-loop -- one refusal per candidate proof
        const r = await post(peer.port, { ...body, repair_proofs: [proof] });
        assert.equal(r.status, 409, JSON.stringify(r.body));
        assert.equal(r.body.error, "already_paired");
        assert.match(r.body.hint, /--allow-re-pair peerA/, "the operator allowance is the way back");
      }
    } finally {
      await peer.close();
    }
    assert.equal(await storedOf(s.db, "peerA"), keyed, "nothing was rewritten by the refusals");
  } finally {
    s.close();
  }
});

test("repairProofSecret: the recorded hash first, the legacy stored verifier only while unconverted, never an h1 value", async () => {
  const keyed = `h1.${"a".repeat(16)}.${"b".repeat(64)}`;
  const s = scratch();
  try {
    // A recorded hash is taken as-is (it is what the peer itself computes).
    setPeerCreds("pRecord", { auth_token: "t".repeat(64), signing_key: SIGNING, inbound_bearer_sha256: sha256(OLD) });
    assert.equal(await repairProofSecret(s.db, { id: "pRecord", auth_token_hash: keyed }), sha256(OLD));
    // No record: the stored verifier IS the value the peer computes, but only in its legacy form
    // AND only while the family is not converted (its stored value is not a verifier after that).
    assert.equal(await repairProofSecret(s.db, { id: "pLegacy", auth_token_hash: sha256("z".repeat(64)) }), sha256("z".repeat(64)));
    assert.equal(await repairProofSecret(s.db, { id: "pUpper", auth_token_hash: sha256("y".repeat(64)).toUpperCase() }), sha256("y".repeat(64)), "normalized");
    // An h1 stored value is never a proof input, whatever else is missing.
    assert.equal(await repairProofSecret(s.db, { id: "pKeyed", auth_token_hash: keyed }), null);
    assert.equal(await repairProofSecret(s.db, { id: "pJunk", auth_token_hash: "not-a-hash" }), null);
    assert.equal(await repairProofSecret(s.db, null), null);
    assert.equal(await repairProofSecret(s.db, { id: "pNull", auth_token_hash: null }), null);
    // Once the family is converted, a stored bare sha256 was written by something without the
    // key, so keying the proof by it would let that writer choose the proof key.
    await markConverted(PEER_INBOUND_FAMILY);
    assert.equal(await repairProofSecret(s.db, { id: "pLegacy", auth_token_hash: sha256("z".repeat(64)) }), null,
      "a converted family never keys the proof from a stored value");
    assert.equal(await repairProofSecret(s.db, { id: "pRecord", auth_token_hash: keyed }), sha256(OLD),
      "a RECORDED hash is still used — it is the D4 value, not the stored verifier");
  } finally {
    s.close();
  }
});

// ─── sync: the column never rides the wire ────────────────────────────────

test("auth_token_hash is never emitted by instance sync", () => {
  assert.deepEqual(EXCLUDED_COLUMNS.crow_instances, ["auth_token_hash"], "the column is on the exclude list");
  const row = {
    id: "peerA", name: "A", crow_id: "peerA", status: "active", trusted: 1,
    gateway_url: "http://100.64.5.5:3001", auth_token_hash: `h1.${"a".repeat(16)}.${"b".repeat(64)}`,
  };
  assert.equal(shouldSyncRow("crow_instances", row), false, "the table is gated in both directions");
  // Belt and braces: even if a path reached emitChange, the strip removes the verifier.
  const clean = { ...row };
  for (const column of EXCLUDED_COLUMNS.crow_instances) delete clean[column];
  assert.equal("auth_token_hash" in clean, false);
  assert.equal("auth_token_hash" in JSON.parse(JSON.stringify(clean)), false);
});

// ─── the operator dry run ────────────────────────────────────────────────

const DRYRUN = join(ROOT, "scripts/ops/peer-token-hmac-dryrun.mjs");

/** Run the dry run against a COPY of `s`'s DB, into its own scratch rehearsal home. */
function dryrun(s, label) {
  const scratchHome = mkdtempSync(join(tmpdir(), "crow-peer-dryrun-"));
  roots.push(scratchHome);
  try {
    const out = execFileSync(process.execPath, [
      DRYRUN, "--db", `${label}=${join(s.dataDir, "crow.db")}`, "--files-from", s.home, "--home", scratchHome,
    ], { cwd: ROOT, encoding: "utf8", stdio: "pipe", timeout: 120_000 });
    return { code: 0, out };
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

test("the dry run rehearses a copy: PASS on a clean box, STOP when a value would be refused", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });

    const pass = dryrun(s, "crow");
    assert.equal(pass.code, 0, pass.out);
    assert.match(pass.out, /^PASS:/m, "one verdict line");
    assert.match(pass.out, /1 row\(s\) would be converted, 0 old-style value\(s\) refused/);
    assert.match(pass.out, /credential records: 1 gained inbound_bearer_sha256/);
    assert.match(pass.out, /re-pair proof: 1 key\(s\) unchanged, 0 WOULD CHANGE/, "D4 is checked, not assumed");
    // Never a token, a hash or an id on stdout.
    assert.equal(/[0-9a-f]{64}/.test(pass.out), false, "the rehearsal prints no hash and no token");
    assert.equal(pass.out.includes("peerA"), false, "and no peer id");
    // The rehearsal changed nothing at the source.
    assert.equal(readState().families[PEER_INBOUND_FAMILY], undefined, "the source era is untouched");
    assert.equal(await storedOf(s.db, "peerA"), sha256(OLD), "the source row is untouched");
    assert.equal(getPeerCreds("peerA").inbound_bearer_sha256, undefined, "and so is the source credential store");

    // A converted box carrying a planted old-style value: the rehearsal must STOP.
    await runPeerTokenHmacBoot({ db: s.db });
    await addPeer(s.db, "plantedRow", sha256("planted-bearer"));
    const stop = dryrun(s, "r4");
    assert.equal(stop.code, 1, stop.out);
    assert.match(stop.out, /^STOP:/m);
    assert.match(stop.out, /1 old-style value\(s\) refused/);
    assert.equal(/[0-9a-f]{64}/.test(stop.out), false, "the rehearsal prints no hash and no token");
  } finally {
    s.close();
  }
});

test("the dry run reports rows with no credential record as a count and still PASSes (report, never refuse)", async () => {
  const s = scratch();
  try {
    // A trusted legacy row and no secrets/peer-tokens.json entry at all.
    await addPeer(s.db, "peerNoCreds", sha256(OLD));
    const pass = dryrun(s, "crow");
    assert.equal(pass.code, 0, pass.out);
    assert.match(pass.out, /^PASS:/m);
    assert.match(pass.out, /rows with no credential record: 1/);
    assert.equal(/[0-9a-f]{64}/.test(pass.out), false, "the rehearsal prints no hash and no token");
    assert.equal(pass.out.includes("peerNoCreds"), false, "and no peer id");
  } finally {
    s.close();
  }
});

// ─── the reset rail (§2.6) ────────────────────────────────────────────────

test("`token-hmac.mjs --reset` clears every peer verifier, KEEPS the era, and leaves the re-pair record alone", async () => {
  const s = scratch();
  let db = s.db;
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });
    // The state a working pair is in: converted, with the D4 record written by the conversion.
    await runPeerTokenHmacBoot({ db: s.db });
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA", "positive control before the reset");
    assert.equal(getPeerCreds("peerA").inbound_bearer_sha256, sha256(OLD));
    const proofKeyBefore = repairProofKey(getPeerCreds("peerA").inbound_bearer_sha256, SIGNING);
    s.close();

    execFileSync(process.execPath, [
      join(ROOT, "scripts/token-hmac.mjs"), "--reset", "--yes", "--force-while-running",
    ], { cwd: ROOT, env: process.env, stdio: "pipe", timeout: 120_000 });

    // The key is new; this process was holding the retired one.
    forgetTokenMacKey();
    forgetTokenMacAlarms();
    forgetPeerInboundEvidence();
    db = createDbClient(process.env.CROW_DB_PATH);

    // Every peer verifier is cleared: the bearer lives on the peer, so each pair has to re-pair.
    assert.equal(await storedOf(db, "peerA"), null, "the row holds no verifier any more");
    assert.equal(await validateInstanceToken(db, OLD), null);
    // The family stays CONVERTED — a value planted while the gateway is stopped is refused, not
    // converted by the next boot.
    assert.ok(readState().families[PEER_INBOUND_FAMILY]?.converted_at, "the era is kept, never cleared");
    assert.ok(await readSetting(db, `token_hmac_era:${PEER_INBOUND_FAMILY}`), "and so is the DB mirror");
    await addPeer(db, "plantedAfterReset", sha256("planted-after-reset"));
    forgetTokenMacAlarms();
    assert.equal(await validateInstanceToken(db, "planted-after-reset"), null, "a planted legacy value is refused");
    assert.ok((await legacyAudits(db)).some((row) => JSON.parse(row.details).row === "plantedAfterReset"),
      "and it is audited");
    // D4 survives: the credential store still holds what the peer's own install computes, so the
    // peer can prove the old pairing and re-pair without the operator's --allow-re-pair.
    assert.equal(getPeerCreds("peerA").inbound_bearer_sha256, sha256(OLD), "the re-pair record is untouched");
    assert.equal(repairProofKey(getPeerCreds("peerA").inbound_bearer_sha256, SIGNING), proofKeyBefore);
  } finally {
    try { db.close?.(); } catch { /* closed */ }
    try { s.close(); } catch { /* closed */ }
  }
});

test("the bearer seam installs once: a later install is ignored (one line) and clearing is test-only", async () => {
  const seam = await import("../servers/shared/peer-bearer.js");
  // Importing the gateway module above installed the real implementation in this process.
  assert.equal(seam.peerBearerInstalled(), true);
  const realWarn = console.warn;
  const lines = [];
  let first;
  console.warn = (msg) => { lines.push(String(msg)); };
  try {
    first = seam.installPeerBearer({ find: async () => ({ id: "spy" }), mint: async () => "spy" });
    seam.installPeerBearer({ find: async () => ({ id: "spy2" }) });
  } finally {
    console.warn = realWarn;
  }
  assert.equal(first, false, "the first install wins and a later one is ignored");
  assert.equal(lines.filter((l) => l.includes("already installed")).length, 1, "one line for both attempts");
  // The gateway's own verifier is still the one installed: a converted peer still authenticates.
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    await runPeerTokenHmacBoot({ db: s.db });
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA", "the ignored install changed nothing");
    assert.equal(await seam.peerBearerFind(s.db, "x"), null, "and no spy answers a lookup");
  } finally {
    s.close();
  }
  assert.equal(typeof seam.clearPeerBearer, "undefined", "a production-looking clear does not exist");
  assert.equal(typeof seam.clearPeerBearerForTest, "function", "the seam itself is named for tests");
});

// ─── static guards ────────────────────────────────────────────────────────

function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (entry.name === "node_modules") continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, out);
    else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) out.push(path);
  }
  return out;
}

test("source: inbound_bearer_sha256 is never a verifier — nothing compares a presented bearer against it", () => {
  const FILES = [
    ...walk(join(ROOT, "servers")),
    ...walk(join(ROOT, "scripts")).filter((p) => !p.includes(`${join("scripts", "pi-bots")}`)),
  ];
  const NAMED = new Set([
    // The store module owns the field (and compares two RECORDS for idempotence), and the operator
    // dry run compares two RECORDS for its report. Neither sees a presented bearer.
    "servers/shared/peer-credentials.js",
    "scripts/ops/peer-token-hmac-dryrun.mjs",
  ]);
  const namers = [];
  for (const path of FILES) {
    const rel = relative(ROOT, path).split("\\").join("/");
    const src = readFileSync(path, "utf8");
    if (!src.includes("inbound_bearer_sha256") && !src.includes("getInboundBearerSha256")) continue;
    namers.push(rel);
    if (NAMED.has(rel)) continue;
    for (const line of src.split("\n")) {
      if (!line.includes("inbound_bearer_sha256") && !line.includes("getInboundBearerSha256")) continue;
      assert.equal(/(===|!==|safeEqual|timingSafeEqual|verifyStored)/.test(line), false,
        `${rel}: the recorded hash must never be compared to a credential: ${line.trim()}`);
    }
  }
  assert.deepEqual(namers.sort(), [
    "scripts/cli/instance-pair.js",
    "scripts/ops/peer-token-hmac-dryrun.mjs",
    // Documentation mentions only (the field is described, never read): the reset tool's header
    // says what a reset does to it, and the family module's header says it is not a verifier.
    "scripts/token-hmac.mjs",
    "servers/gateway/boot/token-hmac-peers.js",
    "servers/gateway/peer-inbound-token.js",
    "servers/gateway/routes/instance-enroll.js",
    "servers/shared/peer-credentials.js",
  ], "only the store, the converter, the two pairing writers, the reset/dry-run tools and the doc mentions know the field");
  // The one consumer: the enroll route's proof key.
  const enroll = readFileSync(join(ROOT, "servers/gateway/routes/instance-enroll.js"), "utf8");
  assert.match(enroll, /repairProofKey\(proofSecret/, "the recorded hash is an INPUT to repairProofKey and nothing else");
});

test("source: the gateway installs the seam and runs the peer converter before listen", () => {
  const index = readFileSync(join(ROOT, "servers/gateway/index.js"), "utf8");
  assert.match(index, /import "\.\/peer-inbound-token\.js";/, "the seam implementation is installed by a static import");
  const boot = index.indexOf("runPeerTokenHmacBoot");
  const listen = index.indexOf("app.listen(PORT, BIND");
  assert.ok(boot > 0, "the peer converter runs at boot");
  assert.ok(boot < listen, "before the gateway listens (zero accepted-legacy window)");
  // instance-registry is bot-reachable: it must reach the verifier only through the seam.
  const registry = readFileSync(join(ROOT, "servers/gateway/instance-registry.js"), "utf8");
  assert.match(registry, /from "\.\.\/shared\/peer-bearer\.js"/);
  assert.equal(/token-mac|peer-inbound-token/.test(registry.replace(/\/\*[\s\S]*?\*\//g, "")), false,
    "instance-registry must not import the key module (tests/bot-seed-import-guard.test.js)");
  assert.ok(tokenMacKeyPath().endsWith("token-hmac.key"));
});
// ─── round 2 (H1) ─────────────────────────────────────────────────────────

test("H1: an era recorded ONLY in the database is adopted into the state file; a sha256 row planted after the mirror is deleted stays refused and is never converted", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const { eraSettingKey } = await import("../servers/shared/token-mac.js");
    const { writeSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
    await writeSetting(s.db, eraSettingKey(PEER_INBOUND_FAMILY), new Date().toISOString(), { scope: "local" });
    assert.equal(readState().families[PEER_INBOUND_FAMILY], undefined, "precondition: the state file has no era");
    const first = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(first.key, "ok");
    assert.ok(readState().families[PEER_INBOUND_FAMILY]?.converted_at, "the era is now in the state file");
    assert.deepEqual(snapshotFiles(s.home), [], "adopted, not converted: no snapshot");
    await auditCountAtLeast(s.db, 1);
    assert.ok((await legacyAudits(s.db)).some((r) => JSON.parse(r.details).mirror === true));

    await s.db.execute({ sql: "DELETE FROM dashboard_settings_overrides WHERE key = ?", args: [`token_hmac_era:${PEER_INBOUND_FAMILY}`] });
    forgetTokenMacAlarms();
    await addPeer(s.db, "plantedAfterMirrorDelete", sha256("bot-bearer"));
    assert.equal(await validateInstanceToken(s.db, "bot-bearer"), null, "refused at runtime");
    const second = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(await storedOf(s.db, "plantedAfterMirrorDelete"), sha256("bot-bearer"), "not converted");
    assert.ok(second.alarms >= 1, "and alarmed");
    assert.equal(await validateInstanceToken(s.db, "bot-bearer"), null);
  } finally {
    s.close();
  }
});

// ─── round 3 ──────────────────────────────────────────────────────────────

/** A db whose reads of the era mirror throw a NON-"no such table" error (the bot's "unreadable mirror"). */
function withUnreadableMirror(db) {
  return new Proxy(db, {
    get(target, prop) {
      if (prop !== "execute") return target[prop];
      return (statement) => {
        const sql = String(typeof statement === "string" ? statement : statement?.sql ?? "");
        const args = Array.isArray(statement?.args) ? statement.args : [];
        if (/^\s*SELECT/i.test(sql) && args.some((a) => String(a).startsWith("token_hmac_era:"))) {
          throw new Error("disk I/O error (simulated)");
        }
        return target.execute(statement);
      };
    },
  });
}

async function plantPeerMirror(db) {
  const { eraSettingKey } = await import("../servers/shared/token-mac.js");
  const { writeSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
  await writeSetting(db, eraSettingKey(PEER_INBOUND_FAMILY), new Date().toISOString(), { scope: "local" });
}

test("M-B: an unreadable mirror does not postpone the era: with no marker the boot converts and records it", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    await addPeer(s.db, "peerA", sha256(OLD));
    const boot = await runPeerTokenHmacBoot({ db: withUnreadableMirror(s.db) });
    assert.equal(boot.family.state, "converted");
    assert.equal(boot.converted, 1);
    assert.ok(readState().families[PEER_INBOUND_FAMILY]?.converted_at, "the state file has the marker");
    assert.equal(await storedOf(s.db, "peerA"), macToken(PEER_INBOUND_FAMILY, OLD));
  } finally {
    s.close();
  }
});

test("M-B: a failed adoption write still takes the conversion path", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    await addPeer(s.db, "peerA", sha256(OLD));
    await plantPeerMirror(s.db);
    const { adoptMirrorOnlyEra } = await import("../servers/gateway/boot/token-hmac-era-adopt.js");
    const boot = await runPeerTokenHmacBoot({
      db: s.db,
      adoptEra: (family, opts) => adoptMirrorOnlyEra(family, { ...opts, mark: async () => { throw new Error("state write failed (simulated)"); } }),
    });
    assert.equal(boot.converted, 1, "converted, not scanned");
    assert.ok(readState().families[PEER_INBOUND_FAMILY]?.converted_at);
    assert.equal(await storedOf(s.db, "peerA"), macToken(PEER_INBOUND_FAMILY, OLD));
  } finally {
    s.close();
  }
});

test("L-B: a pending snapshot beats adoption: its rows convert and the real count and file are recorded", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    const failing = await runPeerTokenHmacBoot({
      db: s.db, runTransaction: async () => { throw new Error("simulated crash"); },
    });
    assert.equal(failing.family.state, "failed");
    const [snapshot] = snapshotFiles(s.home);
    assert.ok(snapshot);
    await plantPeerMirror(s.db);
    forgetForcedPeerLegacyRefusal();
    const boot = await runPeerTokenHmacBoot({ db: s.db });
    assert.equal(boot.converted, 1);
    const era = readState().families[PEER_INBOUND_FAMILY];
    assert.equal(era.count, 1);
    assert.equal(era.rollback_file, snapshot);
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA");
  } finally {
    s.close();
  }
});

test("L-D: when more than one keyed row verifies for a bearer, the lookup is ambiguous: refused and alarmed (ids only)", async () => {
  const s = scratch();
  try {
    await addPeer(s.db, "peerA", sha256(OLD));
    await runPeerTokenHmacBoot({ db: s.db });
    assert.equal((await validateInstanceToken(s.db, OLD))?.id, "peerA", "positive control");
    // A bot copies the genuine peer's keyed value onto a second trusted row.
    await addPeer(s.db, "peerCopy", macToken(PEER_INBOUND_FAMILY, OLD));
    forgetTokenMacAlarms();
    assert.equal(await validateInstanceToken(s.db, OLD), null, "the genuine bearer is refused too");
    const deadline = Date.now() + 2_000;
    let rows = [];
    while (Date.now() < deadline) {
      // eslint-disable-next-line no-await-in-loop -- a bounded poll
      rows = (await legacyAudits(s.db)).map((r) => JSON.parse(r.details)).filter((d) => d.ambiguous === true);
      if (rows.length) break;
      // eslint-disable-next-line no-await-in-loop -- a bounded poll
      await new Promise((r) => { setTimeout(r, 20); });
    }
    assert.equal(rows.length >= 1, true, "alarmed");
    assert.equal(rows[0].count, 2);
    assert.deepEqual(rows[0].rows.slice().sort(), ["peerA", "peerCopy"]);
    assert.equal(JSON.stringify(rows[0]).includes(macToken(PEER_INBOUND_FAMILY, OLD)), false, "no value in the audit row");
  } finally {
    s.close();
  }
});
