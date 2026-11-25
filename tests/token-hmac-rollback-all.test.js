/**
 * `scripts/token-hmac.mjs --rollback` restores EVERY keyed family (P1b PR 5b) — not just the three
 * `oauth_tokens` ones. A scratch box is converted by the four REAL boot functions (oauth_tokens,
 * settings, paired instances, report links), then the operator CLI runs in a child process.
 *
 * What is pinned:
 *   - every family is back in the form the PREVIOUS release reads (oauth/report/settings rows =
 *     the snapshot's legacy value, file-backed settings = sha256 of the raw token file, peers =
 *     sha256(bearer) from the D4 record — including a peer paired AFTER the conversion), what was
 *     minted after the conversion is removed / NULLed / revoked per family, every era mirror row is
 *     gone, and the state file, key and snapshots are moved aside;
 *   - a RE-UPGRADE then converts everything afresh under a NEW key and every raw credential the test
 *     holds verifies again, with no adoption line and no alarm;
 *   - a legacy value planted after the conversion in each family is removed, never restored;
 *   - a peer whose recorded hash does not reproduce its row is NULLed, not restored from the record;
 *   - a promised snapshot of a non-oauth family that is gone refuses the whole run, changing nothing;
 *   - the interruption seam (`CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT`) still recovers.
 *
 * Every run is in a scratch CROW_HOME; nothing here touches a real instance.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createDbClient } from "../servers/db.js";
import { writeSetting } from "../servers/gateway/dashboard/settings/registry.js";
import {
  forgetForcedSettingsLegacyRefusal, forgetSettingsTokenEvidence, SETTINGS_TOKEN_FAMILIES, settingsTokenRawFile,
} from "../servers/gateway/token-settings.js";
import {
  forgetForcedLegacyRefusal, forgetTokenStoreEvidence, DASHBOARD_SESSION_FAMILY, OAUTH_ACCESS_FAMILY,
  OAUTH_REFRESH_FAMILY,
} from "../servers/gateway/token-store.js";
import {
  forgetTokenMacAlarms, forgetTokenMacKey, macToken, readState, tokenMacKeyPath, tokenMacStatePath,
} from "../servers/shared/token-mac.js";
import { ROLLBACK_PREFIX, runTokenHmacBoot } from "../servers/gateway/boot/token-hmac.js";
import { SETTINGS_ROLLBACK_PREFIX, runSettingsTokenHmacBoot } from "../servers/gateway/boot/token-hmac-settings.js";
import { PEER_ROLLBACK_PREFIX, runPeerTokenHmacBoot } from "../servers/gateway/boot/token-hmac-peers.js";
import { REPORT_LINK_ROLLBACK_PREFIX, runReportLinkTokenHmacBoot } from "../servers/gateway/boot/token-hmac-reports.js";
import {
  PEER_INBOUND_FAMILY, forgetForcedPeerLegacyRefusal, forgetPeerInboundEvidence,
} from "../servers/gateway/peer-inbound-token.js";
import {
  REPORT_LINK_FAMILY, findLinkRowByToken, forgetForcedReportLinkLegacyRefusal, forgetReportLinkEvidence,
} from "../servers/gateway/reports/link-token.js";
import { validateInstanceToken } from "../servers/gateway/instance-registry.js";
import { validateBoardToken, validateLocalToken, validatePhoneToken } from "../servers/gateway/local-token.js";
import { getInboundBearerSha256, setInboundBearerSha256Many, setPeerCreds } from "../servers/shared/peer-credentials.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = join(ROOT, "scripts", "token-hmac.mjs");
const sha256 = (value) => createHash("sha256").update(String(value)).digest("hex");
const INSTANCE_ID = "0123456789abcdef0123456789abcdef";

const SAVED = {};
for (const k of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH"]) SAVED[k] = process.env[k];
const roots = [];
after(() => {
  for (const [k, v] of Object.entries(SAVED)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  for (const root of roots) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

// The raw credentials the test holds.
const RAW = {
  access: "rb-all-oauth-access", refresh: "rb-all-oauth-refresh", session: "rb-all-dashboard-session",
  local: "rb-all-local-token", board: "rb-all-board-token", phone: "rb-all-phone-token-after",
  peerA: "a".repeat(64), peerB: "b".repeat(64), peerC: "c".repeat(64),
  linkA: "rb-all-link-a", linkB: "rb-all-link-b", linkC: "rb-all-link-c",
};
const SIGNING = "s".repeat(64);
const OAUTH_CLIENT = "6c1f2a34-9b7d-4e21-8a55-0d3f9b7c2e11";

/** A fresh scratch instance on the REAL schema, with every in-process cache forgotten. */
function scratch() {
  const root = mkdtempSync(join(tmpdir(), "crow-token-rollback-all-"));
  roots.push(root);
  const dataDir = join(root, "data");
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "instance-id"), INSTANCE_ID, { mode: 0o600 });
  process.env.CROW_HOME = root;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = join(dataDir, "crow.db");
  forgetCaches();
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: process.env, cwd: ROOT, stdio: "pipe", timeout: 120_000,
  });
  const db = createDbClient(process.env.CROW_DB_PATH);
  return {
    root, db, secrets: join(root, "secrets"), close: () => { try { db.close(); } catch { /* closed */ } },
  };
}

function forgetCaches() {
  forgetTokenMacKey();
  forgetTokenMacAlarms();
  forgetTokenStoreEvidence();
  forgetForcedLegacyRefusal();
  forgetSettingsTokenEvidence();
  forgetForcedSettingsLegacyRefusal();
  forgetPeerInboundEvidence();
  forgetForcedPeerLegacyRefusal();
  forgetReportLinkEvidence();
  forgetForcedReportLinkLegacyRefusal();
}

const overrideOf = async (db, family) => (await db.execute({
  sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
  args: [family, INSTANCE_ID],
})).rows[0]?.value ?? null;
const globalOf = async (db, family) => (await db.execute({
  sql: "SELECT value FROM dashboard_settings WHERE key = ?", args: [family],
})).rows[0]?.value ?? null;
const peerHash = async (db, id) => (await db.execute({
  sql: "SELECT auth_token_hash AS h FROM crow_instances WHERE id = ?", args: [id],
})).rows[0]?.h ?? null;
const linkRow = async (db, id) => (await db.execute({
  sql: "SELECT token_hash AS h, revoked_at AS r FROM report_link_tokens WHERE id = ?", args: [id],
})).rows[0] ?? null;
const oauthHas = async (db, token) => (await db.execute({
  sql: "SELECT 1 AS present FROM oauth_tokens WHERE token = ?", args: [token],
})).rows.length > 0;

async function insertOauth(db, token, type, client, scopes) {
  await db.execute({
    sql: `INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at)
          VALUES (?, ?, ?, ?, datetime('now', '+1 hour'))`,
    args: [token, type, client, scopes],
  });
}

async function insertPeer(db, id, stored, status = "active") {
  await db.execute({
    sql: `INSERT INTO crow_instances (id, name, crow_id, gateway_url, tailscale_ip, auth_token_hash, status, trusted)
          VALUES (?, ?, ?, 'http://100.64.5.5:3001', '100.64.5.5', ?, ?, 1)`,
    args: [id, id, id, stored, status],
  });
}

async function insertLink(db, id, stored, { revokedAt = null } = {}) {
  await db.execute({
    sql: `INSERT INTO report_link_tokens
            (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
             approval_nonce, created_at, revoked_at, expires_at)
          VALUES (?, 'rep1', 'rcp1', 'run1', 'snd1', 'art1', 1, ?, 'view', 'nonce1', 1700000000000, ?, 4102444800000)`,
    args: [id, stored, revokedAt],
  });
}

function plantTokenFile(family, raw) {
  const path = settingsTokenRawFile(family);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, raw, { mode: 0o600 });
  return path;
}

/** The four real boots, in the gateway's order. */
async function bootAll(s) {
  const oauth = await runTokenHmacBoot({ db: s.db });
  const settings = await runSettingsTokenHmacBoot({ db: s.db });
  const peers = await runPeerTokenHmacBoot({ db: s.db });
  const links = await runReportLinkTokenHmacBoot({ db: s.db });
  return { oauth, settings, peers, links };
}

/**
 * A box written by the previous release, converted by the four boots, then used for a while:
 * a peer paired, a phone token and a report link minted AFTER the conversion.
 */
async function convertedBox() {
  const s = scratch();
  await insertOauth(s.db, sha256(RAW.access), "access", OAUTH_CLIENT, "mcp:tools");
  await insertOauth(s.db, sha256(RAW.refresh), "refresh", OAUTH_CLIENT, "mcp:tools");
  await insertOauth(s.db, sha256(RAW.session), "access", "dashboard", "dashboard");
  await writeSetting(s.db, "mcp_local_token_hash", sha256(RAW.local), { scope: "local" });
  // A rotated-at-boot family: the boot MINTS a fresh keyed value over it, which no snapshot can name.
  await writeSetting(s.db, "mcp_services_token_hash", sha256("rb-all-old-services"), { scope: "local" });
  plantTokenFile("mcp_board_token_hash", RAW.board);
  await writeSetting(s.db, "mcp_board_token_hash", sha256(RAW.board), { scope: "local" });
  await insertPeer(s.db, "peerA", sha256(RAW.peerA));
  await insertPeer(s.db, "peerB", sha256(RAW.peerB));
  setPeerCreds("peerA", { auth_token: "t".repeat(64), signing_key: SIGNING });
  await insertLink(s.db, "linkA", sha256(RAW.linkA));
  await insertLink(s.db, "linkB", sha256(RAW.linkB), { revokedAt: 1700000001000 });

  const boots = await bootAll(s);
  assert.equal(boots.oauth.key, "ok");
  assert.equal(boots.settings.key, "ok");
  assert.equal(boots.peers.family.state, "converted");
  assert.equal(boots.links.family.state, "converted");

  // After the deploy: a peer pairs (the enroll route / CLI record the D4 hash), a phone token is
  // minted (keyed value + its file), a link is mailed. None of them is in any snapshot.
  await insertPeer(s.db, "peerC", macToken(PEER_INBOUND_FAMILY, RAW.peerC));
  setPeerCreds("peerC", { auth_token: "u".repeat(64), signing_key: SIGNING });
  setInboundBearerSha256Many([{ id: "peerC", sha256: sha256(RAW.peerC) }]);
  plantTokenFile("mcp_phone_token_hash", RAW.phone);
  await writeSetting(s.db, "mcp_phone_token_hash", macToken("mcp_phone_token_hash", RAW.phone), { scope: "local" });
  await insertLink(s.db, "linkC", macToken(REPORT_LINK_FAMILY, RAW.linkC));
  return s;
}

// ─── the CLI ────────────────────────────────────────────────────────────────

function freePort() {
  return new Promise((done, fail) => {
    const srv = createServer((_req, res) => res.end("ok"));
    srv.on("error", fail);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => done(port));
    });
  });
}
let closedPortMemo = null;
const closedPort = () => { closedPortMemo ??= freePort(); return closedPortMemo; };

async function runCli(args, home, extraEnv = {}) {
  const env = {
    ...process.env,
    CROW_HOME: home,
    CROW_DATA_DIR: join(home, "data"),
    CROW_DB_PATH: join(home, "data", "crow.db"),
    CROW_GATEWAY_PORT: String(await closedPort()),
    ...extraEnv,
  };
  delete env.PORT;
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI, ...args], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => done({ code, stdout, stderr }));
  });
}

const snapshotFiles = (s, prefix) => {
  try {
    return readdirSync(s.secrets).filter((n) => n.startsWith(prefix) && n.endsWith(".json"));
  } catch {
    return [];
  }
};
const movedAside = (s, prefix) => {
  try {
    return readdirSync(s.secrets).filter((n) => n.startsWith(prefix) && n.includes(".rolledback-"));
  } catch {
    return [];
  }
};
const ALL_PREFIXES = [ROLLBACK_PREFIX, SETTINGS_ROLLBACK_PREFIX, PEER_ROLLBACK_PREFIX, REPORT_LINK_ROLLBACK_PREFIX];
const mirrorRows = async (db) => {
  const a = (await db.execute({
    sql: "SELECT COUNT(*) AS n FROM dashboard_settings_overrides WHERE key LIKE 'token_hmac_era:%'", args: [],
  })).rows[0].n;
  const b = (await db.execute({
    sql: "SELECT COUNT(*) AS n FROM dashboard_settings WHERE key LIKE 'token_hmac_era:%'", args: [],
  })).rows[0].n;
  return Number(a) + Number(b);
};

// ─── the tests ──────────────────────────────────────────────────────────────

test("one --rollback puts every family back in the previous release's form and moves the evidence aside", async () => {
  const s = await convertedBox();
  try {
    for (const prefix of ALL_PREFIXES) {
      assert.ok(snapshotFiles(s, prefix).length >= 1, `a ${prefix} snapshot was written`);
    }
    // Before: everything keyed.
    assert.match(String(await overrideOf(s.db, "mcp_local_token_hash")), /^h1\./);
    assert.match(String(await peerHash(s.db, "peerA")), /^h1\./);

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.match(out.stdout, /Token conversion rolled back/);
    assert.ok(!/h1\./.test(out.stdout), "no verifier is printed");
    assert.ok(!/[0-9a-f]{64}/.test(out.stdout), "no hash is printed");

    // THE PREVIOUS RELEASE'S LOOKUPS, simulated directly: value === sha256(raw).
    assert.ok(await oauthHas(s.db, sha256(RAW.access)), "oauth:access");
    assert.ok(await oauthHas(s.db, sha256(RAW.refresh)), "oauth:refresh");
    assert.ok(await oauthHas(s.db, sha256(RAW.session)), "dashboard:session");
    assert.equal(await overrideOf(s.db, "mcp_local_token_hash"), sha256(RAW.local), "non-file settings: snapshot legacy");
    assert.equal(await overrideOf(s.db, "mcp_board_token_hash"), sha256(RAW.board), "file-backed: sha256(raw file)");
    assert.equal(await overrideOf(s.db, "mcp_phone_token_hash"), sha256(RAW.phone),
      "a file-backed token minted AFTER the conversion is restored from its file too");
    assert.equal(await peerHash(s.db, "peerA"), sha256(RAW.peerA), "peer from its D4 record");
    assert.equal(await peerHash(s.db, "peerB"), sha256(RAW.peerB), "a peer with no record: its snapshot entry");
    assert.equal(await peerHash(s.db, "peerC"), sha256(RAW.peerC), "a peer paired AFTER the conversion: its D4 record");
    assert.equal((await linkRow(s.db, "linkA")).h, sha256(RAW.linkA), "report link: snapshot legacy");
    assert.equal((await linkRow(s.db, "linkB")).h, sha256(RAW.linkB));
    assert.equal((await linkRow(s.db, "linkB")).r, 1700000001000, "a revoked link stays revoked at its own stamp");

    // Minted after the conversion, with nothing to restore from: removed per family.
    assert.equal(await overrideOf(s.db, "mcp_services_token_hash"), null, "a rotated-at-boot verifier is deleted");
    const afterLink = await linkRow(s.db, "linkC");
    assert.match(afterLink.h, /^h1\./, "the post-conversion link keeps its keyed value (the old release can never match it)");
    assert.ok(Number(afterLink.r) > 0, "and is revoked");
    assert.match(out.stdout, /mcp_services_token_hash.*1 deleted \(minted after conversion\)/);
    assert.match(out.stdout, /report:link\s+2 restored.*1 revoked \(minted after conversion\)/);
    assert.match(out.stdout, /peer:inbound\s+2 restored from the recorded bearer hash, 1 restored from the snapshot/);
    assert.match(out.stdout, /bot defs:.*bot-def-reapprove\.mjs <bot_id> --show/s);

    // The D4 record stays where it was.
    assert.equal(getInboundBearerSha256("peerA"), sha256(RAW.peerA));

    // No keyed value is left in any verifier store but the revoked link.
    for (const family of SETTINGS_TOKEN_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- one operator-run's worth of families
      assert.ok(!String(await overrideOf(s.db, family)).startsWith("h1."), `${family} holds no keyed value`);
    }

    // Every era mirror row is gone (all families, both stores) and the evidence moved aside.
    assert.equal(await mirrorRows(s.db), 0, "no token_hmac_era:* row is left");
    assert.equal(existsSync(tokenMacKeyPath()), false);
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.equal(movedAside(s, "token-hmac.key").length, 1);
    assert.equal(movedAside(s, "token-hmac-state.json").length, 1);
    for (const prefix of ALL_PREFIXES) {
      assert.deepEqual(snapshotFiles(s, prefix), [], `${prefix} snapshots moved aside`);
      assert.ok(movedAside(s, prefix).length >= 1, `${prefix} snapshots kept as .rolledback-`);
    }
  } finally {
    s.close();
  }
});

test("a re-upgrade converts the rolled-back box afresh under a NEW key; every raw credential verifies again, no alarms", async () => {
  const s = await convertedBox();
  try {
    const keyBefore = JSON.parse(readFileSync(tokenMacKeyPath(), "utf8")).id;
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);

    forgetCaches();
    const warnings = [];
    const realWarn = console.warn;
    console.warn = (...args) => { warnings.push(args.join(" ")); };
    let boots;
    try {
      boots = await bootAll(s);
    } finally {
      console.warn = realWarn;
    }
    assert.notEqual(JSON.parse(readFileSync(tokenMacKeyPath(), "utf8")).id, keyBefore, "a NEW key");
    // The revoked post-conversion link still carries an old-key `h1.` value; the oauth boot runs first,
    // creates the new key and scans oauth_tokens alone, so no family reads as "key lost".
    assert.match((await linkRow(s.db, "linkC")).h, /^h1\./, "the revoked post-conversion link is still keyed");
    for (const [name, boot] of Object.entries(boots)) assert.equal(boot.key, "ok", `${name} boot: key ok`);
    assert.equal(boots.oauth.alarms, 0);
    assert.equal(boots.settings.alarms, 0);
    assert.equal(boots.peers.alarms, 0);
    assert.equal(boots.links.alarms, 0);
    assert.ok(!warnings.some((w) => /era was recorded only in the database|old-style/.test(w)),
      `no adoption line and no alarm: ${warnings.join(" | ")}`);
    assert.ok(readState().families[PEER_INBOUND_FAMILY]?.converted_at, "converted again");

    // The raw credentials the test holds all verify under the new key.
    assert.equal(await validateLocalToken(s.db, RAW.local), true);
    assert.equal(await validateBoardToken(s.db, RAW.board), true);
    assert.equal(await validatePhoneToken(s.db, RAW.phone), true);
    for (const [bearer, id] of [[RAW.peerA, "peerA"], [RAW.peerB, "peerB"], [RAW.peerC, "peerC"]]) {
      // eslint-disable-next-line no-await-in-loop -- three peers
      assert.equal((await validateInstanceToken(s.db, bearer))?.id, id, `${id} authenticates again`);
    }
    for (const [raw, id] of [[RAW.linkA, "linkA"], [RAW.linkB, "linkB"]]) {
      // eslint-disable-next-line no-await-in-loop -- two links
      assert.equal((await findLinkRowByToken(s.db, raw, { columns: "id, token_hash" }))?.id, id, `${id} resolves again`);
    }
    for (const [raw, type, family] of [
      [RAW.access, "access", OAUTH_ACCESS_FAMILY], [RAW.refresh, "refresh", OAUTH_REFRESH_FAMILY],
      [RAW.session, "access", DASHBOARD_SESSION_FAMILY],
    ]) {
      // eslint-disable-next-line no-await-in-loop -- three rows
      assert.ok(await oauthHas(s.db, macToken(family, raw)), `${family} (${type}) converted under the new key`);
    }
  } finally {
    s.close();
  }
});

test("a legacy value planted after the conversion, in any family, is removed and never restored", async () => {
  const s = await convertedBox();
  try {
    // oauth: a bare row. settings: a bare override on a family with a snapshot value and one on a
    // rotated family, a GLOBAL row. peers: bare rows, one uppercase. report links: a bare row, and one
    // sitting on linkA's own snapshot value (which the restore would otherwise collide with).
    await insertOauth(s.db, sha256("forged-oauth"), "access", "bot-client", "mcp:tools");
    await s.db.execute({
      sql: "UPDATE dashboard_settings_overrides SET value = ? WHERE key = ? AND instance_id = ?",
      args: [sha256("forged-local"), "mcp_local_token_hash", INSTANCE_ID],
    });
    await s.db.execute({
      sql: "UPDATE dashboard_settings_overrides SET value = ? WHERE key = ? AND instance_id = ?",
      args: [sha256("forged-memory"), "mcp_memory_bot_token_hash", INSTANCE_ID],
    });
    await s.db.execute({
      sql: "INSERT INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: ["mcp_artifacts_token_hash", sha256("forged-global")],
    });
    await insertPeer(s.db, "peerD", sha256("forged-peer"));
    await insertPeer(s.db, "peerE", sha256("forged-peer-2").toUpperCase());
    await insertLink(s.db, "linkForged", sha256("forged-link"));
    await insertLink(s.db, "linkClash", sha256(RAW.linkA));

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);

    assert.equal(await oauthHas(s.db, sha256("forged-oauth")), false, "oauth forgery removed");
    assert.equal(await overrideOf(s.db, "mcp_local_token_hash"), null, "a forged settings value is removed, not restored");
    assert.equal(await overrideOf(s.db, "mcp_memory_bot_token_hash"), null);
    assert.equal(await globalOf(s.db, "mcp_artifacts_token_hash"), null, "a global row of a converted family is removed");
    assert.equal(await peerHash(s.db, "peerD"), null);
    assert.equal(await peerHash(s.db, "peerE"), null, "uppercase 64-hex counts as legacy");
    const forged = await linkRow(s.db, "linkForged");
    assert.ok(Number(forged.r) > 0, "a forged link is revoked");
    assert.ok(!/^[0-9a-f]{64}$/i.test(forged.h), "and no longer holds a usable value");
    assert.equal((await linkRow(s.db, "linkA")).h, sha256(RAW.linkA), "the genuine link took its value back");
    assert.ok(Number((await linkRow(s.db, "linkClash")).r) > 0, "the forgery on the snapshot's value is revoked");
    assert.match(out.stdout, /peer:inbound.*2 removed/);
    assert.match(out.stdout, /report:link.*2 removed/);
    // The genuine rows survived next to the forgeries.
    assert.equal(await peerHash(s.db, "peerA"), sha256(RAW.peerA));
    assert.equal(await overrideOf(s.db, "mcp_board_token_hash"), sha256(RAW.board));
  } finally {
    s.close();
  }
});

test("a peer whose recorded hash does not reproduce its row is NULLed, not restored from the record", async () => {
  const s = await convertedBox();
  try {
    // peerA's row now holds an h1 value of something else: the record must not be written over it.
    await s.db.execute({
      sql: "UPDATE crow_instances SET auth_token_hash = ? WHERE id = 'peerA'",
      args: [macToken(PEER_INBOUND_FAMILY, "some-other-bearer")],
    });
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await peerHash(s.db, "peerA"), null, "NULL: that peer re-pairs");
    assert.equal(await peerHash(s.db, "peerB"), sha256(RAW.peerB), "its siblings are restored");
    assert.equal(await peerHash(s.db, "peerC"), sha256(RAW.peerC));
    assert.match(out.stdout, /peer:inbound.*1 set to NULL/);
    assert.equal(getInboundBearerSha256("peerA"), sha256(RAW.peerA), "the record itself is left in place");
  } finally {
    s.close();
  }
});

test("a file-backed verifier whose token file is missing is deleted, not guessed", async () => {
  const s = await convertedBox();
  try {
    unlinkSync(settingsTokenRawFile("mcp_board_token_hash"));
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await overrideOf(s.db, "mcp_board_token_hash"), null);
    assert.match(out.stdout, /mcp_board_token_hash.*1 deleted \(token file missing/);
    assert.match(out.stdout, /re-ensured by the previous release's own boot/);
    assert.equal(await overrideOf(s.db, "mcp_phone_token_hash"), sha256(RAW.phone), "the other file-backed family is restored");
  } finally {
    s.close();
  }
});

test("a promised snapshot of a non-oauth family that is gone refuses the whole run and changes nothing", async () => {
  for (const prefix of [SETTINGS_ROLLBACK_PREFIX, PEER_ROLLBACK_PREFIX, REPORT_LINK_ROLLBACK_PREFIX]) {
    const s = await convertedBox();
    try {
      const gone = snapshotFiles(s, prefix);
      assert.ok(gone.length >= 1);
      for (const name of gone) unlinkSync(join(s.secrets, name));
      const peerBefore = await peerHash(s.db, "peerA");
      const out = await runCli(["--rollback", "--yes"], s.root);
      assert.equal(out.code, 3, `${prefix}: ${out.stdout}${out.stderr}`);
      assert.match(out.stderr, /still records/);
      assert.match(out.stderr, /Nothing was changed/);
      assert.equal(await peerHash(s.db, "peerA"), peerBefore, "no row was touched");
      assert.match(String(await overrideOf(s.db, "mcp_local_token_hash")), /^h1\./);
      assert.ok(existsSync(tokenMacKeyPath()), "the key is still in place");
      assert.ok(existsSync(tokenMacStatePath()), "the state is still in place");
    } finally {
      s.close();
    }
  }
});

test("a home with no instance id is refused before anything changes", async () => {
  const s = await convertedBox();
  try {
    unlinkSync(join(s.root, "data", "instance-id"));
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 1, out.stdout + out.stderr);
    assert.match(out.stderr, /No instance id/);
    assert.match(String(await overrideOf(s.db, "mcp_local_token_hash")), /^h1\./);
    assert.ok(existsSync(tokenMacKeyPath()));
  } finally {
    s.close();
  }
});

test("interruption after the commit: everything is already restored, files stay, and the re-run finishes without deleting anything", async () => {
  const s = await convertedBox();
  try {
    const crashed = await runCli(["--rollback", "--yes"], s.root, {
      CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT: "commit",
    });
    assert.equal(crashed.code, 7, crashed.stdout + crashed.stderr);
    assert.equal(await overrideOf(s.db, "mcp_local_token_hash"), sha256(RAW.local));
    assert.equal(await peerHash(s.db, "peerA"), sha256(RAW.peerA));
    assert.equal((await linkRow(s.db, "linkA")).h, sha256(RAW.linkA));
    assert.equal(await mirrorRows(s.db), 0, "the mirror went with the restored rows");
    assert.ok(existsSync(tokenMacKeyPath()) && existsSync(tokenMacStatePath()), "not one file moved");
    for (const prefix of ALL_PREFIXES) assert.ok(snapshotFiles(s, prefix).length >= 1, `${prefix} still in place`);

    const again = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(again.code, 0, again.stdout + again.stderr);
    assert.equal(await overrideOf(s.db, "mcp_local_token_hash"), sha256(RAW.local), "the re-run spared the restored row");
    assert.equal(await overrideOf(s.db, "mcp_board_token_hash"), sha256(RAW.board));
    assert.equal(await peerHash(s.db, "peerA"), sha256(RAW.peerA));
    assert.equal(await peerHash(s.db, "peerB"), sha256(RAW.peerB));
    assert.equal((await linkRow(s.db, "linkA")).h, sha256(RAW.linkA));
    assert.match(again.stdout, /report:link\s+2 restored, 0 gone/);
    assert.match(again.stdout, /peer:inbound\s+2 restored from the recorded bearer hash, 1 restored from the snapshot/);
    assert.equal(existsSync(tokenMacKeyPath()), false, "the re-run finished the moves");
    for (const prefix of ALL_PREFIXES) assert.deepEqual(snapshotFiles(s, prefix), []);
  } finally {
    s.close();
  }
});

test("interruption after the state file moved: the key is still there and a re-run completes", async () => {
  const s = await convertedBox();
  try {
    const crashed = await runCli(["--rollback", "--yes"], s.root, {
      CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT: "state",
    });
    assert.equal(crashed.code, 7, crashed.stdout + crashed.stderr);
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.ok(existsSync(tokenMacKeyPath()), "a key file answers for itself");
    assert.equal(await peerHash(s.db, "peerB"), sha256(RAW.peerB));
    for (const prefix of ALL_PREFIXES) assert.ok(snapshotFiles(s, prefix).length >= 1);
    const again = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(again.code, 0, again.stdout + again.stderr);
    for (const prefix of ALL_PREFIXES) assert.deepEqual(snapshotFiles(s, prefix), []);
    assert.equal(await peerHash(s.db, "peerB"), sha256(RAW.peerB));
  } finally {
    s.close();
  }
});

test("a --reset box (every family re-marked converted, no rollback files) rolls back without refusing", async () => {
  const s = await convertedBox();
  try {
    const reset = await runCli(["--reset", "--yes"], s.root);
    assert.equal(reset.code, 0, reset.stdout + reset.stderr);
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await mirrorRows(s.db), 0);
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.ok(!/h1\./.test(out.stdout));
  } finally {
    s.close();
  }
});

// ─── a replanted legacy value is never "restored" (a snapshot value is not proof of genuineness) ───

const journalFiles = (s) => {
  try {
    return readdirSync(s.secrets).filter((n) => n.startsWith("token-hmac-rbjournal-") && n.endsWith(".json"));
  } catch {
    return [];
  }
};

test("REPLANT oauth session: a logged-out session whose old sha256 a writer puts back is removed, not restored", async () => {
  const s = await convertedBox();
  try {
    // The operator logs the session out (its keyed row is deleted); a writer holding the old hash puts it back.
    await s.db.execute({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [macToken(DASHBOARD_SESSION_FAMILY, RAW.session)] });
    await insertOauth(s.db, sha256(RAW.session), "access", "dashboard", "dashboard");
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await oauthHas(s.db, sha256(RAW.session)), false, "the replanted session is gone");
    assert.match(out.stdout, /dashboard:session\s+0 restored, 1 gone.*1 removed/);
    assert.ok(await oauthHas(s.db, sha256(RAW.access)), "a genuine row beside it is restored");
  } finally {
    s.close();
  }
});

test("REPLANT settings (non-file): a regenerated local token whose old sha256 is written back is removed, not restored", async () => {
  const s = await convertedBox();
  try {
    await writeSetting(s.db, "mcp_local_token_hash", macToken("mcp_local_token_hash", "regenerated"), { scope: "local" });
    await s.db.execute({
      sql: "UPDATE dashboard_settings_overrides SET value = ? WHERE key = ? AND instance_id = ?",
      args: [sha256(RAW.local), "mcp_local_token_hash", INSTANCE_ID],
    });
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await overrideOf(s.db, "mcp_local_token_hash"), null, "the old value is not left for the previous release");
    assert.match(out.stdout, /mcp_local_token_hash\s+0 restored, 1 gone, 0 deleted.*1 removed/);
  } finally {
    s.close();
  }
});

test("REPLANT settings (file-backed): sha256(file) written over a deleted verifier is removed unless this rollback restored it", async () => {
  const s = await convertedBox();
  try {
    await s.db.execute({
      sql: "DELETE FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
      args: ["mcp_board_token_hash", INSTANCE_ID],
    });
    await s.db.execute({
      sql: "INSERT INTO dashboard_settings_overrides (key, instance_id, value) VALUES (?, ?, ?)",
      args: ["mcp_board_token_hash", INSTANCE_ID, sha256(RAW.board)],
    });
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await overrideOf(s.db, "mcp_board_token_hash"), null);
    assert.match(out.stdout, /mcp_board_token_hash\s+0 restored as sha256 of the token file.*1 removed/);
    assert.equal(await overrideOf(s.db, "mcp_phone_token_hash"), sha256(RAW.phone), "a keyed file-backed row is still restored");
  } finally {
    s.close();
  }
});

test("REPLANT peer: a revoked pairing whose recorded hash is written back is NULLed, not restored", async () => {
  const s = await convertedBox();
  try {
    await s.db.execute({
      sql: "UPDATE crow_instances SET status = 'revoked', auth_token_hash = ? WHERE id = 'peerA'",
      args: [sha256(RAW.peerA)],
    });
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await peerHash(s.db, "peerA"), null);
    assert.match(out.stdout, /peer:inbound.*1 removed/);
    assert.equal(await peerHash(s.db, "peerC"), sha256(RAW.peerC), "genuine pairings are restored");
  } finally {
    s.close();
  }
});

test("REPLANT report link: a deleted link whose old sha256 is re-inserted under the same id is revoked, not restored", async () => {
  const s = await convertedBox();
  try {
    await s.db.execute({ sql: "DELETE FROM report_link_tokens WHERE id = 'linkA'", args: [] });
    await insertLink(s.db, "linkA", sha256(RAW.linkA));
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    const row = await linkRow(s.db, "linkA");
    assert.ok(!/^[0-9a-f]{64}$/i.test(row.h), "no usable legacy value is left");
    assert.ok(Number(row.r) > 0, "and the row is revoked");
    assert.match(out.stdout, /report:link\s+1 restored, 1 gone.*1 removed/);
    assert.equal((await linkRow(s.db, "linkB")).h, sha256(RAW.linkB), "the other genuine link is restored");
  } finally {
    s.close();
  }
});

test("JOURNAL: an interrupted run's re-run spares exactly the journal's entries and sweeps everything else", async () => {
  const s = await convertedBox();
  try {
    const crashed = await runCli(["--rollback", "--yes"], s.root, {
      CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT: "commit",
    });
    assert.equal(crashed.code, 7, crashed.stdout + crashed.stderr);
    assert.equal(journalFiles(s).length, 1, "the journal was written (0600) before the transaction");
    assert.equal(statSync(join(s.secrets, journalFiles(s)[0])).mode & 0o777, 0o600);
    // While stopped, a writer adds bare values that no run restored.
    await insertOauth(s.db, sha256("planted-after-crash"), "access", "bot", "mcp:tools");
    await insertPeer(s.db, "peerZ", sha256("planted-peer"));
    const again = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(again.code, 0, again.stdout + again.stderr);
    assert.ok(await oauthHas(s.db, sha256(RAW.access)), "journalled oauth row spared");
    assert.equal(await overrideOf(s.db, "mcp_board_token_hash"), sha256(RAW.board), "journalled file-backed value spared");
    assert.equal(await peerHash(s.db, "peerA"), sha256(RAW.peerA), "journalled peer spared");
    assert.equal((await linkRow(s.db, "linkA")).h, sha256(RAW.linkA), "journalled link spared");
    assert.equal(await oauthHas(s.db, sha256("planted-after-crash")), false, "an unjournalled bare row is swept");
    assert.equal(await peerHash(s.db, "peerZ"), null);
    assert.match(again.stdout, /report:link\s+2 restored, 0 gone/);
    assert.deepEqual(journalFiles(s), [], "the journal moved aside with the snapshots");
    assert.ok(readdirSync(s.secrets).some((n) => n.startsWith("token-hmac-rbjournal-") && n.includes(".rolledback-")));
  } finally {
    s.close();
  }
});

test("JOURNAL: a re-run with NO journal sweeps every bare row in a converted family", async () => {
  const s = await convertedBox();
  try {
    const crashed = await runCli(["--rollback", "--yes"], s.root, {
      CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT: "commit",
    });
    assert.equal(crashed.code, 7, crashed.stdout + crashed.stderr);
    for (const name of journalFiles(s)) unlinkSync(join(s.secrets, name));
    const again = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(again.code, 0, again.stdout + again.stderr);
    assert.equal(await oauthHas(s.db, sha256(RAW.access)), false);
    assert.equal(await overrideOf(s.db, "mcp_board_token_hash"), null);
    assert.equal(await peerHash(s.db, "peerA"), null);
    assert.ok(!/^[0-9a-f]{64}$/i.test((await linkRow(s.db, "linkA")).h));
    assert.match(again.stdout, /oauth:access\s+0 restored.*1 removed/);
  } finally {
    s.close();
  }
});

// ─── the journal exists only after the commit ───────────────────────────────

test("a crash BEFORE the commit leaves no journal: a later rollback removes what was replanted meanwhile", async () => {
  const s = await convertedBox();
  try {
    const crashed = await runCli(["--rollback", "--yes"], s.root, {
      CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT: "precommit",
    });
    assert.equal(crashed.code, 7, crashed.stdout + crashed.stderr);
    assert.deepEqual(journalFiles(s), [], "no journal: nothing was restored by a run that did not commit");
    assert.match(String(await overrideOf(s.db, "mcp_local_token_hash")), /^h1\./, "the transaction rolled back");
    assert.ok(existsSync(tokenMacKeyPath()) && existsSync(tokenMacStatePath()), "no file moved");

    // The keyed release runs again: the operator logs the session out and rotates the local token; a
    // writer holding the old hashes puts them back.
    await s.db.execute({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [macToken(DASHBOARD_SESSION_FAMILY, RAW.session)] });
    await insertOauth(s.db, sha256(RAW.session), "access", "dashboard", "dashboard");
    await s.db.execute({
      sql: "UPDATE dashboard_settings_overrides SET value = ? WHERE key = ? AND instance_id = ?",
      args: [sha256(RAW.local), "mcp_local_token_hash", INSTANCE_ID],
    });
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await oauthHas(s.db, sha256(RAW.session)), false, "the replanted session is removed");
    assert.equal(await overrideOf(s.db, "mcp_local_token_hash"), null, "the replanted local token is removed");
    assert.ok(await oauthHas(s.db, sha256(RAW.access)), "genuine rows are still restored");
  } finally {
    s.close();
  }
});

test("a journal under another key is ignored and moved aside, with any leftover temp journal", async () => {
  const s = await convertedBox();
  try {
    const foreign = "token-hmac-rbjournal-2026-01-01T00-00-00-000Z.json";
    writeFileSync(join(s.secrets, foreign), JSON.stringify({
      v: 1, key_id: "ffffffffffffffff", created_at: "2026-01-01T00:00:00.000Z",
      families: { [DASHBOARD_SESSION_FAMILY]: [sha256(RAW.session)] },
    }), { mode: 0o600 });
    const leftover = "token-hmac-rbjournal-2026-01-02T00-00-00-000Z.json.tmp-1-abcd";
    writeFileSync(join(s.secrets, leftover), "{", { mode: 0o600 });
    await s.db.execute({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [macToken(DASHBOARD_SESSION_FAMILY, RAW.session)] });
    await insertOauth(s.db, sha256(RAW.session), "access", "dashboard", "dashboard");
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await oauthHas(s.db, sha256(RAW.session)), false, "a foreign journal spares nothing");
    assert.ok(!existsSync(join(s.secrets, foreign)) && !existsSync(join(s.secrets, leftover)));
    const aside = readdirSync(s.secrets).filter((n) => n.startsWith("token-hmac-rbjournal-") && n.includes(".rolledback-"));
    assert.ok(aside.some((n) => n.includes("2026-01-01")), "the foreign journal was moved aside");
    assert.ok(aside.some((n) => n.includes("2026-01-02")), "the temp leftover was moved aside");
  } finally {
    s.close();
  }
});

test("a journal that does not parse, or carries an unknown version, refuses the run (exit 3) and changes nothing", async () => {
  for (const content of ["{not json", JSON.stringify({ v: 2, key_id: "x", families: {} })]) {
    const s = await convertedBox();
    try {
      writeFileSync(join(s.secrets, "token-hmac-rbjournal-2026-01-01T00-00-00-000Z.json"), content, { mode: 0o600 });
      const out = await runCli(["--rollback", "--yes"], s.root);
      assert.equal(out.code, 3, out.stdout + out.stderr);
      assert.match(out.stderr, /rollback journal/);
      assert.match(out.stderr, /Nothing was changed/);
      assert.match(String(await overrideOf(s.db, "mcp_local_token_hash")), /^h1\./);
      assert.match(String(await peerHash(s.db, "peerA")), /^h1\./);
      assert.ok(existsSync(tokenMacKeyPath()) && existsSync(tokenMacStatePath()));
    } finally {
      s.close();
    }
  }
});
