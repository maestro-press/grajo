/**
 * Keyed verifiers for `oauth_tokens` — PR 2 of the keyed-token-hashes design (§8).
 *
 * What these tests pin, in the design's own terms:
 *   - THE FORGERY (lane B F1/F3, §6.1): after the boot conversion, a "bot" that can write
 *     crow.db only inserts `sha256(own token)` into an access row, a dashboard-session row
 *     and a refresh row; every one of the three validators refuses it and the legacy alarm
 *     is audited;
 *   - THE COPY ATTACK (§2.3, §6.2): a real `h1.` value taken from a dashboard session does
 *     not verify as an OAuth access token, and the reverse;
 *   - REAL FLOWS still work: password login, 2FA completion, OAuth code exchange, refresh,
 *     access validation and logout — all of which now store the keyed form;
 *   - the CONVERSION (§3.2): legacy rows convert offline at boot, keep authenticating with
 *     their raw tokens, write a 0600 rollback snapshot, and a second boot never re-converts
 *     (so a post-conversion sha256 row is not laundered — it is refused and alarmed);
 *   - the DEPLOY-DAY ROLLBACK (`node scripts/token-hmac.mjs --rollback --yes`): the snapshot
 *     rows go back to their pre-conversion sha256 form (the previous release's lookup finds
 *     them again), tokens minted after the conversion are revoked, the key / era state /
 *     snapshots are moved aside (`*.rolledback-*`, 0600 kept, never deleted) and the three
 *     `token_hmac_era:*` mirror rows are DELETED — which is what lets a re-deploy convert the
 *     restored rows again, under a fresh key, instead of refusing them as forgeries; plus its
 *     refusals, each of which changes NOTHING: a live gateway (exit 2) and a missing key (exit 3);
 *   - the ROLLBACK'S OWN HARDENING: the mirror deletes commit WITH the restored rows, so an
 *     interruption after the commit leaves every file in place and a re-run completes (and never
 *     deletes the rows it already restored); the moves go state → key → snapshots, so a box
 *     interrupted between them still boots normally (a key file answers for itself, so it is not
 *     "key lost", and the restored rows convert again under that same key); a post-conversion
 *     legacy write — a forgery the alarm refused — is removed, including one sitting on a
 *     snapshot's own value (the primary-key collision the restore would otherwise hit); a
 *     snapshot written under ANOTHER key is ignored and reported instead of refusing the run, and
 *     a post-reset box (nothing to restore) proceeds and retires the era — after sweeping a
 *     post-conversion legacy row it has no snapshot to spare (counted as removed); a DB without
 *     the overrides table still loses its global era rows;
 *   - the CRASH RE-RUN rule: with a pending snapshot and no era, only the snapshot's rows
 *     convert; any other legacy row stays and alarms;
 *   - the RESET's laundering window (§M1): a reset leaves the three families CONVERTED in both
 *     copies and never clears an era at any point, so a legacy row a bot inserts before the next
 *     boot is refused and alarmed instead of converted, and a sibling family's era set before the
 *     reset is still there;
 *   - a FAILING family (§M2): a throwing transaction is retried, that family refuses legacy
 *     values for the rest of the process, its siblings still convert, and the next boot resumes
 *     and converts it; an unwritable `secrets/` still only SKIPS the family (§2.6) — legacy stays
 *     accepted there — and a family that skips is NOT treated as a failure;
 *   - the HEALTH PROBE (§L5): the operator reset refuses to run while something answers `/health`
 *     on the gateway's own port and bind (`gatewayListenPort()`/`gatewayListenHost()`, not a
 *     second copy of their precedence), and `--force-while-running` is the override;
 *   - the COPY attack inside the refresh family (access↔refresh, session→refresh), and the forged
 *     legacy SESSION row refused by the three real readers (`viewerOf`, `isLocalPasswordSessionOn`,
 *     `sessionCreatedAt`);
 *   - KEY LOST (§2.6): a boot after the key vanished logs the recovery line, still returns
 *     (the gateway starts), and every validation refuses; `scripts/token-hmac.mjs --reset
 *     --yes` then makes a new key, revokes every row, and password login works again;
 *   - STATIC guards: no private sha256 `hashToken` in the consolidated readers, no
 *     hard-coded `converted:` flag anywhere in `servers/`, the boot runs before listen, and
 *     `resetFamiliesForOperator` is reachable only from `servers/shared/token-mac.js` and is
 *     NEVER called by the operator CLI (which clears no era).
 *
 * Everything runs in a scratch CROW_HOME against real gateway modules; nothing here touches
 * a real instance, and no forgery is ever attempted outside this scratch DB.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, networkInterfaces } from "node:os";
import { join, relative } from "node:path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";

import { createDbClient } from "../servers/db.js";
import {
  forgetTokenMacAlarms, forgetTokenMacKey, ensureKey, macFromLegacy, macToken, markConverted, readState,
  tokenMacKeyPath, tokenMacStatePath, verifyStored,
} from "../servers/shared/token-mac.js";
import {
  DASHBOARD_SESSION_FAMILY, OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, forgetForcedLegacyRefusal,
  forgetTokenStoreEvidence, mintStoreToken,
} from "../servers/gateway/token-store.js";
import { ROLLBACK_PREFIX, runTokenHmacBoot } from "../servers/gateway/boot/token-hmac.js";
import { gatewayListenPort } from "../servers/gateway/listen-port.js";
import { createOAuthProvider } from "../servers/gateway/auth.js";
import {
  attemptLogin, complete2faLogin, destroySession, sessionAuth, setPassword, verifySession,
} from "../servers/gateway/dashboard/auth.js";
import { isLocalPasswordSessionOn } from "../servers/gateway/dashboard/local-session.js";
import { viewerOf } from "../servers/gateway/dashboard/panels/project-reports.js";
import { sessionCreatedAt } from "../servers/gateway/dashboard/shell/mode.js";

const ROOT = new URL("..", import.meta.url).pathname;
const CLI = join(ROOT, "scripts", "token-hmac.mjs");
const sha256Hex = (s) => createHash("sha256").update(s).digest("hex");

const SAVED = {};
for (const k of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH"]) SAVED[k] = process.env[k];
after(() => {
  for (const [k, v] of Object.entries(SAVED)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

const SCHEMA = `
  CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY, metadata TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE oauth_tokens (
    token TEXT PRIMARY KEY,
    token_type TEXT NOT NULL CHECK(token_type IN ('access', 'refresh')),
    client_id TEXT NOT NULL,
    scopes TEXT DEFAULT '',
    resource TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')));
  CREATE INDEX idx_tokens_client ON oauth_tokens(client_id);
  CREATE INDEX idx_tokens_type ON oauth_tokens(token_type);
  CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, actor TEXT,
    ip_address TEXT, details TEXT, created_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE dashboard_settings (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE dashboard_settings_overrides (
    key TEXT NOT NULL, instance_id TEXT NOT NULL, value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')), lamport_ts INTEGER DEFAULT 0,
    PRIMARY KEY (key, instance_id));
`;

const scratchRoots = [];
after(() => {
  for (const root of scratchRoots) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** A fresh scratch instance: env, tables, and a forgotten in-process key/alarm/evidence cache. */
function scratch(seed = null) {
  const root = mkdtempSync(join(tmpdir(), "crow-token-mac-oauth-"));
  scratchRoots.push(root);
  process.env.CROW_HOME = root;
  process.env.CROW_DATA_DIR = join(root, "data");
  process.env.CROW_DB_PATH = join(root, "data", "crow.db");
  mkdirSync(process.env.CROW_DATA_DIR, { recursive: true });
  forgetTokenMacKey();
  forgetTokenMacAlarms();
  forgetTokenStoreEvidence();
  forgetForcedLegacyRefusal(); // the §M2 process-local override is per-process, like the eras
  const raw = new Database(process.env.CROW_DB_PATH);
  try {
    raw.exec(SCHEMA);
    if (seed) seed(raw);
  } finally {
    raw.close();
  }
  const db = createDbClient(process.env.CROW_DB_PATH);
  return {
    root,
    db,
    secrets: join(root, "secrets"),
    close: () => { try { db.close(); } catch { /* closed */ } },
  };
}

function seedLegacy(spec) {
  return (raw) => {
    for (const row of spec) {
      raw.prepare(
        `INSERT INTO oauth_tokens (token, token_type, client_id, scopes, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, datetime('now', ?))`,
      ).run(sha256Hex(row.token), row.type || "access", row.client, row.scopes || "",
        row.resource || null, row.expires || "+1 hour");
    }
  };
}

/** The stored verifier for a raw token, whichever form holds it (keyed first, then legacy). */
async function storedFor(db, raw, family) {
  const candidates = [];
  try { candidates.push(macToken(family, raw)); } catch { /* key lost: legacy only */ }
  candidates.push(sha256Hex(raw));
  for (const candidate of candidates) {
    // eslint-disable-next-line no-await-in-loop -- at most two candidates
    const { rows } = await db.execute({ sql: "SELECT token FROM oauth_tokens WHERE token = ?", args: [candidate] });
    if (rows[0]) return rows[0].token;
  }
  return null;
}

async function rowCount(db) {
  const { rows } = await db.execute({ sql: "SELECT COUNT(*) AS n FROM oauth_tokens", args: [] });
  return Number(rows[0]?.n ?? 0);
}

async function settingsCount(db, sql) {
  const { rows } = await db.execute({ sql, args: [] });
  return Number(rows[0]?.n ?? 0);
}

const auditRows = async (db, type) => (await db.execute({
  sql: "SELECT details FROM audit_log WHERE event_type = ?", args: [type],
})).rows;

const rollbackFiles = (s) => {
  try {
    return readdirSync(s.secrets).filter((n) => n.startsWith(ROLLBACK_PREFIX) && n.endsWith(".json"));
  } catch {
    return [];
  }
};

const insertToken = (db, { token, type = "access", client, scopes = "", expires = "+1 hour" }) =>
  db.execute({
    sql: `INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at)
          VALUES (?, ?, ?, ?, datetime('now', ?))`,
    args: [token, type, client, scopes, expires],
  });

// ─── conversion (§3.2) ────────────────────────────────────────────────────

const ACCESS_RAW = "legacy-oauth-access-raw";
const REFRESH_RAW = "legacy-oauth-refresh-raw";
const SESSION_RAW = "legacy-dashboard-session-raw";
const OAUTH_CLIENT = "6c1f2a34-9b7d-4e21-8a55-0d3f9b7c2e11";

test("the boot converts every legacy family offline, keeps the raw tokens working, and snapshots 0600", async () => {
  const s = scratch(seedLegacy([
    { token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: REFRESH_RAW, type: "refresh", client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: SESSION_RAW, client: "dashboard", scopes: "dashboard" },
  ]));
  try {
    const provider = createOAuthProvider(process.env.CROW_DB_PATH);
    try {
      const boot = await runTokenHmacBoot({ db: s.db });
      assert.equal(boot.key, "ok");
      assert.equal(boot.alarms, 0);

      // Every row moved to the keyed form, and the three families are recorded.
      assert.match(await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY), /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/);
      assert.match(await storedFor(s.db, REFRESH_RAW, OAUTH_REFRESH_FAMILY), /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/);
      assert.match(await storedFor(s.db, SESSION_RAW, DASHBOARD_SESSION_FAMILY), /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/);
      const state = readState();
      for (const family of [OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, DASHBOARD_SESSION_FAMILY]) {
        assert.ok(state.families[family]?.converted_at, `${family} is marked converted in secrets`);
        // The mirror is a LOCAL-scope setting (§2.5): the override table, this instance.
        const mirror = (await s.db.execute({
          sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ?", args: [`token_hmac_era:${family}`],
        })).rows[0];
        assert.ok(mirror?.value, `${family} is mirrored into the DB`);
      }

      // The raw tokens still authenticate — the conversion needs no raw secret.
      const access = await provider.verifyAccessToken(ACCESS_RAW);
      assert.equal(access.clientId, OAUTH_CLIENT);
      assert.deepEqual(access.scopes, ["mcp:tools"]);
      const refreshed = await provider.exchangeRefreshToken({ client_id: OAUTH_CLIENT }, REFRESH_RAW);
      assert.ok(refreshed.access_token);
      assert.equal((await provider.verifyAccessToken(refreshed.access_token)).clientId, OAUTH_CLIENT);
      assert.equal(await verifySession(SESSION_RAW), true);
      assert.equal((await sessionAuth(SESSION_RAW)).valid, true);

      // One snapshot per family, 0600, carrying the pre-conversion values (hashes, not tokens).
      const files = rollbackFiles(s);
      assert.equal(files.length, 3, "one rollback snapshot per converted family");
      for (const name of files) {
        const path = join(s.secrets, name);
        assert.equal(statSync(path).mode & 0o777, 0o600, `${name} is 0600`);
        const body = JSON.parse(readFileSync(path, "utf8"));
        assert.equal(body.v, 1);
        assert.ok([OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, DASHBOARD_SESSION_FAMILY].includes(body.family));
        for (const row of body.rows) assert.match(row.token, /^[0-9a-f]{64}$/);
      }
      const accessSnap = JSON.parse(readFileSync(
        join(s.secrets, files.find((n) => n.includes("oauth-access"))), "utf8",
      ));
      assert.deepEqual(accessSnap.rows.map((r) => r.token), [sha256Hex(ACCESS_RAW)]);

      // A second boot does not convert again, and a post-conversion sha256 write is NOT
      // laundered: it stays in the old form, alarms, and never authenticates.
      const before = readState();
      const forgeRaw = "forged-after-conversion";
      await insertToken(s.db, { token: sha256Hex(forgeRaw), client: "bot-client", scopes: "mcp:tools", expires: "+30 days" });
      forgetTokenMacAlarms();
      const second = await runTokenHmacBoot({ db: s.db });
      assert.equal(second.families.find((f) => f.family === OAUTH_ACCESS_FAMILY).count, undefined);
      assert.equal(readState().families[OAUTH_ACCESS_FAMILY].converted_at,
        before.families[OAUTH_ACCESS_FAMILY].converted_at);
      assert.equal(await storedFor(s.db, forgeRaw, OAUTH_ACCESS_FAMILY), sha256Hex(forgeRaw), "the post-conversion write was not converted");
      assert.ok(second.alarms >= 1, "the boot scan reported it");
      await assert.rejects(() => provider.verifyAccessToken(forgeRaw));
      assert.ok((await auditRows(s.db, "token_legacy_form")).length >= 1);
    } finally {
      provider.db.close();
    }
  } finally {
    s.close();
  }
});

// ─── the forgery (F1 / F3) ────────────────────────────────────────────────

test("after conversion a bot's sha256 rows — access, session and refresh — are all refused and alarmed", async () => {
  const s = scratch();
  try {
    const provider = createOAuthProvider(process.env.CROW_DB_PATH);
    try {
      await runTokenHmacBoot({ db: s.db });
      forgetTokenMacAlarms();

      // What a contained bot can do: crow.db is bound read-write.
      await insertToken(s.db, { token: sha256Hex("bot-owns-this-access"), client: "bot-client", scopes: "mcp:tools", expires: "+1000 days" });
      await insertToken(s.db, { token: sha256Hex("bot-owns-this-session"), client: "dashboard", scopes: "dashboard", expires: "+1000 days" });
      await insertToken(s.db, { token: sha256Hex("bot-owns-this-refresh"), type: "refresh", client: "bot-client", scopes: "mcp:tools", expires: "+1000 days" });

      await assert.rejects(() => provider.verifyAccessToken("bot-owns-this-access"), /Invalid token/);
      assert.equal(await verifySession("bot-owns-this-session"), false);
      assert.equal((await sessionAuth("bot-owns-this-session")).valid, false);
      await assert.rejects(
        () => provider.exchangeRefreshToken({ client_id: "bot-client" }, "bot-owns-this-refresh"),
        /Invalid refresh token/,
      );

      // The alarm is audited per family and never carries the stored value.
      const audits = (await auditRows(s.db, "token_legacy_form")).map((r) => JSON.parse(r.details));
      const families = new Set(audits.map((a) => a.family));
      assert.ok(families.has(OAUTH_ACCESS_FAMILY));
      assert.ok(families.has(DASHBOARD_SESSION_FAMILY));
      assert.ok(families.has(OAUTH_REFRESH_FAMILY));
      for (const a of audits) {
        assert.ok(!/^[0-9a-f]{64}$/.test(String(a.row)), "an audit row never holds the stored verifier");
      }
    } finally {
      provider.db.close();
    }
  } finally {
    s.close();
  }
});

// ─── the copy attack (§2.3) ──────────────────────────────────────────────

test("a copied h1 dashboard-session value is not an OAuth access token (and the reverse)", async () => {
  const s = scratch();
  try {
    const provider = createOAuthProvider(process.env.CROW_DB_PATH);
    try {
      await runTokenHmacBoot({ db: s.db });
      // The bot writes the session's keyed value into an access row of its own.
      const rawSession = "a-real-dashboard-session";
      const sessionStored = await mintStoreToken(s.db, DASHBOARD_SESSION_FAMILY, rawSession);
      await insertToken(s.db, { token: sessionStored, client: "bot-client", scopes: "mcp:tools", expires: "+1000 days" });
      await assert.rejects(() => provider.verifyAccessToken(rawSession), /Invalid token/);
      assert.equal(await verifySession(rawSession), false, "and there is no session row behind it");

      // The reverse: an access token's keyed value planted in a session row.
      const rawAccess = "a-real-access-token";
      const accessStored = await mintStoreToken(s.db, OAUTH_ACCESS_FAMILY, rawAccess);
      await insertToken(s.db, { token: accessStored, client: "dashboard", scopes: "dashboard", expires: "+1000 days" });
      assert.equal(await verifySession(rawAccess), false);
      await assert.rejects(() => provider.verifyAccessToken(rawAccess));
    } finally {
      provider.db.close();
    }
  } finally {
    s.close();
  }
});

// ─── real flows ───────────────────────────────────────────────────────────

test("password login, 2FA completion and OAuth exchange store the keyed form; logout revokes", async () => {
  const s = scratch();
  try {
    const provider = createOAuthProvider(process.env.CROW_DB_PATH);
    try {
      await runTokenHmacBoot({ db: s.db });
      await setPassword("correct horse battery staple");

      const login = await attemptLogin("correct horse battery staple", "127.0.0.1", null, null, { onHost: false });
      assert.ok(login.token, "password login mints a session");
      const loginStored = (await s.db.execute({
        sql: "SELECT token FROM oauth_tokens WHERE client_id = 'dashboard'", args: [],
      })).rows.map((r) => r.token);
      assert.equal(loginStored.length, 1);
      assert.match(loginStored[0], /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/, "the session row stores the keyed form");
      assert.equal(await verifySession(login.token), true);
      assert.equal((await sessionAuth(login.token)).valid, true);

      const twofa = await complete2faLogin("127.0.0.1", { onHost: false });
      assert.equal(await verifySession(twofa.token), true);

      // Logout deletes both forms of the presented token.
      await destroySession(login.token);
      assert.equal(await verifySession(login.token), false);
      assert.equal(await verifySession(twofa.token), true);

      // OAuth: code exchange, access validation, refresh, then a fresh access token.
      const client = { client_id: OAUTH_CLIENT, redirect_uris: ["http://localhost/cb"] };
      provider.codes.set("code-1", {
        client,
        params: { scopes: ["mcp:tools"], redirectUri: "http://localhost/cb" },
        expiresAt: Date.now() + 60_000,
      });
      const issued = await provider.exchangeAuthorizationCode(client, "code-1", undefined);
      const access = await provider.verifyAccessToken(issued.access_token);
      assert.equal(access.clientId, OAUTH_CLIENT);
      const refreshed = await provider.exchangeRefreshToken({ client_id: OAUTH_CLIENT }, issued.refresh_token);
      const access2 = await provider.verifyAccessToken(refreshed.access_token);
      assert.equal(access2.clientId, OAUTH_CLIENT);
      const oauthRows = (await s.db.execute({
        sql: "SELECT token, token_type FROM oauth_tokens WHERE client_id = ?", args: [OAUTH_CLIENT],
      })).rows;
      assert.equal(oauthRows.length, 3, "issued access + refresh + refreshed access");
      for (const row of oauthRows) assert.match(row.token, /^h1\./);
    } finally {
      provider.db.close();
    }
  } finally {
    s.close();
  }
});

// ─── the crash re-run rule (§3.2) ────────────────────────────────────────

test("an interrupted conversion converts only its snapshot rows; any other legacy row alarms", async () => {
  const s = scratch(seedLegacy([
    { token: "in-the-snapshot", client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: "written-after-the-snapshot", client: "bot-client", scopes: "mcp:tools" },
  ]));
  try {
    const provider = createOAuthProvider(process.env.CROW_DB_PATH);
    try {
      // What a crash between "snapshot written" and "era marked" leaves behind: the key,
      // the snapshot, and NO converted marker.
      const key = ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
      mkdirSync(s.secrets, { recursive: true });
      const snapshotName = `${ROLLBACK_PREFIX}2026-11-23T00-00-00-000Z-oauth-access.json`;
      writeFileSync(join(s.secrets, snapshotName), JSON.stringify({
        v: 1,
        family: OAUTH_ACCESS_FAMILY,
        key_id: key.id,
        created_at: "2026-11-23T00:00:00.000Z",
        rows: [{ rowid: 1, token: sha256Hex("in-the-snapshot") }],
      }), { mode: 0o600 });

      forgetTokenMacAlarms();
      const boot = await runTokenHmacBoot({ db: s.db });
      assert.equal(boot.key, "ok");
      const access = boot.families.find((f) => f.family === OAUTH_ACCESS_FAMILY);
      assert.equal(access.count, 1, "only the snapshot's row converted");
      assert.equal(await storedFor(s.db, "in-the-snapshot", OAUTH_ACCESS_FAMILY),
        macFromLegacy(OAUTH_ACCESS_FAMILY, sha256Hex("in-the-snapshot")));
      assert.equal(await storedFor(s.db, "written-after-the-snapshot", OAUTH_ACCESS_FAMILY),
        sha256Hex("written-after-the-snapshot"), "a post-snapshot legacy row is NOT converted");
      assert.equal(access.alarms, 1);

      // Both are judged by the same validator: the converted one works, the other is refused.
      assert.equal((await provider.verifyAccessToken("in-the-snapshot")).clientId, OAUTH_CLIENT);
      await assert.rejects(() => provider.verifyAccessToken("written-after-the-snapshot"));
    } finally {
      provider.db.close();
    }
  } finally {
    s.close();
  }
});

// ─── key lost + the operator reset (§2.6) ────────────────────────────────

test("a lost key still boots, refuses everything, and the operator reset restores password login", async () => {
  const s = scratch();
  const realError = console.error;
  let logged = "";
  try {
    const provider = createOAuthProvider(process.env.CROW_DB_PATH);
    try {
      await runTokenHmacBoot({ db: s.db });
      await setPassword("still-the-password");
      const login = await attemptLogin("still-the-password", "127.0.0.1", null, null, { onHost: false });
      assert.equal(await verifySession(login.token), true);
      const client = { client_id: OAUTH_CLIENT, redirect_uris: ["http://localhost/cb"] };
      provider.codes.set("code-2", {
        client,
        params: { scopes: ["mcp:tools"], redirectUri: "http://localhost/cb" },
        expiresAt: Date.now() + 60_000,
      });
      const oauth = await provider.exchangeAuthorizationCode(client, "code-2", undefined);

      // The key is gone (a crow.db restore without secrets/): a fresh process must NOT
      // re-create it, must log the recovery line, and must still come up.
      unlinkSync(tokenMacKeyPath());
      forgetTokenMacKey();
      forgetTokenStoreEvidence();
      console.error = (line, ...rest) => { logged += `${line} ${rest.join(" ")}\n`; };
      let boot;
      try {
        boot = await runTokenHmacBoot({ db: s.db });
      } finally {
        console.error = realError;
      }
      assert.equal(boot.key, "lost", "the boot reports the key lost, and returns");
      assert.match(logged, /token-hmac\.key/, "names the key file");
      assert.match(logged, /scripts\/token-hmac\.mjs --reset/, "names the recovery command");
      assert.equal(existsSync(tokenMacKeyPath()), false, "no replacement key was minted");

      await assert.rejects(() => provider.verifyAccessToken(oauth.access_token));
      await assert.rejects(() => provider.exchangeRefreshToken({ client_id: OAUTH_CLIENT }, oauth.refresh_token));
      assert.equal(await verifySession(login.token), false);

      // The operator's way out.
      const out = await runCli(["--reset", "--yes"], s.root);
      assert.equal(out.code, 0, out.stderr);
      assert.match(out.stdout, /oauth_tokens:/);
      assert.match(out.stdout, /revoked/);
      assert.ok(statSync(tokenMacKeyPath()).size > 0, "a new key exists");
      assert.equal(await rowCount(s.db), 0, "every grant and session is gone");
      // The three families are left CONVERTED — never cleared (§M1) — in BOTH copies, so the
      // next boot cannot launder a legacy row a bot inserts in between.
      const resetState = readState();
      for (const family of [OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, DASHBOARD_SESSION_FAMILY]) {
        assert.ok(resetState.families[family]?.converted_at, `${family} stays converted after the reset`);
        // eslint-disable-next-line no-await-in-loop -- three families
        const mirror = (await s.db.execute({
          sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ?", args: [`token_hmac_era:${family}`],
        })).rows[0];
        assert.ok(mirror?.value, `${family}'s DB mirror is written as converted, not deleted`);
      }
      assert.equal(await settingsCount(s.db, "SELECT COUNT(*) AS n FROM dashboard_settings WHERE key LIKE 'token_hmac_era:%'"), 0,
        "the mirror rows are local-scope overrides");
      assert.equal(readdirSync(s.secrets).filter((n) => n.includes(".reset-")).length, 0,
        "the era state file is re-marked in place, never renamed aside (sibling eras survive)");

      // Password login works again — the password was never peppered in this release.
      forgetTokenMacKey();
      forgetTokenStoreEvidence();
      const again = await attemptLogin("still-the-password", "127.0.0.1", null, null, { onHost: false });
      assert.ok(again.token, `login after reset: ${JSON.stringify(again)}`);
      assert.equal(await verifySession(again.token), true);
    } finally {
      provider.db.close();
    }
  } finally {
    console.error = realError;
    s.close();
  }
});

// ─── the reset's laundering window (§M1) ─────────────────────────────────

test("a reset leaves the three families converted, so a post-reset legacy row is refused, not laundered", async () => {
  const s = scratch(seedLegacy([{ token: "pre-reset-access", client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  const provider = createOAuthProvider(process.env.CROW_DB_PATH);
  try {
    await runTokenHmacBoot({ db: s.db });
    // An UNRELATED family's era, set before the reset: it must survive in place.
    await markConverted("report:link", { count: 1, rollbackFile: null, at: "2026-01-02T03:04:05.000Z" });
    const unrelated = readState().families["report:link"];
    assert.ok(unrelated?.converted_at, "the sibling family's marker is set before the reset");

    const out = await runCli(["--reset", "--yes"], s.root);
    assert.equal(out.code, 0, out.stderr);
    assert.equal(await rowCount(s.db), 0, "the reset revoked every row");

    // The reset leaves the three families CONVERTED, in the secrets state AND the DB mirror; it
    // never clears a family and never moves the state file aside.
    const st = readState();
    for (const family of [OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, DASHBOARD_SESSION_FAMILY]) {
      assert.ok(st.families[family]?.converted_at, `${family} is converted after the reset`);
      // eslint-disable-next-line no-await-in-loop -- three families
      const mirror = (await s.db.execute({
        sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ?", args: [`token_hmac_era:${family}`],
      })).rows[0];
      assert.ok(mirror?.value, `${family}'s DB mirror is written as converted`);
    }
    assert.deepEqual(st.families["report:link"], unrelated, "the sibling family's era survives the reset in place");

    // A bot inserts a legacy sha256 access row between the reset and the next gateway boot.
    await insertToken(s.db, { token: sha256Hex("bot-access-after-reset"), client: "bot-client", scopes: "mcp:tools", expires: "+30 days" });
    forgetTokenMacKey(); // the next boot loads the NEW key
    forgetTokenStoreEvidence();
    forgetTokenMacAlarms();
    const realWarn = console.warn;
    console.warn = () => {}; // the alarm line is asserted through the audit rows below
    let boot;
    try {
      boot = await runTokenHmacBoot({ db: s.db });
    } finally {
      console.warn = realWarn;
    }
    assert.equal(boot.key, "ok");
    assert.equal(boot.alarms, 1, "the boot reported the post-reset row instead of converting it");
    assert.equal(
      await storedFor(s.db, "bot-access-after-reset", OAUTH_ACCESS_FAMILY),
      sha256Hex("bot-access-after-reset"),
      "the row was NOT converted to a keyed form",
    );
    await assert.rejects(() => provider.verifyAccessToken("bot-access-after-reset"), /Invalid token/);
    const audits = (await auditRows(s.db, "token_legacy_form")).map((r) => JSON.parse(r.details));
    assert.ok(audits.some((a) => a.family === OAUTH_ACCESS_FAMILY), "the refusal was alarmed");
  } finally {
    provider.db.close();
    s.close();
  }
});

// ─── a failing family is retried and refuses legacy (§M2) ────────────────

test("a family whose conversion throws is retried, refuses legacy here, and never skips its siblings", async () => {
  const s = scratch(seedLegacy([
    { token: "m2-access", client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: "m2-refresh", type: "refresh", client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: "m2-session", client: "dashboard", scopes: "dashboard" },
  ]));
  const provider = createOAuthProvider(process.env.CROW_DB_PATH);
  const realError = console.error;
  const attempts = [];
  let logged = "";
  try {
    console.error = (line, ...rest) => { logged += `${line} ${rest.join(" ")}\n`; };
    let boot;
    try {
      boot = await runTokenHmacBoot({
        db: s.db,
        retryDelaysMs: [0, 0, 0], // the real backoff, without the waiting
        sleep: async () => {},
        runTransaction: async (family, runner) => {
          attempts.push(family);
          if (family === OAUTH_ACCESS_FAMILY) throw new Error("injected transactional failure");
          return s.db.runTransaction(runner);
        },
      });
    } finally {
      console.error = realError;
    }

    assert.equal(boot.key, "ok", "the boot still comes up");
    assert.equal(attempts.filter((f) => f === OAUTH_ACCESS_FAMILY).length, 4, "one try and three retries");
    const failed = boot.families.find((f) => f.family === OAUTH_ACCESS_FAMILY);
    assert.equal(failed.state, "failed");
    assert.match(failed.reason, /injected transactional failure/);
    assert.match(logged, /oauth:access/, "one console line names the family");
    assert.match(logged, /REFUSED/, "and says legacy values are refused");

    // The two siblings converted normally — one family failing never skips the others.
    for (const [raw, family] of [
      ["m2-refresh", OAUTH_REFRESH_FAMILY],
      ["m2-session", DASHBOARD_SESSION_FAMILY],
    ]) {
      // eslint-disable-next-line no-await-in-loop -- two families
      assert.equal(await storedFor(s.db, raw, family), macFromLegacy(family, sha256Hex(raw)), `${family} still converted`);
    }
    assert.equal(await verifySession("m2-session"), true);

    // NO era was written for the failed family — this process refuses instead — so the next
    // boot still resumes from its snapshot.
    assert.equal(readState().families[OAUTH_ACCESS_FAMILY], undefined);
    assert.equal((await s.db.execute({
      sql: "SELECT key FROM dashboard_settings_overrides WHERE key = ?",
      args: [`token_hmac_era:${OAUTH_ACCESS_FAMILY}`],
    })).rows.length, 0);

    // In THIS process a legacy row of that family is not a credential...
    assert.equal(await storedFor(s.db, "m2-access", OAUTH_ACCESS_FAMILY), sha256Hex("m2-access"), "not converted");
    await assert.rejects(() => provider.verifyAccessToken("m2-access"), /Invalid token/);

    // ...and a later boot (a fresh process, modelled here by dropping the override) resumes the
    // snapshot and converts it, after which the raw token works again.
    forgetForcedLegacyRefusal();
    forgetTokenMacAlarms();
    const second = await runTokenHmacBoot({ db: s.db });
    const resumed = second.families.find((f) => f.family === OAUTH_ACCESS_FAMILY);
    assert.equal(resumed.state, "converted");
    assert.equal(resumed.count, 1, "the snapshot's single row converted");
    assert.equal(await storedFor(s.db, "m2-access", OAUTH_ACCESS_FAMILY), macFromLegacy(OAUTH_ACCESS_FAMILY, sha256Hex("m2-access")));
    assert.equal((await provider.verifyAccessToken("m2-access")).clientId, OAUTH_CLIENT);
  } finally {
    console.error = realError;
    provider.db.close();
    s.close();
  }
});

test("an unwritable secrets/ only SKIPS the families: legacy stays accepted and nothing is refused (§2.6)", async () => {
  const s = scratch(seedLegacy([{ token: "unwritable-legacy", client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  const provider = createOAuthProvider(process.env.CROW_DB_PATH);
  const realWarn = console.warn;
  let warned = "";
  try {
    // A key exists first, so the boot reaches the snapshot write (the §2.6 gate).
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    console.warn = (line) => { warned += `${line}\n`; };
    let boot;
    try {
      boot = await runTokenHmacBoot({
        db: s.db,
        retryDelaysMs: [0, 0, 0],
        sleep: async () => {},
        writeSnapshot: () => { const err = new Error("read-only file system"); err.code = "EROFS"; throw err; },
      });
    } finally {
      console.warn = realWarn;
    }
    assert.equal(boot.key, "ok");
    for (const family of [OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, DASHBOARD_SESSION_FAMILY]) {
      assert.equal(boot.families.find((f) => f.family === family).state, "skipped", `${family} skipped, not failed`);
    }
    assert.match(warned, /skipped the oauth:access conversion/);
    assert.equal(readState().families[OAUTH_ACCESS_FAMILY], undefined, "no era is recorded");
    // The deliberate §2.6 skip is NOT a failure: legacy stays accepted (unprotected) here.
    assert.equal((await provider.verifyAccessToken("unwritable-legacy")).clientId, OAUTH_CLIENT);
    assert.equal(await verifyStored(OAUTH_ACCESS_FAMILY, "unwritable-legacy", sha256Hex("unwritable-legacy"), { converted: false }).ok, true);
  } finally {
    console.warn = realWarn;
    provider.db.close();
    s.close();
  }
});

// ─── the reset refuses while a gateway is running (§L5) ──────────────────

test("the reset exits 2 without changing anything while a gateway answers /health", async () => {
  const s = scratch(seedLegacy([{ token: "survives-the-refusal", client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  const server = createServer((req, res) => {
    if (req.url === "/health") { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); return; }
    res.writeHead(404); res.end();
  });
  try {
    await runTokenHmacBoot({ db: s.db });
    const keyBefore = readFileSync(tokenMacKeyPath(), "utf8");
    const stateBefore = readFileSync(tokenMacStatePath(), "utf8");
    const rowsBefore = await rowCount(s.db);
    const port = await new Promise((done) => server.listen(0, "127.0.0.1", () => done(server.address().port)));

    const refused = await runCli(["--reset", "--yes"], s.root, { CROW_GATEWAY_PORT: String(port) });
    assert.equal(refused.code, 2, refused.stdout + refused.stderr);
    assert.match(refused.stderr, /must be stopped/);
    assert.equal(readFileSync(tokenMacKeyPath(), "utf8"), keyBefore, "the key was not moved or replaced");
    assert.equal(readFileSync(tokenMacStatePath(), "utf8"), stateBefore, "the era state is untouched");
    assert.equal(await rowCount(s.db), rowsBefore, "no token row was deleted");

    // The stated override: the operator may skip the probe deliberately.
    const forced = await runCli(["--reset", "--yes", "--force-while-running"], s.root, { CROW_GATEWAY_PORT: String(port) });
    assert.equal(forced.code, 0, forced.stderr);
    assert.equal(await rowCount(s.db), 0, "the forced run did reset");
  } finally {
    await new Promise((done) => server.close(done));
    s.close();
  }
});

// ─── the probe's target is the gateway's own (§L5) ──────────────────────

test("the /health probe takes the gateway's own gatewayListenPort() precedence: PORT, then CROW_GATEWAY_PORT, then 3001", async () => {
  const cli = readFileSync(CLI, "utf8");
  // The CLI must ASK the gateway's own expression, not re-derive it: a second copy of the
  // precedence is how the probe and the listener drift apart.
  assert.match(cli, /import \{ gatewayListenPort \} from "\.\.\/servers\/gateway\/listen-port\.js"/,
    "the CLI imports the gateway's own gatewayListenPort()");
  assert.ok(!/CROW_GATEWAY_PORT\s*\|\|/.test(cli), "the CLI must not spell out the port precedence itself");

  const s = scratch();
  const live = await healthServer();
  try {
    const loser = await freePort();
    // Every combo the gateway's own precedence distinguishes. In each one the winner — the port
    // the child is actually given — is the one listening, so an exit 2 means the CLI chose it.
    const combos = [
      { PORT: String(live.port), CROW_GATEWAY_PORT: String(loser) }, // PORT wins
      { CROW_GATEWAY_PORT: String(live.port) },                     // CROW_GATEWAY_PORT when PORT is unset
      { PORT: String(live.port), CROW_GATEWAY_PORT: "not-a-port" }, // PORT still wins over garbage
    ];
    for (const extraEnv of combos) {
      // The env the child gets, checked against the expression the gateway binds with.
      // eslint-disable-next-line no-await-in-loop -- three env combos, one probe each
      assert.equal(gatewayListenPort(await cliEnv(s.root, extraEnv)), live.port,
        `gatewayListenPort() picks the probed port for ${JSON.stringify(extraEnv)}`);
      // eslint-disable-next-line no-await-in-loop -- three env combos, one probe each
      const out = await runCli(["--reset", "--yes"], s.root, extraEnv);
      assert.equal(out.code, 2, `${JSON.stringify(extraEnv)}: ${out.stdout}${out.stderr}`);
      assert.match(out.stderr, new RegExp(`http://127\\.0\\.0\\.1:${live.port}/health`),
        "the refusal names the gateway's own port");
    }

    // The old, backwards precedence (CROW_GATEWAY_PORT first) would have refused here: nothing
    // listens on the PORT winner, so a run that probes the gateway's own port proceeds and
    // really resets.
    const negative = scratch(seedLegacy([{ token: "revoked-by-the-real-reset", client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
    try {
      // eslint-disable-next-line no-await-in-loop -- the last of the four probes
      const out = await runCli(["--reset", "--yes"], negative.root, {
        PORT: String(await freePort()), CROW_GATEWAY_PORT: String(live.port),
      });
      assert.equal(out.code, 0, out.stdout + out.stderr);
      assert.equal(await rowCount(negative.db), 0, "the reset ran: PORT was the port probed");
    } finally {
      negative.close();
    }
  } finally {
    await live.close();
    s.close();
  }
});

test("the /health probe follows gatewayListenHost(): 127.0.0.1 for a wildcard, loopback or unset bind and the address itself otherwise", async (t) => {
  const cli = readFileSync(CLI, "utf8");
  assert.match(cli, /import \{ gatewayListenHost \} from "\.\.\/servers\/gateway\/listen-host\.js"/,
    "the CLI imports the gateway's own gatewayListenHost()");

  const s = scratch();
  try {
    // Every one of these binds still answers on loopback, so a listener on 127.0.0.1 is found.
    for (const bind of [undefined, "0.0.0.0", "::", "127.0.0.1", "127.0.0.2", "::1", "localhost"]) {
      // eslint-disable-next-line no-await-in-loop -- one probe per bind
      const live = await healthServer("127.0.0.1");
      try {
        const extraEnv = { CROW_GATEWAY_PORT: String(live.port) };
        if (bind !== undefined) extraEnv.CROW_GATEWAY_BIND = bind;
        // eslint-disable-next-line no-await-in-loop -- one probe per bind
        const out = await runCli(["--reset", "--yes"], s.root, extraEnv);
        assert.equal(out.code, 2, `bind ${bind}: ${out.stdout}${out.stderr}`);
        assert.match(out.stderr, /must be stopped/);
      } finally {
        // eslint-disable-next-line no-await-in-loop -- one probe per bind
        await live.close();
      }
    }

    // A SPECIFIC, non-loopback bind is probed on that address: a listener there is found, and one
    // on 127.0.0.1 alone would not be. Skipped when this host has no such interface to bind.
    const iface = Object.values(networkInterfaces()).flat()
      .find((i) => i && i.family === "IPv4" && !i.internal);
    if (!iface) {
      t.skip("no non-loopback IPv4 interface here: the specific-bind case is untested");
      return;
    }
    let live;
    try {
      live = await healthServer(iface.address);
    } catch (err) {
      t.skip(`cannot bind ${iface.address} (${err.code || err.message}): the specific-bind case is untested`);
      return;
    }
    try {
      const out = await runCli(["--reset", "--yes"], s.root, {
        CROW_GATEWAY_PORT: String(live.port), CROW_GATEWAY_BIND: iface.address,
      });
      assert.equal(out.code, 2, out.stdout + out.stderr);
      assert.match(out.stderr, new RegExp(iface.address.replace(/\./g, "\\.")),
        "the refusal names the specific bind address, not loopback");
    } finally {
      await live.close();
    }
  } finally {
    s.close();
  }
});

// ─── the copy attack, and the forged legacy session, in every reader ─────

test("a copied h1 value never crosses into or out of the refresh family", async () => {
  const s = scratch();
  const provider = createOAuthProvider(process.env.CROW_DB_PATH);
  try {
    await runTokenHmacBoot({ db: s.db });
    // access → refresh: a real access token's keyed value planted in a refresh row.
    const rawAccess = "copy-access-into-refresh";
    await insertToken(s.db, {
      token: await mintStoreToken(s.db, OAUTH_ACCESS_FAMILY, rawAccess),
      type: "refresh", client: "bot-client", scopes: "mcp:tools", expires: "+1000 days",
    });
    await assert.rejects(
      () => provider.exchangeRefreshToken({ client_id: "bot-client" }, rawAccess),
      /Invalid refresh token/,
    );
    // refresh → access: the reverse direction.
    const rawRefresh = "copy-refresh-into-access";
    await insertToken(s.db, {
      token: await mintStoreToken(s.db, OAUTH_REFRESH_FAMILY, rawRefresh),
      client: "bot-client", scopes: "mcp:tools", expires: "+1000 days",
    });
    await assert.rejects(() => provider.verifyAccessToken(rawRefresh), /Invalid token/);
    // dashboard session → refresh: a session value is not a refresh token either.
    const rawSession = "copy-session-into-refresh";
    await insertToken(s.db, {
      token: await mintStoreToken(s.db, DASHBOARD_SESSION_FAMILY, rawSession),
      type: "refresh", client: "bot-client", scopes: "mcp:tools", expires: "+1000 days",
    });
    await assert.rejects(
      () => provider.exchangeRefreshToken({ client_id: "bot-client" }, rawSession),
      /Invalid refresh token/,
    );
  } finally {
    provider.db.close();
    s.close();
  }
});

test("after conversion a forged legacy session row is refused by viewerOf, isLocalPasswordSessionOn and sessionCreatedAt", async () => {
  const s = scratch();
  try {
    await runTokenHmacBoot({ db: s.db });
    // A direct TCP request from off-box, the shape the owner's reader accepts.
    const request = (session) => ({ dashboardSession: session, headers: {}, socket: { remoteAddress: "203.0.113.7" } });
    // The control: a REAL keyed session row from the same request shape IS the owner, so the
    // refusals below are the row's form and not the origin gate.
    const goodRaw = "a-real-session-from-the-laptop";
    await insertToken(s.db, {
      token: await mintStoreToken(s.db, DASHBOARD_SESSION_FAMILY, goodRaw),
      client: "dashboard", scopes: "dashboard", expires: "+1 hour",
    });
    assert.equal(await isLocalPasswordSessionOn(s.db, request(goodRaw)), true, "the owner control");
    assert.equal(await viewerOf(s.db, request(goodRaw)), "owner");
    assert.ok(await sessionCreatedAt(s.db, goodRaw), "the control session has a created_at");

    // The forgery: what a contained bot can write — sha256 of a token it knows.
    const forgedRaw = "forged-legacy-session";
    await insertToken(s.db, { token: sha256Hex(forgedRaw), client: "dashboard", scopes: "dashboard", expires: "+1000 days" });
    assert.equal(await verifySession(forgedRaw), false);
    assert.equal(await isLocalPasswordSessionOn(s.db, request(forgedRaw)), false);
    assert.equal(await viewerOf(s.db, request(forgedRaw)), "peer", "a forged session is refused, not downgraded to member");
    assert.equal(await sessionCreatedAt(s.db, forgedRaw), null, "and it invents no session time");
  } finally {
    s.close();
  }
});

/** A port nothing listens on: bind it once, read it, release it (the CLI's probe must miss). */
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
function closedPort() {
  if (!closedPortMemo) closedPortMemo = freePort();
  return closedPortMemo;
}

/** A server answering `/health` on `host`, on `port` or on a free one: what a gateway looks like. */
async function healthServer(host = "127.0.0.1", port = 0) {
  const server = createServer((req, res) => {
    if (req.url === "/health") { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); return; }
    res.writeHead(404); res.end();
  });
  const bound = await new Promise((done, fail) => {
    server.on("error", fail);
    server.listen(port, host, () => done(server.address().port));
  });
  return { port: bound, close: () => new Promise((done) => server.close(done)) };
}

/** The child's environment, exactly: the reset probes /health before touching anything. */
async function cliEnv(home, extraEnv = {}) {
  const env = {
    ...process.env,
    CROW_HOME: home,
    CROW_DATA_DIR: join(home, "data"),
    CROW_DB_PATH: join(home, "data", "crow.db"),
    ...extraEnv,
  };
  // The probe follows the gateway's own precedence, PORT first, so a PORT inherited from the
  // test runner's environment would point it at a stranger's port.
  if (!("PORT" in extraEnv)) delete env.PORT;
  // Point it at a port nothing listens on unless the caller names one.
  if (!("CROW_GATEWAY_PORT" in extraEnv)) env.CROW_GATEWAY_PORT = String(await closedPort());
  return env;
}

/** Run the operator CLI in a child, against the scratch instance. */
async function runCli(args, home, extraEnv = {}) {
  const env = await cliEnv(home, extraEnv);
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI, ...args], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => done({ code, stdout, stderr }));
  });
}

// ─── the deploy-day rollback (§ the CLI's --rollback) ──────────────────────

const POST_CONVERSION_RAW = "session-minted-after-the-conversion";

/** The three seeded rows: what a rollback restores, per family. */
const SEEDED = [
  [ACCESS_RAW, OAUTH_ACCESS_FAMILY],
  [REFRESH_RAW, OAUTH_REFRESH_FAMILY],
  [SESSION_RAW, DASHBOARD_SESSION_FAMILY],
];

const eraMirrorRows = (db) => settingsCount(db,
  "SELECT COUNT(*) AS n FROM dashboard_settings_overrides WHERE key LIKE 'token_hmac_era:%'");

const movedAside = (s, prefix) => {
  try {
    return readdirSync(s.secrets).filter((n) => n.startsWith(prefix) && n.includes(".rolledback-"));
  } catch {
    return [];
  }
};

test("the rollback restores the snapshot rows, revokes the post-conversion ones, and a re-deploy converts again", async () => {
  const s = scratch(seedLegacy([
    { token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: REFRESH_RAW, type: "refresh", client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: SESSION_RAW, client: "dashboard", scopes: "dashboard" },
  ]));
  const provider = createOAuthProvider(process.env.CROW_DB_PATH);
  try {
    const boot = await runTokenHmacBoot({ db: s.db });
    assert.equal(boot.key, "ok");
    const keyIdBefore = JSON.parse(readFileSync(tokenMacKeyPath(), "utf8")).id;
    for (const [raw, family] of SEEDED) {
      assert.equal(await storedFor(s.db, raw, family), macFromLegacy(family, sha256Hex(raw)), `${family} converted`);
    }

    // A login AFTER the deploy: an `h1.` row no snapshot knows, so no rollback can compute it
    // back. The previous release could never read it, so the rollback revokes it.
    const postH1 = await mintStoreToken(s.db, DASHBOARD_SESSION_FAMILY, POST_CONVERSION_RAW);
    await insertToken(s.db, {
      token: postH1, client: "dashboard", scopes: "dashboard", expires: "+1 hour",
    });
    assert.equal(await verifySession(POST_CONVERSION_RAW), true);

    // The deploy-day undo.
    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.match(out.stdout, /Token conversion rolled back/);
    for (const family of [OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, DASHBOARD_SESSION_FAMILY]) {
      assert.match(out.stdout, new RegExp(`${family}\\s+1 restored`), `the counts name ${family}`);
    }
    assert.match(out.stdout, /0 gone/, "nothing in the seeded rows expired");
    assert.match(out.stdout, /dashboard:session\s+1 restored.*1 revoked \(minted after conversion\)/,
      "the post-conversion session is reported as revoked");
    assert.ok(!/h1\./.test(out.stdout), "no verifier is printed");
    assert.ok(!/[0-9a-f]{64}/.test(out.stdout), "no hash is printed");

    // Every seeded row is back to EXACTLY the value the previous release looks up.
    for (const [raw, family] of SEEDED) {
      const legacy = sha256Hex(raw);
      // eslint-disable-next-line no-await-in-loop -- three families, one lookup each
      const found = (await s.db.execute({
        sql: "SELECT token_type FROM oauth_tokens WHERE token = ?", args: [legacy],
      })).rows[0];
      assert.ok(found, `${family}: SELECT … WHERE token = sha256hex(raw) finds the row again`);
      // eslint-disable-next-line no-await-in-loop -- three families
      assert.equal(await storedFor(s.db, raw, family), legacy, `${family} is back in the legacy form`);
    }
    // The post-conversion session is GONE, and nothing else was invented.
    assert.equal((await s.db.execute({
      sql: "SELECT 1 AS present FROM oauth_tokens WHERE token = ?", args: [postH1],
    })).rows.length, 0, "the token minted after the conversion was revoked");
    assert.equal(await rowCount(s.db), SEEDED.length, "only the restored rows are left");

    // The key and the era state moved ASIDE (never deleted), 0600 kept.
    assert.equal(existsSync(tokenMacKeyPath()), false);
    assert.equal(existsSync(tokenMacStatePath()), false);
    const keyAsides = movedAside(s, "token-hmac.key");
    assert.equal(keyAsides.length, 1, "the key file moved aside");
    assert.equal(statSync(join(s.secrets, keyAsides[0])).mode & 0o777, 0o600, "the moved key is still 0600");
    assert.equal(movedAside(s, "token-hmac-state.json").length, 1, "the era state file moved aside");
    // … and so did every snapshot.
    assert.deepEqual(rollbackFiles(s), [], "no snapshot is left in place");
    assert.equal(movedAside(s, ROLLBACK_PREFIX).length, 3, "all three snapshots moved aside");

    // The one-way era mirror is DELETED — both copies — so a re-deploy converts again instead of
    // refusing the restored bare-sha256 rows as forgeries written without the key.
    assert.equal(await eraMirrorRows(s.db), 0, "no local-scope era override is left");
    assert.equal(await settingsCount(s.db,
      "SELECT COUNT(*) AS n FROM dashboard_settings WHERE key LIKE 'token_hmac_era:%'"), 0,
    "no global era row is left");

    // RE-DEPLOY: a fresh key, the restored rows converted once more, and the raw tokens work.
    forgetTokenMacKey();
    forgetTokenStoreEvidence();
    forgetTokenMacAlarms();
    const again = await runTokenHmacBoot({ db: s.db });
    assert.equal(again.key, "ok", "the new key is minted, not reported lost");
    assert.equal(again.alarms, 0, "nothing is refused as an old-style forgery");
    assert.notEqual(JSON.parse(readFileSync(tokenMacKeyPath(), "utf8")).id, keyIdBefore, "a NEW key");
    for (const [raw, family] of SEEDED) {
      // eslint-disable-next-line no-await-in-loop -- three families
      assert.equal(await storedFor(s.db, raw, family), macFromLegacy(family, sha256Hex(raw)),
        `${family} converted again from the restored legacy row`);
    }
    assert.equal((await provider.verifyAccessToken(ACCESS_RAW)).clientId, OAUTH_CLIENT);
    assert.ok((await provider.exchangeRefreshToken({ client_id: OAUTH_CLIENT }, REFRESH_RAW)).access_token);
    assert.equal(await verifySession(SESSION_RAW), true, "the restored dashboard session signs in again");
  } finally {
    provider.db.close();
    s.close();
  }
});

test("the rollback exits 2 without changing anything while a gateway answers /health", async () => {
  const s = scratch(seedLegacy([{ token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  const live = await healthServer();
  try {
    await runTokenHmacBoot({ db: s.db });
    const keyBefore = readFileSync(tokenMacKeyPath(), "utf8");
    const stateBefore = readFileSync(tokenMacStatePath(), "utf8");
    const snapshotsBefore = rollbackFiles(s).length;
    const h1Before = await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY);
    assert.match(h1Before, /^h1\./, "the row is keyed before the run");

    const refused = await runCli(["--rollback", "--yes"], s.root, { CROW_GATEWAY_PORT: String(live.port) });
    assert.equal(refused.code, 2, refused.stdout + refused.stderr);
    assert.match(refused.stderr, /must be stopped/);
    assert.equal(readFileSync(tokenMacKeyPath(), "utf8"), keyBefore, "the key was not moved aside");
    assert.equal(readFileSync(tokenMacStatePath(), "utf8"), stateBefore, "the era state is untouched");
    assert.equal(rollbackFiles(s).length, snapshotsBefore, "no snapshot moved");
    assert.equal(await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY), h1Before, "the row was not restored");
    assert.equal(await eraMirrorRows(s.db), 3, "the era mirror still marks the three families converted");

    // The stated override: the operator may skip the probe deliberately.
    const forced = await runCli(["--rollback", "--yes", "--force-while-running"], s.root, {
      CROW_GATEWAY_PORT: String(live.port),
    });
    assert.equal(forced.code, 0, forced.stdout + forced.stderr);
    assert.equal(await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY), sha256Hex(ACCESS_RAW),
      "the forced run did roll back");
  } finally {
    await live.close();
    s.close();
  }
});

test("the rollback ignores and reports a snapshot written under another key, and rolls the rest back", async () => {
  const s = scratch(seedLegacy([
    { token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: SESSION_RAW, client: "dashboard", scopes: "dashboard" },
  ]));
  try {
    await runTokenHmacBoot({ db: s.db });
    const names = rollbackFiles(s);
    assert.equal(names.length, 3, "one snapshot per converted family");

    // One file belongs to a key this box does not hold (a reset, a rotation): it is unusable, and
    // it must not veto a rollback the current key can still do.
    const victimName = names.find((n) => n.includes("oauth-access"));
    assert.ok(victimName, "the access snapshot is there");
    const victimPath = join(s.secrets, victimName);
    const body = JSON.parse(readFileSync(victimPath, "utf8"));
    body.key_id = "0123456789abcdef";
    writeFileSync(victimPath, JSON.stringify(body, null, 2) + "\n");

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.match(out.stdout, /ignored:/, "the run says what it ignored");
    assert.ok(out.stdout.includes(`secrets/${victimName}`), "and names the file");
    assert.match(out.stdout, /different token-hmac key/);
    assert.ok(!/h1\./.test(out.stdout + out.stderr) && !/[0-9a-f]{64}/.test(out.stdout + out.stderr),
      "no verifier and no hash is printed");

    // The session family rolled back normally. The access family had no usable snapshot, so none
    // of its rows can be proven and they are revoked instead — the count says exactly that.
    assert.equal(await storedFor(s.db, SESSION_RAW, DASHBOARD_SESSION_FAMILY), sha256Hex(SESSION_RAW));
    assert.equal((await s.db.execute({
      sql: "SELECT 1 AS present FROM oauth_tokens WHERE token = ?", args: [sha256Hex(ACCESS_RAW)],
    })).rows.length, 0, "the access row was revoked, not restored");
    assert.match(out.stdout, /oauth:access\s+0 restored, 0 gone \(expired or revoked since\), 1 revoked/);

    // The foreign file is NOT moved aside (it belongs to another era, and is ignored on sight).
    assert.equal(existsSync(victimPath), true, "a foreign snapshot is left where it is");
    assert.equal(movedAside(s, ROLLBACK_PREFIX).length, 2, "the two usable snapshots moved aside");
    assert.equal(existsSync(tokenMacKeyPath()), false);
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.equal(await eraMirrorRows(s.db), 0);
  } finally {
    s.close();
  }
});

test("the rollback still refuses what it cannot use: an unparseable snapshot, a foreign family, a promised file that is gone", async () => {
  const seeded = () => scratch(seedLegacy([{ token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  const cases = [
    {
      what: "unparseable",
      break: (s, names) => writeFileSync(join(s.secrets, names[0]), "{not json"),
      expect: /does not parse as a conversion snapshot/,
    },
    {
      what: "a family a rollback does not restore",
      break: (s, names) => {
        const path = join(s.secrets, names[0]);
        const body = JSON.parse(readFileSync(path, "utf8"));
        body.family = "report:link";
        writeFileSync(path, JSON.stringify(body, null, 2) + "\n");
      },
      expect: /which a rollback does not restore/,
    },
    {
      what: "a snapshot the era state promises and that is gone",
      break: (s, names) => { unlinkSync(join(s.secrets, names[0])); },
      expect: /The era state still records/,
    },
  ];
  for (const entry of cases) {
    // eslint-disable-next-line no-await-in-loop -- one scratch box per case
    const s = seeded();
    try {
      // eslint-disable-next-line no-await-in-loop -- one scratch box per case
      await runTokenHmacBoot({ db: s.db });
      const names = rollbackFiles(s);
      assert.equal(names.length, 3, `${entry.what}: three snapshots to start from`);
      const stateBefore = readFileSync(tokenMacStatePath(), "utf8");
      const keyBefore = readFileSync(tokenMacKeyPath(), "utf8");
      const h1Before = await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY);
      entry.break(s, names);

      // eslint-disable-next-line no-await-in-loop -- one scratch box per case
      const out = await runCli(["--rollback", "--yes"], s.root);
      assert.equal(out.code, 3, `${entry.what}: ${out.stdout}${out.stderr}`);
      assert.match(out.stderr, entry.expect, entry.what);
      assert.match(out.stderr, /Nothing was changed/, entry.what);
      assert.equal(readFileSync(tokenMacKeyPath(), "utf8"), keyBefore, `${entry.what}: the key is untouched`);
      assert.equal(readFileSync(tokenMacStatePath(), "utf8"), stateBefore, `${entry.what}: the state is untouched`);
      // eslint-disable-next-line no-await-in-loop -- one scratch box per case
      assert.equal(await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY), h1Before, `${entry.what}: no row moved`);
      // eslint-disable-next-line no-await-in-loop -- one scratch box per case
      assert.equal(await eraMirrorRows(s.db), 3, `${entry.what}: the era mirror is untouched`);
      assert.ok(!/h1\./.test(out.stdout + out.stderr) && !/[0-9a-f]{64}/.test(out.stdout + out.stderr),
        `${entry.what}: no verifier and no hash is printed`);
    } finally {
      s.close();
    }
  }
});

test("a post-reset box with nothing to restore still rolls back: it revokes the keyed rows and retires the era", async () => {
  const s = scratch(); // nothing converted yet: no legacy row, no snapshot
  try {
    // The operator reset (an install whose key was lost before this release ever converted): it
    // re-marks the three families CONVERTED with NO rollback file and writes no snapshot.
    const reset = await runCli(["--reset", "--yes"], s.root);
    assert.equal(reset.code, 0, reset.stdout + reset.stderr);
    assert.deepEqual(rollbackFiles(s), [], "the reset wrote no conversion snapshot");
    const st = readState();
    for (const family of [OAUTH_ACCESS_FAMILY, OAUTH_REFRESH_FAMILY, DASHBOARD_SESSION_FAMILY]) {
      assert.ok(st.families[family]?.converted_at, `${family} is converted`);
      assert.equal(st.families[family].rollback_file, null, `${family} records no rollback file`);
    }

    // A sign-in under the reset's new key: an `h1.` row no snapshot knows.
    forgetTokenMacKey();
    forgetTokenStoreEvidence();
    const sessionStored = await mintStoreToken(s.db, DASHBOARD_SESSION_FAMILY, "post-reset-session");
    await insertToken(s.db, { token: sessionStored, client: "dashboard", scopes: "dashboard" });
    assert.equal(await rowCount(s.db), 1);

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.match(out.stdout, /no usable snapshot/);
    assert.equal(await rowCount(s.db), 0, "the keyed row was revoked");
    assert.match(out.stdout, /dashboard:session\s+0 restored, 0 gone \(expired or revoked since\), 1 revoked/);

    // The era is retired as usual: the state file and the key moved aside, the mirror gone.
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.equal(existsSync(tokenMacKeyPath()), false);
    assert.equal(movedAside(s, "token-hmac-state.json").length, 1);
    assert.equal(movedAside(s, "token-hmac.key").length, 1);
    assert.equal(await eraMirrorRows(s.db), 0);
    assert.equal(await settingsCount(s.db,
      "SELECT COUNT(*) AS n FROM dashboard_settings WHERE key LIKE 'token_hmac_era:%'"), 0);
  } finally {
    s.close();
  }
});

test("a post-reset box sweeps a bot's legacy row even though it has no snapshot to spare values from", async () => {
  const s = scratch(); // nothing converted yet: no legacy row, no snapshot
  try {
    // The reset leaves every family CONVERTED and writes no snapshot: nothing can ever be proven
    // genuine here, so the legacy sweep has no spared value set at all.
    const reset = await runCli(["--reset", "--yes"], s.root);
    assert.equal(reset.code, 0, reset.stdout + reset.stderr);
    assert.deepEqual(rollbackFiles(s), [], "the reset wrote no conversion snapshot");

    // What a contained bot writes between the reset and the next boot: a bare row the alarm
    // refuses. No snapshot names it, and no snapshot ever will.
    const forged = sha256Hex("bot-legacy-after-reset");
    await insertToken(s.db, {
      token: forged, client: "bot-client", scopes: "mcp:tools", expires: "+30 days",
    });
    assert.equal(await rowCount(s.db), 1);

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.match(out.stdout, /no usable snapshot/);
    // The sweep still ran for the converted family: it is counted as removed, not left behind.
    assert.match(out.stdout,
      /oauth:access\s+0 restored, 0 gone \(expired or revoked since\), 0 revoked \(minted after conversion\), 1 removed/,
      "the post-reset legacy write is swept and counted");
    assert.equal(await rowCount(s.db), 0, "the forged legacy row is gone");
    assert.equal((await s.db.execute({
      sql: "SELECT 1 AS present FROM oauth_tokens WHERE token NOT LIKE 'h1.%'", args: [],
    })).rows.length, 0, "nothing legacy is left in any family");
    assert.equal(existsSync(tokenMacKeyPath()), false, "the era was retired as usual");
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.equal(await eraMirrorRows(s.db), 0);
  } finally {
    s.close();
  }
});

test("a bot's post-conversion legacy write is removed, including one on a snapshot's own value", async () => {
  const s = scratch(seedLegacy([{ token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  try {
    await runTokenHmacBoot({ db: s.db });
    const legacy = sha256Hex(ACCESS_RAW);
    // (a) What a contained bot can write: a bare row sitting on the PRE-CONVERSION value of a real
    //     token. The restore of that snapshot row would collide with it (the stored value is the
    //     primary key), so the run has to clear the claim and keep the genuine row.
    await insertToken(s.db, { token: legacy, client: "bot-client", scopes: "bot", expires: "+1000 days" });
    // (b) and another bare row on a value no snapshot names.
    const botLegacy = sha256Hex("bot-legacy-written-after-conversion");
    await insertToken(s.db, { token: botLegacy, client: "bot-client", scopes: "mcp:tools", expires: "+1000 days" });

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);

    const rows = (await s.db.execute({
      sql: "SELECT token, client_id, scopes FROM oauth_tokens", args: [],
    })).rows;
    assert.deepEqual(rows.map((r) => r.token), [legacy], "only the restored row is left");
    assert.equal(rows[0].client_id, OAUTH_CLIENT, "(a) the GENUINE row survived the collision, not the bot's");
    assert.equal(rows[0].scopes, "mcp:tools", "and it kept its own columns");
    assert.ok(!rows.some((r) => r.token === botLegacy), "(b) the other bot row is gone");

    assert.match(out.stdout, /oauth:access\s+1 restored, 0 gone \(expired or revoked since\)/);
    assert.match(out.stdout, /2 removed \(written after conversion, never valid\)/);
    assert.ok(!/h1\./.test(out.stdout) && !/[0-9a-f]{64}/.test(out.stdout), "no verifier and no hash is printed");
  } finally {
    s.close();
  }
});

test("an interruption right after the commit re-runs cleanly and never deletes the restored rows", async () => {
  const s = scratch(seedLegacy([
    { token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: REFRESH_RAW, type: "refresh", client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: SESSION_RAW, client: "dashboard", scopes: "dashboard" },
  ]));
  try {
    await runTokenHmacBoot({ db: s.db });
    assert.equal(rollbackFiles(s).length, 3);

    const crashed = await runCli(["--rollback", "--yes"], s.root, {
      CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT: "commit",
    });
    assert.equal(crashed.code, 7, crashed.stdout + crashed.stderr);
    assert.match(crashed.stderr, /interrupted after the commit step/);
    assert.match(crashed.stderr, /re-running --rollback/);

    // The transaction COMMITTED (rows bare, mirror gone) and NOT ONE file was moved.
    for (const [raw, family] of SEEDED) {
      // eslint-disable-next-line no-await-in-loop -- three families
      assert.equal(await storedFor(s.db, raw, family), sha256Hex(raw), `${family} is restored`);
    }
    assert.equal(await rowCount(s.db), SEEDED.length);
    assert.equal(await eraMirrorRows(s.db), 0, "the mirror went with the restored rows");
    assert.ok(existsSync(tokenMacKeyPath()), "the key is still there");
    assert.ok(existsSync(tokenMacStatePath()), "the era state is still there");
    assert.equal(rollbackFiles(s).length, 3, "the snapshots are still there");
    assert.equal(movedAside(s, "token-hmac.key").length, 0, "nothing moved yet");

    // The re-run finishes the job. It must be a NO-OP restore, not a sweep that eats the rows the
    // first run put back.
    const again = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(again.code, 0, again.stdout + again.stderr);
    assert.equal(await rowCount(s.db), SEEDED.length, "the re-run deleted nothing");
    for (const [raw, family] of SEEDED) {
      // eslint-disable-next-line no-await-in-loop -- three families
      assert.equal(await storedFor(s.db, raw, family), sha256Hex(raw));
      // eslint-disable-next-line no-await-in-loop -- three families
      assert.match(again.stdout, new RegExp(`${family}\\s+1 restored, 0 gone`), `${family} counts as restored, not gone`);
    }
    assert.equal(existsSync(tokenMacKeyPath()), false, "the re-run finished the moves");
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.deepEqual(rollbackFiles(s), []);
    assert.equal(await eraMirrorRows(s.db), 0);
  } finally {
    s.close();
  }
});

test("an interruption after the era state moved leaves a box that boots normally, not \"key lost\"", async () => {
  const s = scratch(seedLegacy([
    { token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: REFRESH_RAW, type: "refresh", client: OAUTH_CLIENT, scopes: "mcp:tools" },
    { token: SESSION_RAW, client: "dashboard", scopes: "dashboard" },
  ]));
  const provider = createOAuthProvider(process.env.CROW_DB_PATH);
  try {
    await runTokenHmacBoot({ db: s.db });
    const keyId = JSON.parse(readFileSync(tokenMacKeyPath(), "utf8")).id;

    const crashed = await runCli(["--rollback", "--yes"], s.root, {
      CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT: "state",
    });
    assert.equal(crashed.code, 7, crashed.stdout + crashed.stderr);
    assert.match(crashed.stderr, /interrupted after the state step/);

    // The state file moved FIRST; the key and the snapshots did not.
    assert.equal(existsSync(tokenMacStatePath()), false);
    assert.equal(movedAside(s, "token-hmac-state.json").length, 1);
    assert.ok(existsSync(tokenMacKeyPath()), "the key is still on disk");
    assert.equal(rollbackFiles(s).length, 3, "the snapshots were not moved yet");
    for (const [raw, family] of SEEDED) {
      // eslint-disable-next-line no-await-in-loop -- three families
      assert.equal(await storedFor(s.db, raw, family), sha256Hex(raw));
    }
    assert.equal(await eraMirrorRows(s.db), 0, "the mirror committed away with the restored rows");

    // THE PICKED BRANCH: with the mirror gone and the state gone, a boot with the OLD KEY still
    // present must be a NORMAL boot — a key file answers for itself, so this is never "key lost" —
    // and it converts the restored rows again under that same key. Nobody is locked out.
    forgetTokenMacKey();
    forgetTokenStoreEvidence();
    forgetTokenMacAlarms();
    const boot = await runTokenHmacBoot({ db: s.db });
    assert.equal(boot.key, "ok", "the old key file is loaded, never reported lost");
    assert.equal(boot.alarms, 0, "nothing is refused as an old-style forgery");
    assert.equal(JSON.parse(readFileSync(tokenMacKeyPath(), "utf8")).id, keyId, "the same key, untouched");
    for (const [raw, family] of SEEDED) {
      // eslint-disable-next-line no-await-in-loop -- three families
      const stored = await storedFor(s.db, raw, family);
      assert.equal(stored, macFromLegacy(family, sha256Hex(raw)), `${family} converted again`);
      assert.equal(stored.split(".")[1], keyId, `${family} was converted under the same key`);
    }
    assert.equal((await provider.verifyAccessToken(ACCESS_RAW)).clientId, OAUTH_CLIENT);
    assert.equal(await verifySession(SESSION_RAW), true);
  } finally {
    provider.db.close();
    s.close();
  }
});

test("the era mirror delete does not skip the global rows when the overrides table is missing", async () => {
  const s = scratch(seedLegacy([{ token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  try {
    await runTokenHmacBoot({ db: s.db });
    // A store that has the global settings table and no per-instance overrides at all.
    await s.db.execute({ sql: "DROP TABLE dashboard_settings_overrides", args: [] });
    await s.db.execute({
      sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: [`token_hmac_era:${OAUTH_ACCESS_FAMILY}`, "2026-01-02T03:04:05.000Z"],
    });

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY), sha256Hex(ACCESS_RAW));
    assert.equal(await settingsCount(s.db,
      "SELECT COUNT(*) AS n FROM dashboard_settings WHERE key LIKE 'token_hmac_era:%'"), 0,
    "the global era row was deleted even though the overrides table is gone");
  } finally {
    s.close();
  }
});

test("the rollback refuses when the key that converted the rows is gone (exit 3, nothing changed)", async () => {
  const s = scratch(seedLegacy([{ token: ACCESS_RAW, client: OAUTH_CLIENT, scopes: "mcp:tools" }]));
  try {
    await runTokenHmacBoot({ db: s.db });
    const stateBefore = readFileSync(tokenMacStatePath(), "utf8");
    const names = rollbackFiles(s);
    const h1Before = await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY);
    unlinkSync(tokenMacKeyPath());

    const out = await runCli(["--rollback", "--yes"], s.root);
    assert.equal(out.code, 3, out.stdout + out.stderr);
    assert.match(out.stderr, /needs the token-hmac key that converted these rows/);
    assert.match(out.stderr, /Nothing was changed/);
    assert.equal(existsSync(tokenMacKeyPath()), false, "no key was minted to stand in");
    assert.equal(readFileSync(tokenMacStatePath(), "utf8"), stateBefore, "the era state is untouched");
    assert.equal(rollbackFiles(s).length, names.length, "no snapshot moved");
    assert.equal(await storedFor(s.db, ACCESS_RAW, OAUTH_ACCESS_FAMILY), h1Before, "no row was restored");
    assert.equal(await eraMirrorRows(s.db), 3, "the era mirror is untouched");
  } finally {
    s.close();
  }
});

// ─── static guards (§6.8) ────────────────────────────────────────────────

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules") continue;
      walk(path, out);
    } else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) {
      out.push(path);
    }
  }
  return out;
}

test("no private sha256 hashToken is left in the consolidated readers", () => {
  const files = [
    "servers/gateway/auth.js",
    "servers/gateway/dashboard/local-session.js",
    "servers/gateway/dashboard/shell/mode.js",
    "servers/gateway/dashboard/panels/project-reports.js",
  ];
  for (const rel of files) {
    const src = readFileSync(join(ROOT, rel), "utf8");
    assert.ok(!/function hashToken|hashToken\s*=\s*\(/.test(src), `${rel} must not define its own hashToken`);
  }
  // dashboard/auth.js keeps exactly ONE exported legacy helper, for tests and tools that
  // seed a pre-conversion row. No gateway reader or writer may call it.
  const authSrc = readFileSync(join(ROOT, "servers/gateway/dashboard/auth.js"), "utf8");
  assert.equal(authSrc.match(/hashToken\s*\(/g)?.length, 1, "only the documented export remains");

  // The only surviving users are the OTHER families this PR does not own: report links
  // (`report:link`, PR 5) and the peer inbound bearer (`peer:inbound`, PR 4).
  const allowed = new Set([
    "servers/gateway/dashboard/auth.js",
    "servers/gateway/reports/links.js",
    "servers/gateway/reports/public-door.js",
    "servers/gateway/reports/seal.js",
    "servers/shared/cross-host-auth.js",
  ]);
  for (const path of walk(join(ROOT, "servers"))) {
    const rel = relative(ROOT, path);
    if (allowed.has(rel)) continue;
    assert.ok(!/\bhashToken\b/.test(readFileSync(path, "utf8")), `${rel} must not name hashToken`);
  }
});

test("no validator hard-codes converted, and the boot runs before listen", () => {
  for (const path of walk(join(ROOT, "servers"))) {
    const rel = relative(ROOT, path);
    if (rel === "servers/shared/token-mac.js") continue;
    const src = readFileSync(path, "utf8");
    assert.ok(!/\bconverted\s*:\s*(true|false)\b/.test(src),
      `${rel} must take converted from familyConverted, never a literal`);
  }
  const index = readFileSync(join(ROOT, "servers/gateway/index.js"), "utf8");
  const bootAt = index.indexOf("runTokenHmacBoot");
  const listenAt = index.indexOf("app.listen(PORT, BIND");
  assert.ok(bootAt > 0 && bootAt < listenAt, "the converter must run before the gateway listens");
});

test("resetFamiliesForOperator and adoptOperatorKey are operator-shell only — no file under servers/ names them, and the CLI never clears an era", () => {
  for (const path of walk(join(ROOT, "servers"))) {
    const rel = relative(ROOT, path);
    if (rel === "servers/shared/token-mac.js") continue; // the definitions
    const src = readFileSync(path, "utf8");
    for (const name of ["resetFamiliesForOperator", "adoptOperatorKey"]) {
      assert.ok(!src.includes(name), `${rel} must not reach the operator-only ${name}`);
    }
  }
  const cli = readFileSync(CLI, "utf8");
  assert.match(cli, /adoptOperatorKey/);
  // The three families stay CONVERTED throughout a reset: the CLI has no clear step at all, so
  // there is no moment at which a family is unconverted and a bare sha256 would be a credential.
  assert.ok(!cli.includes("resetFamiliesForOperator"), "the reset CLI must never clear an era");
  assert.match(cli, /markConverted/);
});

test("the rollback is operator-shell only, and reads the snapshot shape from the code that wrote it", () => {
  // The CLI exports nothing: it IS the operator's entry point (`main()` runs on import), so there
  // is no helper for `servers/` to reach. What stays pinned is that nothing else offers the
  // rollback, and that the CLI takes the snapshot prefix, the family predicates and the mirror
  // key from the gateway modules rather than a second copy that could drift.
  const cli = readFileSync(CLI, "utf8");
  assert.match(cli, /--rollback/);
  assert.match(cli, /import \{ ROLLBACK_PREFIX \} from "\.\.\/servers\/gateway\/boot\/token-hmac\.js"/,
    "the snapshot prefix comes from the converter that wrote the files");
  assert.match(cli, /FAMILY_PREDICATE/, "restores select the families the validators select");
  assert.match(cli, /eraSettingKey/, "the era mirror rows are named by token-mac, never spelled out");
  assert.match(cli, /tokenMacStatePath/, "the era state file is the one token-mac owns");
  assert.ok(!cli.includes("resetFamiliesForOperator"), "a rollback clears no era in place");
  for (const path of walk(join(ROOT, "servers"))) {
    const rel = relative(ROOT, path);
    assert.ok(!readFileSync(path, "utf8").includes("token-hmac.mjs --rollback"),
      `${rel} must not advertise the operator rollback`);
  }
});

test("token-mac refuses a legacy row in a converted family and accepts it before conversion", async () => {
  const s = scratch();
  try {
    await runTokenHmacBoot({ db: s.db });
    const raw = "presented-token";
    const legacy = sha256Hex(raw);
    await insertToken(s.db, { token: legacy, client: "c" });
    forgetTokenMacAlarms();
    assert.equal(verifyStored(OAUTH_ACCESS_FAMILY, raw, legacy, { converted: true }).ok, false);
    assert.equal(verifyStored(OAUTH_ACCESS_FAMILY, raw, legacy, { converted: false }).ok, true);
    assert.equal(verifyStored(OAUTH_ACCESS_FAMILY, raw, macToken(OAUTH_ACCESS_FAMILY, raw), { converted: true }).ok, true);
  } finally {
    s.close();
  }
});