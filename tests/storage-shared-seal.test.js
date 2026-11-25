/**
 * storage.shared.* sealed values BOUND to their setting (AAD v2), release 1: READER only.
 *
 * The two credential settings are the only identity-sealed values that SYNC, and an `enc:v1:`
 * blob carries no AAD — it opens under any setting name, so a bot with crow.db write access
 * could copy the secret blob into `access_key` (SigV4 then sends the secret as the key id in
 * clear to the endpoint). Binding the AAD to the setting key, the NORMALIZED endpoint and the
 * SSL flag closes that, and also closes a plain endpoint/use_ssl rewrite.
 *
 * Covered here:
 *   - servers/shared/storage-shared-seal.js on its own: the AAD, endpoint normalization (and
 *     that the AAD's `host:port` IS the address the reader dials), the one `use_ssl` parser,
 *     and the classification of every value shape (v2, v1, plaintext, unknown `enc:` envelope,
 *     non-canonical bodies, a value that opens to another envelope), plus that a refusal never
 *     logs a value, endpoint or plaintext;
 *   - the storage READER (servers/storage/s3-client.js) failing CLOSED on a refused blob, and
 *     dialling the normalized address for a bound credential while a v1 row keeps its legacy
 *     split;
 *   - the settings section's "keep the stored key" path refusing exactly like a missing key,
 *     and reading `use_ssl` the same way the client does;
 *   - the tailnet-sync `sa` capability: both hellos advertise it, a peer that does not is
 *     recorded as 0, a look-alike key is not a capability, and peersStorageAadCapable answers
 *     per fleet.
 *
 * Nothing here writes a v2 value: release 1 is reader-first (the form still seals v1).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import {
  STORAGE_SHARED_CREDENTIAL_KEYS,
  normalizeStorageEndpoint,
  parseStorageUseSSL,
  splitNormalizedEndpoint,
  storageSharedAad,
  openStorageSharedValue,
} from "../servers/shared/storage-shared-seal.js";
import { sealSecret, sealSecretBound } from "../servers/sharing/secret-box.js";
import {
  readSharedStorageSettingsSync, loadSharedStorageFromDbSync, envStorageConfig, SHARED_STORAGE_UNREADABLE,
} from "../servers/storage/s3-client.js";
import {
  peersStorageAadCapable, SYNC_SA_KEY_PREFIX, _setAllowLoopbackAddressesForTest,
} from "../servers/sharing/tailnet-sync.js";
import { makeFleet, makeRealDb, addPeerRow, until } from "./fixtures/sync-fleet.mjs";
import { startGateway, startWsRelay } from "./fixtures/sync-gateway.mjs";
import { getPeerDialHealth } from "../servers/shared/peer-dial-health.js";

const KEYS = {
  access: STORAGE_SHARED_CREDENTIAL_KEYS[0],
  secret: STORAGE_SHARED_CREDENTIAL_KEYS[1],
};
const ENDPOINT = "minio.example.test:9000";
const ACCESS_PLAINTEXT = "crow-access-key-01";
const SECRET_PLAINTEXT = "crow-secret-key-aaaaaaaaaaaaaaaaaaaaaaaa";
/** A stable fake identity: every blob below is sealed and opened with this one seed. */
const identity = { seed: Buffer.alloc(32, 7) };

const aad = (key, endpoint = ENDPOINT, useSSL = false) => storageSharedAad(key, endpoint, useSSL);
const open = (value, over = {}) => openStorageSharedValue(value, {
  settingKey: KEYS.access, endpoint: ENDPOINT, useSSL: false, identity, ...over,
});

/** Run `fn` with console.warn captured; returns what it wrote. */
function captureWarn(fn) {
  const real = console.warn;
  const lines = [];
  console.warn = (...a) => { lines.push(a.map(String).join(" ")); };
  try { fn(); } finally { console.warn = real; }
  return lines;
}

/* ───────────────────────────── endpoint normalization ───────────────────────────── */

test("normalizeStorageEndpoint: the AAD names the address the storage reader actually dials", () => {
  // The AAD is only worth binding if it names the address the client connects to. These
  // compare the normalized form against the host/port the reader's own split (envStorageConfig,
  // the exported path through _splitHostPort) arrives at, for every spelling it accepts. The
  // HOST is compared case-insensitively: DNS is, so `MinIO.Example.Test` and the lower-cased
  // AAD form are the same address.
  const dialled = (endpoint) => {
    const cfg = envStorageConfig({ S3_ENDPOINT: endpoint });
    return `${cfg.host.toLowerCase()}:${cfg.port}`;
  };
  const spellings = [
    "minio.example.test",
    "minio.example.test:3900",
    "http://minio.example.test:3900",
    "https://minio.example.test",
    "HTTPS://minio.example.test:3900",
    "HTTP://MinIO.Example.Test:3900/",
    "  minio.example.test:3900  ",
  ];
  assert.equal(normalizeStorageEndpoint("minio.example.test"), "minio.example.test:9000", "absent port defaults to 9000");
  assert.equal(normalizeStorageEndpoint("minio.example.test:3900"), "minio.example.test:3900");
  assert.equal(normalizeStorageEndpoint("HTTP://MinIO.Example.Test:3900/"), "minio.example.test:3900", "scheme, host case and one trailing slash");
  for (const endpoint of spellings) {
    assert.equal(normalizeStorageEndpoint(endpoint), dialled(endpoint), `the AAD address is the dialled address: ${endpoint}`);
  }
  // The one helper the reader uses to turn the AAD's spelling back into a host and a port.
  assert.deepEqual(splitNormalizedEndpoint("minio.example.test:3900"), { host: "minio.example.test", port: 3900 });
  assert.deepEqual(splitNormalizedEndpoint("HTTPS://MinIO.Example.Test:3900/"), { host: "minio.example.test", port: 3900 });
  assert.deepEqual(splitNormalizedEndpoint("minio.example.test"), { host: "minio.example.test", port: 9000 });
  assert.throws(() => splitNormalizedEndpoint("minio.example.test:9000/path"), undefined, "the helper refuses what normalization refuses");
});

test("normalizeStorageEndpoint refuses what it cannot normalize unambiguously", () => {
  for (const bad of [
    "",
    "   ",
    "user:pw@minio.example.test:9000", // userinfo
    "http://user@minio.example.test:9000",
    "minio.example.test:9000/path", // a path beyond the trailing slash
    "minio.example.test:9000//",
    "minio.example.test:9000?x=1", // query
    "minio.example.test:9000#frag", // fragment
    ":9000", // empty host
    "minio.example.test:abc", // non-numeric port
    "minio.example.test:", // empty port
    "minio.example.test:0", // out of range
    "minio.example.test:70000",
    "[::1]:9000", // IPv6 literal: refused rather than guessed at
    "[fd00::1]",
    "::1",
  ]) {
    assert.throws(() => normalizeStorageEndpoint(bad), undefined, `refused: ${JSON.stringify(bad)}`);
  }
  assert.throws(() => normalizeStorageEndpoint(null));
});

test("parseStorageUseSSL is the one reader of the stored flag: \"true\" and \"1\" are on, anything else is off", () => {
  assert.equal(parseStorageUseSSL("true"), true);
  assert.equal(parseStorageUseSSL("1"), true);
  for (const off of ["false", "0", "yes", "on", "", undefined, null, true]) {
    assert.equal(parseStorageUseSSL(off), false, `off: ${JSON.stringify(off)}`);
  }
});

test("storageSharedAad is a JSON array tagged first, and refuses a key it does not own", () => {
  const a = JSON.parse(aad(KEYS.access));
  assert.deepEqual(a, ["crow-storage-shared-v2", KEYS.access, ENDPOINT, false]);
  assert.deepEqual(JSON.parse(aad(KEYS.secret, ENDPOINT, true)), ["crow-storage-shared-v2", KEYS.secret, ENDPOINT, true]);
  // Normalization happens INSIDE the AAD, so equivalent spellings share one array.
  assert.equal(aad(KEYS.access, "https://MinIO.Example.Test:9000/", false), aad(KEYS.access));
  // useSSL is a boolean here: the truthy string is not silently accepted as one.
  assert.notEqual(aad(KEYS.access, ENDPOINT, "true"), aad(KEYS.access, ENDPOINT, true));
  assert.throws(() => storageSharedAad("storage.shared.endpoint", ENDPOINT, false));
  assert.throws(() => storageSharedAad("providers.api_key", ENDPOINT, false));
});

/* ───────────────────────────── openStorageSharedValue ───────────────────────────── */

test("a v2 blob opens under the AAD it was sealed for (version v2)", () => {
  const blob = sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access));
  const r = open(blob);
  assert.deepEqual(r, { ok: true, plaintext: ACCESS_PLAINTEXT, version: "v2" });
  const secret = sealSecretBound(SECRET_PLAINTEXT, identity, aad(KEYS.secret));
  assert.deepEqual(open(secret, { settingKey: KEYS.secret }), { ok: true, plaintext: SECRET_PLAINTEXT, version: "v2" });
});

test("a swapped v2 blob, a changed endpoint and a flipped use_ssl are all storage_credentials_unbound", () => {
  // The attack: the secret's blob copied into access_key.
  const secretBlob = sealSecretBound(SECRET_PLAINTEXT, identity, aad(KEYS.secret));
  const swapped = open(secretBlob, { settingKey: KEYS.access });
  assert.equal(swapped.ok, false);
  assert.equal(swapped.reason, "storage_credentials_unbound");
  assert.equal("plaintext" in swapped, false, "a refusal never carries a plaintext");
  // The other direction (access into secret) is equally bound.
  const accessBlob = sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access));
  assert.equal(open(accessBlob, { settingKey: KEYS.secret }).reason, "storage_credentials_unbound");

  // A re-pointed endpoint and a flipped SSL flag fail the tag check too (closes the
  // "no copy needed" variant of the same attack).
  assert.equal(open(accessBlob, { endpoint: "attacker.example.test:9000" }).reason, "storage_credentials_unbound");
  assert.equal(open(accessBlob, { useSSL: true }).reason, "storage_credentials_unbound");
  // An endpoint that cannot be normalized is the same refusal, never an open.
  assert.equal(open(accessBlob, { endpoint: "minio.example.test:9000/extra/path" }).reason, "storage_credentials_unbound");
  assert.equal(open(accessBlob, { endpoint: "" }).reason, "storage_credentials_unbound");

  // Equivalent endpoint spellings open fine: the AAD carries the normalized form.
  for (const equivalent of ["http://minio.example.test:9000", "HTTPS://MINIO.EXAMPLE.TEST:9000/", "minio.example.test:9000"]) {
    assert.equal(open(accessBlob, { endpoint: equivalent }).ok, true, `equivalent spelling: ${equivalent}`);
  }
});

test("every other enc: spelling is an unknown_envelope, never plaintext", () => {
  for (const value of ["enc:v3:abc", "ENC:V2:abc", "enc:junk", "Enc:V1:abc"]) {
    const r = open(value);
    assert.equal(r.ok, false, `refused: ${value}`);
    assert.equal(r.reason, "unknown_envelope", `classified: ${value}`);
  }
  // Non-string and empty values are refused the same way (a caller never passes a missing row).
  assert.equal(open("").reason, "unknown_envelope");
  assert.equal(open(null).reason, "unknown_envelope");
  assert.equal(open(undefined).reason, "unknown_envelope");
  assert.equal(open(1234).reason, "unknown_envelope");
});

test("non-canonical sealed bodies are refused (the form this release writes is exact)", () => {
  const v2 = sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access));
  const v1 = sealSecret(ACCESS_PLAINTEXT, identity);
  const paddingStripped = (v) => v.replace(/=+$/, "");
  for (const [value, label] of [
    [`${v2}\n`, "v2 with a trailing newline"],
    [`${v2} `, "v2 with a trailing space"],
    [paddingStripped(v2), "v2 with its padding stripped"],
    [`${v1}\n`, "v1 with a trailing newline"],
    [paddingStripped(v1), "v1 with its padding stripped"],
  ]) {
    const r = open(value);
    assert.equal(r.ok, false, `refused: ${label}`);
    assert.equal(r.reason, "noncanonical", `classified: ${label}`);
  }
});

test("v1 and plaintext values open exactly as before (versions v1 and plain)", () => {
  const v1 = sealSecret(ACCESS_PLAINTEXT, identity);
  assert.deepEqual(open(v1), { ok: true, plaintext: ACCESS_PLAINTEXT, version: "v1" });
  // v1 carries no AAD, so a v1 blob is still accepted under the other key name (the era rule
  // that refuses it comes in release 2, gated on the fleet).
  assert.deepEqual(open(v1, { settingKey: KEYS.secret }), { ok: true, plaintext: ACCESS_PLAINTEXT, version: "v1" });
  assert.deepEqual(open("plain-access-key"), { ok: true, plaintext: "plain-access-key", version: "plain" });
  assert.deepEqual(open("enc"), { ok: true, plaintext: "enc", version: "plain" }, "only a full enc: prefix is an envelope");
  // A v1 blob sealed with ANOTHER identity cannot be opened (unchanged behaviour: unopenable).
  assert.equal(open(v1, { identity: { seed: Buffer.alloc(32, 9) } }).reason, "unopenable");
});

test("a value that opens to another envelope is refused as nested_envelope (v1 and v2 alike)", () => {
  // A sealed value sealed twice, or a blob carried over from another setting: the plaintext a
  // reader would hand the storage client is itself ciphertext, so it is never a credential.
  const innerV1 = sealSecret(ACCESS_PLAINTEXT, identity);
  const nestedV1 = sealSecret(innerV1, identity);
  const innerV2 = sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access));
  const nestedV2 = sealSecretBound(innerV2, identity, aad(KEYS.access));
  for (const [blob, label] of [[nestedV1, "v1 wrapping v1"], [nestedV2, "v2 wrapping v2"]]) {
    const r = open(blob);
    assert.equal(r.ok, false, `refused: ${label}`);
    assert.equal(r.reason, "nested_envelope", `classified: ${label}`);
    assert.equal("plaintext" in r, false, "a refusal never carries a plaintext");
  }
  // An `ENC:` spelling of the inner envelope is the same refusal, not a plaintext credential.
  const upper = sealSecret(innerV1.replace(/^enc:/, "ENC:"), identity);
  assert.equal(open(upper).reason, "nested_envelope");
  // The refusal is the OPENER's, so it also covers the case the inner blob is a v1 one sealed
  // into a v2 body whose AAD was built for the other setting name.
  const crossKey = sealSecretBound(sealSecret(SECRET_PLAINTEXT, identity), identity, aad(KEYS.secret));
  assert.equal(open(crossKey, { settingKey: KEYS.secret }).reason, "nested_envelope");
});

test("a refusal logs one line with the reason and the setting key only — never a value, endpoint or plaintext", () => {
  const v2 = sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access));
  const v1 = sealSecret(ACCESS_PLAINTEXT, identity);
  const nested = sealSecret(sealSecret(ACCESS_PLAINTEXT, identity), identity);
  const cases = [
    () => open(v2, { settingKey: KEYS.secret }), // swapped
    () => open(v2, { endpoint: "attacker.example.test:9000" }),
    () => open(`${v2}\n`), // non-canonical
    () => open("enc:v3:topsecret"), // unknown envelope
    () => open(v1, { identity: { seed: Buffer.alloc(32, 9) } }), // unopenable
    () => open(nested), // nested_envelope
  ];
  for (const run of cases) {
    const lines = captureWarn(run);
    assert.equal(lines.length, 1, "exactly one line per refusal");
    const line = lines[0];
    assert.match(line, /^\[storage\] shared credential refused: \w+ storage\.shared\.(access|secret)_key$/);
    for (const secret of [v2, v1, ACCESS_PLAINTEXT, SECRET_PLAINTEXT, "attacker.example.test", ENDPOINT, "topsecret"]) {
      assert.equal(line.includes(secret), false, `the line must not carry ${JSON.stringify(secret.slice(0, 12))}…`);
    }
  }
});

/* ───────────────────────────── the storage reader (s3-client) ───────────────────────────── */

/** A temp crow.db-shaped file holding only the tables the sync reader touches. */
function tempSettingsDb(dir) {
  const path = join(dir, "crow.db");
  const db = new Database(path);
  db.exec("CREATE TABLE dashboard_settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)");
  db.exec("CREATE TABLE dashboard_settings_overrides (key TEXT NOT NULL, instance_id TEXT NOT NULL, value TEXT, updated_at TEXT, PRIMARY KEY (key, instance_id))");
  const put = (key, value) => db.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))").run(key, value);
  return { db, path, put };
}

test("s3-client: a v2 row dials exactly the endpoint its AAD names (uppercase scheme included)", () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-shared-aad-dial-"));
  const { db, path, put } = tempSettingsDb(dir);
  try {
    // The spelling an owner can type. normalizeStorageEndpoint strips the scheme
    // case-insensitively, so this row's AAD names `minio.example.test:3900`; a reader that
    // stripped only a lower-case scheme would dial a host called `HTTPS` instead.
    const endpoint = "HTTPS://minio.example.test:3900";
    put("storage.shared.endpoint", endpoint);
    put("storage.shared.use_ssl", "false");
    put("storage.shared.access_key", sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access, endpoint)));
    put("storage.shared.secret_key", sealSecretBound(SECRET_PLAINTEXT, identity, aad(KEYS.secret, endpoint)));

    const read = readSharedStorageSettingsSync(path, identity);
    assert.equal(read.ok, true, "a bound pair opens");
    const { config } = read;
    const named = normalizeStorageEndpoint(endpoint);
    assert.equal(named, "minio.example.test:3900");
    assert.equal(`${config.host}:${config.port}`, named, "the dialled host:port IS the AAD endpoint");
    assert.equal(config.endpoint, named, "the config carries the normalized address to the bot pipe");
    assert.equal(config.port, 3900);
    assert.deepEqual([config.host, config.port], [splitNormalizedEndpoint(named).host, splitNormalizedEndpoint(named).port]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("s3-client: a v1 row keeps the legacy split and the raw endpoint (a path or an IPv6 literal included)", () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-shared-v1-split-"));
  const { db, path, put } = tempSettingsDb(dir);
  try {
    put("storage.shared.use_ssl", "false");
    put("storage.shared.access_key", sealSecret(ACCESS_PLAINTEXT, identity));
    put("storage.shared.secret_key", sealSecret(SECRET_PLAINTEXT, identity));
    // v1 carries no AAD, so nothing is bound to a normalized address: the old parsing (and the
    // raw setting exactly as stored) stays, which is what keeps these spellings working.
    for (const [endpoint, host, port] of [
      ["minio.example.test:9000/prefix", "minio.example.test", 9000],
      ["HTTPS://minio.example.test:3900", "minio.example.test", 3900],
      ["[fd00::1]:9000", "[fd00::1]", 9000],
    ]) {
      put("storage.shared.endpoint", endpoint);
      const read = readSharedStorageSettingsSync(path, identity);
      assert.equal(read.ok, true, `a v1 row reads: ${endpoint}`);
      assert.equal(read.config.endpoint, endpoint, `the raw endpoint is unchanged: ${endpoint}`);
      assert.deepEqual([read.config.host, read.config.port], [host, port], `legacy split: ${endpoint}`);
    }
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("s3-client: use_ssl means what parseStorageUseSSL says (\"1\" and \"true\" are the same flag)", () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-shared-usessl-"));
  const { db, path, put } = tempSettingsDb(dir);
  try {
    put("storage.shared.endpoint", ENDPOINT);
    put("storage.shared.access_key", sealSecret(ACCESS_PLAINTEXT, identity));
    put("storage.shared.secret_key", sealSecret(SECRET_PLAINTEXT, identity));
    for (const [raw, expected] of [["true", true], ["1", true], ["false", false], ["0", false], ["yes", false]]) {
      put("storage.shared.use_ssl", raw);
      const read = readSharedStorageSettingsSync(path, identity);
      assert.equal(read.ok, true);
      assert.equal(read.config.useSSL, expected, `use_ssl=${raw}`);
    }
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("s3-client: a stored value that opens to another envelope turns storage OFF, like any refusal", () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-shared-nested-"));
  const { db, path, put } = tempSettingsDb(dir);
  try {
    put("storage.shared.endpoint", ENDPOINT);
    put("storage.shared.use_ssl", "false");
    // Both a v1 and a v2 row whose plaintext is itself a sealed blob.
    put("storage.shared.secret_key", sealSecret(SECRET_PLAINTEXT, identity));
    for (const nested of [
      sealSecret(sealSecret(ACCESS_PLAINTEXT, identity), identity),
      sealSecretBound(sealSecret(ACCESS_PLAINTEXT, identity), identity, aad(KEYS.access)),
    ]) {
      put("storage.shared.access_key", nested);
      const lines = captureWarn(() => {
        assert.deepEqual(readSharedStorageSettingsSync(path, identity), { ok: false, reason: SHARED_STORAGE_UNREADABLE });
        assert.equal(loadSharedStorageFromDbSync(path, identity), null);
      });
      assert.equal(lines.some((l) => l.includes("nested_envelope")), true, "the refusal is classified");
    }
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("s3-client: a swapped v2 blob turns storage OFF (unreadable, never a config); a good v2/v1 row still yields one", () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-shared-seal-"));
  const { db, path, put } = tempSettingsDb(dir);
  try {
    put("storage.shared.endpoint", ENDPOINT);
    put("storage.shared.use_ssl", "false");

    // The correct, bound pair opens like any other config.
    put("storage.shared.access_key", sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access)));
    put("storage.shared.secret_key", sealSecretBound(SECRET_PLAINTEXT, identity, aad(KEYS.secret)));
    const good = readSharedStorageSettingsSync(path, identity);
    assert.equal(good.ok, true, "a bound pair opens");
    assert.equal(good.config.accessKey, ACCESS_PLAINTEXT);
    assert.equal(good.config.secretKey, SECRET_PLAINTEXT);
    assert.equal(good.config.port, 9000);
    assert.equal(good.config.useSSL, false);

    // The secret blob copied into access_key: storage goes OFF through the existing
    // unreadable path — no config, and never a config with the ciphertext as a key.
    put("storage.shared.access_key", sealSecretBound(SECRET_PLAINTEXT, identity, aad(KEYS.secret)));
    const swapped = captureWarn(() => {
      const read = readSharedStorageSettingsSync(path, identity);
      assert.deepEqual(read, { ok: false, reason: SHARED_STORAGE_UNREADABLE });
      assert.equal(loadSharedStorageFromDbSync(path, identity), null);
    });
    assert.equal(swapped.some((l) => l.includes("storage_credentials_unbound")), true, "the refusal is classified");

    // A re-pointed endpoint under an intact v2 pair is the same refusal.
    put("storage.shared.access_key", sealSecretBound(ACCESS_PLAINTEXT, identity, aad(KEYS.access)));
    put("storage.shared.endpoint", "attacker.example.test:9000");
    assert.equal(readSharedStorageSettingsSync(path, identity).ok, false);
    put("storage.shared.endpoint", ENDPOINT);

    // An unknown envelope is refused too (an old reader would have used it as a credential).
    put("storage.shared.secret_key", "enc:v3:bogus");
    assert.equal(readSharedStorageSettingsSync(path, identity).ok, false);
    put("storage.shared.secret_key", sealSecretBound(SECRET_PLAINTEXT, identity, aad(KEYS.secret)));

    // An ordinary v1 pair (what release 1 still writes) is accepted unchanged.
    put("storage.shared.access_key", sealSecret("v1-access-key", identity));
    put("storage.shared.secret_key", sealSecret("v1-secret-key", identity));
    const legacy = readSharedStorageSettingsSync(path, identity);
    assert.equal(legacy.ok, true);
    assert.equal(legacy.config.accessKey, "v1-access-key");
    assert.equal(legacy.config.secretKey, "v1-secret-key");

    // Plaintext values stay accepted in release 1.
    put("storage.shared.access_key", "plain-access");
    put("storage.shared.secret_key", "plain-secret");
    const plain = readSharedStorageSettingsSync(path, identity);
    assert.equal(plain.ok, true);
    assert.equal(plain.config.accessKey, "plain-access");
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/* ───────────────────────────── the settings section ───────────────────────────── */

test("settings section: use_ssl \"1\" reads as SSL ON, and a doubly-sealed stored key counts as unset (400, nothing written)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-shared-section-usessl-"));
  const { db: raw, put } = tempSettingsDb(dir);
  const db = {
    execute: async ({ sql, args = [] }) => {
      const st = raw.prepare(sql);
      if (/^\s*(INSERT|UPDATE|DELETE)/i.test(sql)) return { rows: [], rowsAffected: st.run(...args).changes };
      return { rows: st.all(...args) };
    },
  };
  const rows = () => ({
    settings: raw.prepare("SELECT COUNT(*) AS n FROM dashboard_settings").get().n,
    overrides: raw.prepare("SELECT COUNT(*) AS n FROM dashboard_settings_overrides").get().n,
  });
  try {
    const { loadOrCreateIdentity } = await import("../servers/sharing/identity.js");
    const liveIdentity = loadOrCreateIdentity();

    // The flag an older reader took as OFF (`"1"`) is the SAME flag the client and the AAD use.
    put("storage.shared.endpoint", ENDPOINT);
    put("storage.shared.use_ssl", "1");
    put("storage.shared.access_key", sealSecret(sealSecret(ACCESS_PLAINTEXT, liveIdentity), liveIdentity));
    put("storage.shared.secret_key", sealSecret(SECRET_PLAINTEXT, liveIdentity));

    const { default: section } = await import("../servers/gateway/dashboard/settings/sections/shared-storage.js");
    const html = await section.render({ db, lang: "en" });
    assert.match(html, /name="use_ssl" type="checkbox" checked/, "use_ssl=1 shows as SSL on");
    assert.match(html, /name="access_key" type="text" value="" placeholder="crowadmin"/, "a doubly-sealed key reads as unset");

    // The save path: the nested value does not open, so the blank-key field resolves to nothing
    // and the EXISTING 400 answers. Nothing is re-sealed, nothing is written.
    const before = rows();
    let status = 0; let answer = null;
    const res = { status(c) { status = c; return this; }, json(o) { answer = o; } };
    const handled = await section.handleAction({
      req: { body: { payload: JSON.stringify({ endpoint: ENDPOINT, use_ssl: true, region: "us-east-1", bucket_prefix: "crow" }) } },
      res, db, action: "save",
    });
    assert.equal(handled, true);
    assert.equal(status, 400, "the existing 400, not a new refusal");
    assert.equal(answer.error, "access_key and secret_key required");
    assert.deepEqual(rows(), before, "nothing was written");
    assert.equal(raw.prepare("SELECT value FROM dashboard_settings WHERE key = 'storage.shared.access_key'").get().value.startsWith("enc:v1:"), true, "the stored row is untouched");
  } finally {
    raw.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("settings section: a stored swapped v2 key makes a blank-key save return the existing 400 and write nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-shared-section-"));
  const { db: raw, put } = tempSettingsDb(dir);
  const db = {
    execute: async ({ sql, args = [] }) => {
      const st = raw.prepare(sql);
      if (/^\s*(INSERT|UPDATE|DELETE)/i.test(sql)) return { rows: [], rowsAffected: st.run(...args).changes };
      return { rows: st.all(...args) };
    },
  };
  const rows = () => ({
    settings: raw.prepare("SELECT COUNT(*) AS n FROM dashboard_settings").get().n,
    overrides: raw.prepare("SELECT COUNT(*) AS n FROM dashboard_settings_overrides").get().n,
  });
  try {
    const { loadOrCreateIdentity } = await import("../servers/sharing/identity.js");
    const liveIdentity = loadOrCreateIdentity();

    put("storage.shared.endpoint", ENDPOINT);
    put("storage.shared.use_ssl", "false");
    // The secret's blob copied into access_key: it does not open under the access key's AAD.
    put("storage.shared.access_key", sealSecretBound(SECRET_PLAINTEXT, liveIdentity, storageSharedAad(KEYS.secret, ENDPOINT, false)));
    put("storage.shared.secret_key", sealSecretBound(SECRET_PLAINTEXT, liveIdentity, storageSharedAad(KEYS.secret, ENDPOINT, false)));

    const { default: section } = await import("../servers/gateway/dashboard/settings/sections/shared-storage.js");
    const before = rows();
    let status = 0; let answer = null;
    const res = { status(c) { status = c; return this; }, json(o) { answer = o; } };
    const handled = await section.handleAction({
      req: { body: { payload: JSON.stringify({ endpoint: ENDPOINT, use_ssl: false, region: "us-east-1", bucket_prefix: "crow" }) } },
      res, db, action: "save",
    });
    assert.equal(handled, true);
    assert.equal(status, 400, "the existing 400, not a new refusal");
    assert.equal(answer.error, "access_key and secret_key required");
    assert.deepEqual(rows(), before, "nothing was written");

    // And the form shows the pair as UNSET for the SWAPPED key (a blank field and the
    // not-configured placeholder: masked dots would claim a working key).
    const html = await section.render({ db, lang: "en" });
    assert.equal((html.match(/value="••••••••"/g) || []).length, 1, "only the correctly-bound secret still reads as set");
    assert.match(html, /name="access_key" type="text" value="" placeholder="crowadmin"/, "the swapped key reads as unset");

    // Control: the same section with a v2 pair sealed for THIS endpoint shows both as set.
    put("storage.shared.access_key", sealSecretBound(ACCESS_PLAINTEXT, liveIdentity, storageSharedAad(KEYS.access, ENDPOINT, false)));
    put("storage.shared.secret_key", sealSecretBound(SECRET_PLAINTEXT, liveIdentity, storageSharedAad(KEYS.secret, ENDPOINT, false)));
    const htmlOk = await section.render({ db, lang: "en" });
    assert.equal((htmlOk.match(/value="••••••••"/g) || []).length, 2, "a bound pair reads as set");
  } finally {
    raw.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/* ───────────────────────────── peersStorageAadCapable (DB only) ───────────────────────────── */

const override = async (db, localId, key) => {
  const { rows } = await db.execute({
    sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
    args: [key, localId],
  });
  return rows[0]?.value ?? null;
};

test("peersStorageAadCapable: no peers → true; an old, unknown or non-numeric peer → false; a DB error → false", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-sa-capable-"));
  let db = null;
  try {
    db = await makeRealDb(dir);
    // Nothing to break.
    assert.equal(await peersStorageAadCapable(db, "self"), true);

    // A trusted peer that never advertised `sa` keeps the fleet at v1.
    await addPeerRow(db, "peerOld");
    assert.equal(await peersStorageAadCapable(db, "self"), false);

    // It advertises 1 → capable.
    await db.execute({
      sql: "INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at) VALUES (?, ?, ?, datetime('now'))",
      args: [`${SYNC_SA_KEY_PREFIX}peerOld`, "self", "1"],
    });
    assert.equal(await peersStorageAadCapable(db, "self"), true);

    // A second trusted peer with NO recorded value → false again (one old peer is enough).
    await addPeerRow(db, "peerUnknown");
    assert.equal(await peersStorageAadCapable(db, "self"), false);

    // A non-numeric recorded value is not a capability.
    await db.execute({
      sql: "INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at) VALUES (?, ?, ?, datetime('now'))",
      args: [`${SYNC_SA_KEY_PREFIX}peerUnknown`, "self", "yes"],
    });
    assert.equal(await peersStorageAadCapable(db, "self"), false);

    // A recorded 0 (a peer that went back to older code) counts as incapable.
    await db.execute({
      sql: "UPDATE dashboard_settings_overrides SET value = ? WHERE key = ? AND instance_id = ?",
      args: ["0", `${SYNC_SA_KEY_PREFIX}peerUnknown`, "self"],
    });
    assert.equal(await peersStorageAadCapable(db, "self"), false);

    // Revoking that peer removes it from the question.
    await db.execute({ sql: "UPDATE crow_instances SET status = 'revoked' WHERE id = ?", args: ["peerUnknown"] });
    assert.equal(await peersStorageAadCapable(db, "self"), true);

    // An untrusted row is not a peer at all.
    await db.execute({ sql: "UPDATE crow_instances SET trusted = 0 WHERE id = ?", args: ["peerOld"] });
    assert.equal(await peersStorageAadCapable(db, "self"), true);

    // Missing local id and any DB error fail closed.
    assert.equal(await peersStorageAadCapable(db, null), false);
    assert.equal(await peersStorageAadCapable(db, ""), false);
    assert.equal(await peersStorageAadCapable({ execute: async () => { throw new Error("boom"); } }, "self"), false);
  } finally {
    try { db?.close?.(); } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("peersStorageAadCapable: a look-alike key that only the old LIKE pattern matched is not a capability", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crow-sa-wildcard-"));
  let db = null;
  try {
    db = await makeRealDb(dir);
    await addPeerRow(db, "peerOld");
    // `_` is LIKE's single-character wildcard, so a row under this key matched
    // `LIKE 'tailnet_sync_sa:%'` without being the peer's capability at all.
    const realKey = `${SYNC_SA_KEY_PREFIX}peerOld`;
    const lookAlike = `${SYNC_SA_KEY_PREFIX.replace("_", "X")}peerOld`;
    assert.notEqual(lookAlike, realKey);
    await db.execute({
      sql: "INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at) VALUES (?, ?, ?, datetime('now'))",
      args: [lookAlike, "self", "1"],
    });
    assert.equal(await peersStorageAadCapable(db, "self"), false, "the look-alike row is not that peer's capability");

    // The literal prefix still counts.
    await db.execute({
      sql: "INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at) VALUES (?, ?, ?, datetime('now'))",
      args: [realKey, "self", "1"],
    });
    assert.equal(await peersStorageAadCapable(db, "self"), true);
  } finally {
    try { db?.close?.(); } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

/* ───────────────────────────── the sync hello capability ───────────────────────────── */

before(() => _setAllowLoopbackAddressesForTest(true));
after(() => _setAllowLoopbackAddressesForTest(false));

const quiet = { warn: () => {}, log: () => {} };
const pointAt = (side, peer, port) => side.db.execute({
  sql: "UPDATE crow_instances SET gateway_url = ? WHERE id = ?",
  args: [`http://127.0.0.1:${port}`, peer.id],
});
const frameAt = (seen, dir, idx) => {
  const f = seen.find((x) => x.dir === dir && x.idx === idx);
  return f ? JSON.parse(f.text) : null;
};

test("tailnet-sync: both hellos carry sa: 1, both sides record the peer, and the fleet answers capable", async () => {
  const fleet = await makeFleet();
  const { a, b } = fleet;
  const A = await startGateway(fleet, a, { log: quiet });
  const B = await startGateway(fleet, b, { log: quiet });
  const seen = [];
  const relay = await startWsRelay(B.port, { onText: (dir, idx, text) => { seen.push({ dir, idx, text }); } });
  try {
    await pointAt(a, b, relay.port);
    await A.startClients();
    assert.ok(await until(() => a.mgr.hasDedicatedStream(b.id) && b.mgr.hasDedicatedStream(a.id), 15_000), "the link forms");

    assert.equal(frameAt(seen, "c2s", 1)?.sa, 1, "the client hello advertises the storage-AAD capability");
    assert.equal(frameAt(seen, "s2c", 1)?.sa, 1, "so does the CR-capable server hello");

    assert.ok(await until(async () => (await override(b.db, b.id, `${SYNC_SA_KEY_PREFIX}${a.id}`)) === "1", 5000),
      "the server records the client's advertised sa");
    assert.ok(await until(async () => (await override(a.db, a.id, `${SYNC_SA_KEY_PREFIX}${b.id}`)) === "1", 5000),
      "the client records the server's advertised sa");
    assert.equal(await peersStorageAadCapable(a.db, a.id), true);
    assert.equal(await peersStorageAadCapable(b.db, b.id), true);
  } finally {
    A.stopClients();
    await A.close();
    await B.close();
    await relay.close();
    await fleet.cleanup();
  }
});

test("tailnet-sync: a peer that advertises no sa is recorded as 0, so the fleet is NOT capable", async () => {
  const fleet = await makeFleet();
  const { a, b } = fleet;
  // Session MACs are off so a rewritten C1 does not change a transcript hash (this test is
  // about the capability record, not about binding), and the pair decision runs in `auto`
  // for the same reason (the default `require` refuses a peer that offers no session MACs).
  const A = await startGateway(fleet, a, { log: quiet, sessionMacOffer: false, pairBindingMode: "auto" });
  const B = await startGateway(fleet, b, { log: quiet, sessionMacOffer: false, pairBindingMode: "auto" });
  const seen = [];
  const realWarn = console.warn;
  const lines = [];
  console.warn = (...args) => { lines.push(args.map(String).join(" ")); };
  const relay = await startWsRelay(B.port, {
    onText: (dir, idx, text) => {
      // An older peer: the same authenticated hello, without the capability field.
      let out = text;
      if (dir === "c2s" && idx === 1) {
        const m = JSON.parse(text);
        delete m.sa;
        out = JSON.stringify(m);
      }
      seen.push({ dir, idx, text: out });
      return out === text ? undefined : out;
    },
  });
  try {
    await pointAt(a, b, relay.port);
    await A.startClients();
    assert.ok(await until(() => a.mgr.hasDedicatedStream(b.id), 15_000),
      `the link forms | frames: ${seen.map((f) => `${f.dir}${f.idx}`).join(",")} | dial: ${JSON.stringify(getPeerDialHealth()[b.id] || null)} | logs: ${lines.join(" ;; ")}`);
    assert.ok(await until(async () => (await override(b.db, b.id, `${SYNC_SA_KEY_PREFIX}${a.id}`)) === "0", 15_000),
      `the peer without sa is recorded as 0, not left unknown (got ${await override(b.db, b.id, `${SYNC_SA_KEY_PREFIX}${a.id}`)})`);
    assert.equal(frameAt(seen, "c2s", 1)?.sa, undefined, "the stripped hello really carried none");
    assert.equal(frameAt(seen, "s2c", 1)?.sa, 1, "our own hello still advertises it");
    assert.ok(await until(async () => (await override(a.db, a.id, `${SYNC_SA_KEY_PREFIX}${b.id}`)) === "1", 5000));

    assert.equal(await peersStorageAadCapable(b.db, b.id), false, "one old peer pins the fleet at v1");
    assert.equal(await peersStorageAadCapable(a.db, a.id), true, "the other side saw a capable peer");
  } finally {
    console.warn = realWarn;
    A.stopClients();
    await A.close();
    await B.close();
    await relay.close();
    await fleet.cleanup();
  }
});