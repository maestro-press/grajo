// Crow Mail provider presets (plan 5, Task 1): the IMAP/SMTP settings Crow offers for an address at a
// big provider.
//
// Two kinds of check here. The first pins the values, because a preset's whole worth is that its host,
// port and security were read off the provider's own page (each preset carries that page in `sources`).
// The second hands every preset to the REAL account store — createAccount, a scratch DB built from
// MAIL_DDL — so a preset that the store would refuse cannot ship: the settings a preset offers are
// exactly the settings the store accepts, and the test cannot drift from its validation.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { MAIL_DDL, MAIL_ACCOUNT_SEND_COLUMNS } from "../servers/shared/mail-schema.js";
import { createAccount } from "../servers/gateway/mail/store/accounts.js";
import { PRESETS, presetFor, presetForDomain } from "../servers/gateway/mail/providers/presets.js";

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function tmp(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

async function freshDb() {
  const db = createDbClient(join(tmp("crow-preset-db-"), "crow.db"));
  await db.executeMultiple(MAIL_DDL);
  // The account send columns (the ADD COLUMN specs) are not part of MAIL_DDL.
  for (const spec of MAIL_ACCOUNT_SEND_COLUMNS) {
    await db.execute({ sql: `ALTER TABLE ${spec.table} ADD COLUMN ${spec.column} ${spec.definition}`, args: [] });
  }
  return db;
}

const byId = (id) => PRESETS.find((preset) => preset.id === id);
const PROVIDER_IDS = ["gmail", "outlook", "icloud", "fastmail", "yahoo"];
const ALL_IDS = ["gmail", "outlook", "fastmail", "icloud", "yahoo", "proton-bridge", "generic"];

/** Every string anywhere in a preset, with the path it sits at (for a readable failure). */
function stringsIn(value, path = "", out = []) {
  if (typeof value === "string") {
    out.push([path, value]);
    return out;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => stringsIn(entry, `${path}[${index}]`, out));
    return out;
  }
  if (value && typeof value === "object") {
    for (const [key, inner] of Object.entries(value)) stringsIn(inner, path === "" ? key : `${path}.${key}`, out);
  }
  return out;
}

/** The account store's endpoint rules, mirrored: a host, a port in range, and a security it accepts. */
function assertEndpointShape(endpoint, where) {
  assert.ok(endpoint && typeof endpoint === "object", `${where} is an endpoint`);
  assert.equal(typeof endpoint.host, "string", `${where}.host is a string`);
  assert.ok(endpoint.host.length > 0, `${where}.host is not empty`);
  assert.match(endpoint.host, /^[A-Za-z0-9.:-]+$/, `${where}.host is a host name or a literal address`);
  assert.ok(Number.isInteger(endpoint.port), `${where}.port is an integer`);
  assert.ok(endpoint.port >= 1 && endpoint.port <= 65535, `${where}.port is in 1-65535`);
  assert.ok(["ssl", "starttls"].includes(endpoint.security), `${where}.security is ssl or starttls`);
  assert.notEqual(endpoint.security, "none", `${where}.security never offers a cleartext login`);
}

/* ----------------------------------------------------------------- the ids */

test("the preset set is the seven ids, in a fixed order, and every provider id is there", () => {
  assert.deepEqual(PRESETS.map((preset) => preset.id), ALL_IDS);
  for (const id of PROVIDER_IDS) assert.ok(byId(id), `${id} has a preset`);
  for (const preset of PRESETS) {
    assert.equal(typeof preset.label, "string");
    assert.ok(preset.label.length > 0, `${preset.id} is named`);
    assert.ok(Array.isArray(preset.notes), `${preset.id}.notes is a list`);
    assert.ok(Array.isArray(preset.sources), `${preset.id}.sources is a list`);
    assert.ok(Array.isArray(preset.authKinds), `${preset.id}.authKinds is a list`);
    assert.ok(["provider", "append"].includes(preset.sentCopy), `${preset.id}.sentCopy is one of the two modes`);
    assert.equal(preset.id, preset.id.toLowerCase(), "ids stay lower-case, as an account's provider column holds them");
  }
});

/* -------------------------------------------------------------- the values */

test("every preset carries the verified host, port, security and Sent-copy rule", () => {
  const VERIFIED = [
    ["gmail", "imap.gmail.com", 993, "ssl", "smtp.gmail.com", 465, "ssl", "provider"],
    ["outlook", "outlook.office365.com", 993, "ssl", "smtp-mail.outlook.com", 587, "starttls", "append"],
    ["fastmail", "imap.fastmail.com", 993, "ssl", "smtp.fastmail.com", 465, "ssl", "append"],
    ["icloud", "imap.mail.me.com", 993, "ssl", "smtp.mail.me.com", 587, "starttls", "append"],
    ["yahoo", "imap.mail.yahoo.com", 993, "ssl", "smtp.mail.yahoo.com", 465, "ssl", "append"],
    ["proton-bridge", "127.0.0.1", 1143, "starttls", "127.0.0.1", 1025, "starttls", "append"],
  ];
  for (const [id, imapHost, imapPort, imapSecurity, smtpHost, smtpPort, smtpSecurity, sentCopy] of VERIFIED) {
    const preset = byId(id);
    assert.ok(preset, `${id} has a preset`);
    assert.deepEqual(preset.imap, { host: imapHost, port: imapPort, security: imapSecurity }, `${id}.imap`);
    assert.deepEqual(preset.smtp, { host: smtpHost, port: smtpPort, security: smtpSecurity }, `${id}.smtp`);
    assert.equal(preset.sentCopy, sentCopy, `${id}.sentCopy`);
  }
});

/* ------------------------------------------------------- shape before store */

test("every non-generic preset is a pair of endpoints the store's rules accept", () => {
  for (const preset of PRESETS) {
    if (preset.id === "generic") {
      // "generic" is the manual door: it offers no host at all, so the owner types one.
      assert.equal(preset.imap, null, "generic offers no IMAP host");
      assert.equal(preset.smtp, null, "generic offers no SMTP host");
      assert.deepEqual([...preset.authKinds], ["password"], "generic offers only a password");
      continue;
    }
    assertEndpointShape(preset.imap, `${preset.id}.imap`);
    assertEndpointShape(preset.smtp, `${preset.id}.smtp`);
    // Gmail takes an app password and OAuth2; Outlook.com requires Modern Auth (see the test below).
    const expected = preset.id === "gmail"
      ? ["password", "xoauth2"]
      : preset.id === "outlook" ? ["xoauth2"] : ["password"];
    assert.deepEqual([...preset.authKinds].sort(), expected, `${preset.id}.authKinds`);
  }
});

/* ------------------------------------------------- the account store itself */

test("every non-generic preset is accepted by the account store, unchanged", async () => {
  const db = await freshDb();
  for (const preset of PRESETS) {
    if (preset.id === "generic") continue;
    const account = await createAccount(db, {
      label: preset.label,
      address: `${preset.id}@example.test`,
      imap: { ...preset.imap },
      smtp: { ...preset.smtp },
    });
    assert.ok(account && account.id, `${preset.id} was stored`);
    assert.deepEqual(account.imap, preset.imap, `${preset.id}: the store read back its IMAP endpoint`);
    assert.deepEqual(account.smtp, preset.smtp, `${preset.id}: the store read back its SMTP endpoint`);
  }
  // And an xoauth2 account, for the two presets that offer it: the store's own kind list must hold it.
  for (const id of ["gmail", "outlook"]) {
    const preset = byId(id);
    const account = await createAccount(db, {
      label: preset.label,
      address: `${id}+oauth@example.test`,
      authKind: "xoauth2",
      imap: { ...preset.imap },
      smtp: { ...preset.smtp },
    });
    assert.equal(account.authKind, "xoauth2", `${id}: an OAuth account is storable`);
  }
});

/* -------------------------------------------------------------- the lookup */

test("presetForDomain matches a provider domain, case-insensitively, and answers null otherwise", () => {
  assert.equal(presetForDomain("example.test"), null, "an unknown domain has no preset");
  assert.equal(presetForDomain("gmail.com"), byId("gmail"));
  assert.equal(presetForDomain("GoogleMail.COM"), byId("gmail"));
  assert.equal(presetForDomain("outlook.com"), byId("outlook"));
  assert.equal(presetForDomain("Hotmail.com"), byId("outlook"));
  assert.equal(presetForDomain("live.com"), byId("outlook"));
  assert.equal(presetForDomain("icloud.com"), byId("icloud"));
  assert.equal(presetForDomain("me.com"), byId("icloud"));
  assert.equal(presetForDomain("fastmail.com"), byId("fastmail"));
  assert.equal(presetForDomain("yahoo.com"), byId("yahoo"));

  // A provider domain is matched as a whole domain, never as a substring or a suffix of another one.
  assert.equal(presetForDomain("notgmail.com"), null);
  assert.equal(presetForDomain("mail.gmail.com"), null);
  assert.equal(presetForDomain("gmail.com.evil.test"), null);
  assert.equal(presetForDomain(""), null);
  assert.equal(presetForDomain("   "), null);
  assert.equal(presetForDomain(null), null);
  assert.equal(presetForDomain(undefined), null);
});

test("presetFor reads an address's domain and never the local part", () => {
  // The one address this file builds: assembled at runtime so no provider-domain address sits in the
  // source of a public repository.
  assert.equal(presetFor(["Alex", "GMail.com"].join("@")), byId("gmail"));
  assert.equal(presetFor("alex@example.test"), null, "an unknown domain has no preset");
  assert.equal(presetFor("no-at-sign"), null, "no @ is no domain");
});

/* ------------------------------------------------------------ auth / copies */

test("only gmail and outlook offer xoauth2, outlook offers ONLY it, and only gmail's provider files the Sent copy", () => {
  const oauth = PRESETS.filter((preset) => preset.authKinds.includes("xoauth2")).map((preset) => preset.id);
  assert.deepEqual(oauth, ["gmail", "outlook"]);
  // Microsoft's own IMAP/SMTP page, cited by the outlook preset, says Outlook.com requires Modern
  // authentication (OAuth2) for IMAP and SMTP: the preset must not offer a password it would refuse.
  assert.deepEqual([...byId("outlook").authKinds], ["xoauth2"], "Outlook.com is Modern Auth only");
  assert.deepEqual([...byId("gmail").authKinds], ["password", "xoauth2"], "Gmail still takes an app password");
  for (const preset of PRESETS) {
    assert.equal(preset.id === "outlook" || preset.authKinds.includes("password") || preset.id === "generic", true,
      `${preset.id} offers a password unless the provider refuses one`);
    assert.equal(preset.authKinds.includes("oauth2"), false, `${preset.id} uses the store's own kind name`);
  }
  const provider = PRESETS.filter((preset) => preset.sentCopy === "provider").map((preset) => preset.id);
  assert.deepEqual(provider, ["gmail"], "only Gmail is confirmed to file an SMTP-sent message itself");
  assert.equal(byId("outlook").sentCopy, "append", "an unconfirmed provider gets the safe default");
  assert.equal(byId("generic").sentCopy, "append");
});

/* ------------------------------------------------------------------ notes */

test("the proton-bridge note is an i18n KEY, and no note is a rendered sentence", () => {
  const notes = PRESETS.flatMap((preset) => preset.notes);
  for (const note of notes) {
    assert.equal(typeof note, "string");
    assert.match(note, /^mail\.preset\.[A-Za-z0-9.]+$/, "a note is a key, not English text");
  }
  assert.deepEqual([...byId("proton-bridge").notes], ["mail.preset.protonBridgePorts"],
    "Bridge picks its own ports, so the person is told to use the ones Bridge shows");
});

/* ---------------------------------------------------------------- sources */

test("every provider except proton-bridge and generic links the page its settings came from", () => {
  for (const preset of PRESETS) {
    if (preset.id === "proton-bridge" || preset.id === "generic") {
      assert.deepEqual([...preset.sources], [], `${preset.id} makes no claim it cannot cite`);
      continue;
    }
    assert.ok(preset.sources.length > 0, `${preset.id} cites its source`);
    for (const source of preset.sources) assert.match(source, /^https:\/\//, `${preset.id}: a source is https`);
  }
});

/* ------------------------------------------------------------------ freeze */

test("PRESETS is deep-frozen, so no caller can edit a provider's settings", () => {
  assert.ok(Object.isFrozen(PRESETS), "the list is frozen");
  for (const preset of PRESETS) {
    assert.ok(Object.isFrozen(preset), `${preset.id} is frozen`);
    for (const key of Object.keys(preset)) {
      const value = preset[key];
      if (value && typeof value === "object") assert.ok(Object.isFrozen(value), `${preset.id}.${key} is frozen`);
    }
  }
  // ESM is strict mode, so a write to frozen data throws rather than being silently dropped.
  assert.throws(() => { PRESETS.push({ id: "evil" }); }, TypeError);
  assert.throws(() => { PRESETS[0] = { id: "evil" }; }, TypeError);
  assert.throws(() => { byId("gmail").imap.host = "evil.example.test"; }, TypeError);
  assert.throws(() => { byId("gmail").smtp.port = 25; }, TypeError);
  assert.throws(() => { byId("gmail").authKinds.push("none"); }, TypeError);
  assert.throws(() => { byId("gmail").sources.push("https://evil.example.test"); }, TypeError);
  assert.equal(byId("gmail").imap.host, "imap.gmail.com");
  assert.equal(byId("gmail").smtp.port, 465);
});

/* ----------------------------------------------------------------- hygiene */

test("no preset carries an address, a username or a credential", () => {
  for (const preset of PRESETS) {
    for (const [path, text] of stringsIn(preset)) {
      assert.equal(text.includes("@"), false, `${preset.id}.${path} carries an @`);
      assert.equal(/password|secret|token/i.test(path), false, `${preset.id}.${path} is a credential slot`);
    }
  }
});