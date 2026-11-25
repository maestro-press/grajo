/**
 * The profile-key helper (servers/gateway/ai/profile-keys.js, design §2.2/§2.3): the
 * precedence and blank-field rules, the outbound `toTransit` and the inbound
 * `fromTransit` table, and the "no keyring means no key" rule. Keys are fixtures.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import {
  readProfileKey, sealProfileForStorage, applySubmittedKey, stripProfileKeys,
  toTransit, fromTransit, fromTransitWithOutcome, PROFILE_KEY_SEAL_UNAVAILABLE,
  CLEAR,
} from "../servers/gateway/ai/profile-keys.js";
import { makeProfileKeyring } from "../servers/gateway/keychain/provider-key-box.js";
import { sealTransit, openTransit } from "../servers/gateway/keychain/profile-key-transport.js";

const sentinel = () => `sentinel-${randomUUID()}`;
const keyA = { id: "0123456789abcdef", seed: randomBytes(32) };
const keyB = { id: "fedcba9876543210", seed: randomBytes(32) };
const krA = makeProfileKeyring(keyA);
const krB = makeProfileKeyring(keyB);
const seed = randomBytes(32);
const SK = "stt_profiles";
const kind = "stt";
const prof = (extra = {}) => ({ id: "p1", name: "Groq", provider: "groq", baseUrl: "", defaultModel: "m", isDefault: true, ...extra });
const sealedOf = (plain, kr = krA, id = "p1") => kr.seal(`${kind}/${id}`, plain);
const SK1 = /^sk1:[0-9a-f]{16}:[0-9a-f]{16}:[A-Za-z0-9_-]+$/;

// ─── read ────────────────────────────────────────────────────────────────────
test("read: plaintext wins over the sealed value; sealed opens; no keyring, no id, junk -> null", () => {
  const a = sentinel(), b = sentinel();
  assert.equal(readProfileKey(prof({ apiKey: a, apiKeySealed: sealedOf(b) }), { kind, keyring: krA }), a);
  assert.equal(readProfileKey(prof({ apiKey: "", apiKeySealed: sealedOf(b) }), { kind, keyring: krA }), b);
  assert.equal(readProfileKey(prof({ apiKeySealed: sealedOf(b) }), { kind, keyring: null }), null);
  assert.equal(readProfileKey(prof({ apiKey: a }), { kind, keyring: undefined }), null);
  assert.equal(readProfileKey(prof({ apiKeySealed: sealedOf(b) }), { kind, keyring: krB }), null);
  assert.equal(readProfileKey(prof({ apiKeySealed: sealedOf(b) }), { kind: "tts", keyring: krA }), null);
  assert.equal(readProfileKey({ ...prof({ apiKeySealed: sealedOf(b) }), id: "p2" }, { kind, keyring: krA }), null);
  assert.equal(readProfileKey(prof({ apiKeySealed: "keep" }), { kind, keyring: krA }), null);
  assert.equal(readProfileKey(null, { kind, keyring: krA }), null);
  assert.equal(readProfileKey(prof({ apiKeySealed: "sk1:bad" }), { kind, keyring: krA }), null);
  const throwing = { open() { throw new Error("boom"); }, seal() { throw new Error("boom"); } };
  assert.equal(readProfileKey(prof({ apiKeySealed: sealedOf(b) }), { kind, keyring: throwing }), null);
});

// ─── seal for storage ────────────────────────────────────────────────────────
test("seal: plaintext + sealed -> the plaintext is sealed and replaces it; apiKey blanked", () => {
  const a = sentinel(), b = sentinel();
  const out = sealProfileForStorage(prof({ apiKey: a, apiKeySealed: sealedOf(b) }), { kind, keyring: krA });
  assert.equal(out.apiKey, "");
  assert.match(out.apiKeySealed, SK1);
  assert.equal(readProfileKey(out, { kind, keyring: krA }), a);
  assert.equal(out.name, "Groq");
});

test("seal: idempotent on a sealed profile, unchanged with no key, input never mutated", () => {
  const a = sentinel();
  const once = sealProfileForStorage(prof({ apiKey: a }), { kind, keyring: krA });
  const twice = sealProfileForStorage(once, { kind, keyring: krA });
  assert.deepEqual(twice, once);
  const keyless = prof({ apiKey: "" });
  assert.deepEqual(sealProfileForStorage(keyless, { kind, keyring: krA }), keyless);
  const keylessNoField = prof();
  assert.deepEqual(sealProfileForStorage(keylessNoField, { kind, keyring: null }), keylessNoField);
  const input = prof({ apiKey: a });
  const snapshot = JSON.stringify(input);
  sealProfileForStorage(input, { kind, keyring: krA });
  assert.equal(JSON.stringify(input), snapshot);
});

test("seal: a plaintext key with no keyring refuses (value-free), never stores it", () => {
  const a = sentinel();
  assert.throws(() => sealProfileForStorage(prof({ apiKey: a }), { kind, keyring: null }),
    (e) => e.code === PROFILE_KEY_SEAL_UNAVAILABLE && !String(e.message).includes(a) && !String(e.stack).includes(a));
  const liar = { open: () => null, seal: () => `ps1:${a}` };
  assert.throws(() => sealProfileForStorage(prof({ apiKey: a }), { kind, keyring: liar }), (e) => e.code === PROFILE_KEY_SEAL_UNAVAILABLE);
});

test("seal: a ps1: or keep in apiKeySealed never survives into storage form", () => {
  const out = sealProfileForStorage(prof({ apiKeySealed: sealTransit({ seed, settingKey: SK, profileId: "p1", plaintext: sentinel() }) }), { kind, keyring: krA });
  assert.equal("apiKeySealed" in out, false);
  assert.equal(JSON.stringify(out).includes("ps1:"), false);
  assert.equal("apiKeySealed" in sealProfileForStorage(prof({ apiKeySealed: "keep" }), { kind, keyring: krA }), false);
});

// ─── submitted key (blank-field rule) ────────────────────────────────────────
test("submitted: edit+blank keeps the stored key, create+blank is none, non-blank seals", () => {
  const a = sentinel(), b = sentinel();
  const existing = sealProfileForStorage(prof({ apiKey: a }), { kind, keyring: krA });
  for (const blank of ["", "   ", undefined, null]) {
    const kept = applySubmittedKey(existing, blank, { mode: "edit", kind, keyring: krA });
    assert.equal(kept.apiKeySealed, existing.apiKeySealed);
    const created = applySubmittedKey(existing, blank, { mode: "create", kind, keyring: krA });
    assert.equal("apiKeySealed" in created, false);
    assert.equal(created.apiKey || "", "");
  }
  const edited = applySubmittedKey(existing, `  ${b}  `, { mode: "edit", kind, keyring: krA });
  assert.equal(edited.apiKey, "");
  assert.equal(readProfileKey(edited, { kind, keyring: krA }), b);
  const made = applySubmittedKey(prof(), b, { mode: "create", kind, keyring: krA });
  assert.match(made.apiKeySealed, SK1);
  assert.throws(() => applySubmittedKey(prof(), b, { mode: "create", kind, keyring: null }), (e) => e.code === PROFILE_KEY_SEAL_UNAVAILABLE);
});

test("strip: removes both fields and nothing else", () => {
  const out = stripProfileKeys(prof({ apiKey: sentinel(), apiKeySealed: sealedOf(sentinel()) }));
  assert.equal("apiKey" in out, false);
  assert.equal("apiKeySealed" in out, false);
  assert.equal(out.name, "Groq");
});

// ─── toTransit (outbound) ────────────────────────────────────────────────────
test("toTransit: sk1 -> ps1 that the identity seed opens; no sk1, no plaintext in the output", () => {
  const a = sentinel();
  const stored = sealProfileForStorage(prof({ apiKey: a }), { kind, keyring: krA });
  const { profile, refused } = toTransit(stored, { settingKey: SK, kind, keyring: krA, seed });
  assert.equal(refused, false);
  assert.equal(profile.apiKey, "");
  assert.match(profile.apiKeySealed, /^ps1:/);
  assert.equal(openTransit({ seed, settingKey: SK, profileId: "p1", stored: profile.apiKeySealed }), a);
  const json = JSON.stringify(profile);
  assert.equal(json.includes(a), false);
  assert.equal(json.includes("sk1:"), false);
});

test("toTransit: a legacy plaintext (precedence) is sealed to ps1", () => {
  const a = sentinel(), b = sentinel();
  const { profile } = toTransit(prof({ apiKey: a, apiKeySealed: sealedOf(b) }), { settingKey: SK, kind, keyring: krA, seed });
  assert.equal(openTransit({ seed, settingKey: SK, profileId: "p1", stored: profile.apiKeySealed }), a);
});

test("toTransit: no keyring -> keep + refused, never plaintext or sk1 or ps1", () => {
  const a = sentinel();
  for (const input of [prof({ apiKey: a }), prof({ apiKeySealed: sealedOf(a) })]) {
    const { profile, refused } = toTransit(input, { settingKey: SK, kind, keyring: null, seed });
    assert.equal(refused, true);
    assert.equal(profile.apiKeySealed, "keep");
    assert.equal(profile.apiKey, "");
    const json = JSON.stringify(profile);
    for (const bad of [a, "sk1:", "ps1:"]) assert.equal(json.includes(bad), false);
  }
});

test("toTransit: an sk1 under another keychain key, junk, or a bad seed -> keep + refused, never throws", () => {
  const a = sentinel();
  const foreign = sealedOf(a, krB);
  assert.deepEqual(toTransit(prof({ apiKeySealed: foreign }), { settingKey: SK, kind, keyring: krA, seed }),
    { profile: prof({ apiKeySealed: "keep", apiKey: "" }), refused: true });
  assert.equal(toTransit(prof({ apiKeySealed: "garbage" }), { settingKey: SK, kind, keyring: krA, seed }).refused, true);
  assert.equal(toTransit(prof({ apiKeySealed: sealedOf(a) }), { settingKey: SK, kind, keyring: krA, seed: null }).profile.apiKeySealed, "keep");
  assert.equal(toTransit(prof({ apiKeySealed: sealedOf(a) }), { settingKey: "providers", kind, keyring: krA, seed }).refused, true);
  assert.equal(toTransit({ name: "no id", apiKeySealed: sealedOf(a) }, { settingKey: SK, kind, keyring: krA, seed }).refused, true);
});

test("toTransit: a keyless profile carries the CLEAR marker and is not refused", () => {
  const { profile, refused } = toTransit(prof({ apiKey: "" }), { settingKey: SK, kind, keyring: krA, seed });
  assert.equal(refused, false);
  assert.equal(profile.apiKeySealed, CLEAR);
  assert.equal(profile.apiKey, "");
});

// ─── fromTransit (inbound table, design §2.2) ────────────────────────────────
const wire = (plain, id = "p1") => sealTransit({ seed, settingKey: SK, profileId: id, plaintext: plain });
const opts = (o = {}) => ({ settingKey: SK, kind, keyring: krA, seed, senderCapable: true, ...o });
const localWith = (plain) => sealProfileForStorage(prof({ apiKey: plain }), { kind, keyring: krA });

test("fromTransit: a ps1 that opens becomes this instance's sk1", () => {
  const a = sentinel();
  const r = fromTransitWithOutcome(prof({ apiKey: "", apiKeySealed: wire(a), name: "New name" }), localWith(sentinel()), opts());
  assert.equal(r.outcome, "applied");
  assert.match(r.profile.apiKeySealed, SK1);
  assert.equal(r.profile.apiKey, "");
  assert.equal(r.profile.name, "New name");
  assert.equal(readProfileKey(r.profile, { kind, keyring: krA }), a);
  // Sealed under the RECEIVER's key: the sender's other keychain key cannot open it.
  assert.equal(readProfileKey(r.profile, { kind, keyring: krB }), null);
});

test("fromTransit: ps1 that fails (wrong profile, bad gen, junk) keeps the local key", () => {
  const l = sentinel();
  const local = localWith(l);
  const blob = Buffer.from(wire(sentinel()).slice(4), "base64url");
  blob[0] = 0x02;
  for (const bad of [wire(sentinel(), "other"), "ps1:" + blob.toString("base64url"), "ps1:!!", "enc:v1:abc"]) {
    const r = fromTransitWithOutcome(prof({ apiKeySealed: bad }), local, opts());
    assert.equal(r.outcome, "failed");
    assert.equal(r.profile.apiKeySealed, local.apiKeySealed);
  }
  // With no local key, a failure leaves no key (never the ciphertext).
  const none = fromTransit(prof({ apiKeySealed: wire(sentinel(), "other") }), null, opts());
  assert.equal("apiKeySealed" in none, false);
});

test("fromTransit: keep keeps the local key (and none if there is none)", () => {
  const local = localWith(sentinel());
  assert.equal(fromTransit(prof({ apiKeySealed: "keep" }), local, opts()).apiKeySealed, local.apiKeySealed);
  assert.equal("apiKeySealed" in fromTransit(prof({ apiKeySealed: "keep" }), null, opts()), false);
});

test("fromTransit: a blank NEVER clears, from any sender; only the explicit CLEAR marker does", () => {
  const local = localWith(sentinel());
  for (const blank of [prof({ apiKey: "" }), prof()]) {
    for (const senderCapable of [true, false, undefined]) {
      const r = fromTransitWithOutcome(blank, local, opts({ senderCapable }));
      assert.equal(r.outcome, "kept");
      assert.equal(r.profile.apiKeySealed, local.apiKeySealed);
    }
  }
  // The explicit marker clears for a capable sender only.
  const cleared = fromTransitWithOutcome(prof({ apiKeySealed: CLEAR }), local, opts({ senderCapable: true }));
  assert.equal(cleared.outcome, "cleared");
  assert.equal("apiKeySealed" in cleared.profile, false);
  for (const senderCapable of [false, undefined]) {
    const kept = fromTransitWithOutcome(prof({ apiKeySealed: CLEAR }), local, opts({ senderCapable }));
    assert.equal(kept.outcome, "kept");
    assert.equal(kept.profile.apiKeySealed, local.apiKeySealed);
  }
});

test("toTransit: a keyless profile goes out with the explicit CLEAR marker", () => {
  for (const p of [prof(), prof({ apiKey: "" }), prof({ apiKey: "none" })]) {
    const t = toTransit(p, { settingKey: SK, kind, keyring: krA, seed });
    assert.equal(t.refused, false);
    assert.equal(t.profile.apiKeySealed, CLEAR);
    assert.equal(t.profile.apiKey, "");
  }
});

test("fromTransit: a non-empty plaintext apiKey is stored sealed (and wins over a sealed field)", () => {
  const a = sentinel();
  const r = fromTransit(prof({ apiKey: a, apiKeySealed: "keep" }), localWith(sentinel()), opts());
  assert.equal(r.apiKey, "");
  assert.equal(readProfileKey(r, { kind, keyring: krA }), a);
  assert.equal(JSON.stringify(r).includes(a), false);
});

test("fromTransit: any incoming sk1 is treated as a failed ps1", () => {
  const local = localWith(sentinel());
  const r = fromTransitWithOutcome(prof({ apiKeySealed: sealedOf(sentinel(), krA) }), local, opts());
  assert.equal(r.outcome, "failed");
  assert.equal(r.profile.apiKeySealed, local.apiKeySealed);
});

test("fromTransit: no keyring never stores a ps1 or opens one; the local key stays", () => {
  const a = sentinel();
  const local = localWith(sentinel());
  const r = fromTransitWithOutcome(prof({ apiKeySealed: wire(a) }), local, opts({ keyring: null }));
  assert.equal(r.outcome, "failed");
  assert.equal(r.profile.apiKeySealed, local.apiKeySealed);
  const p = fromTransit(prof({ apiKey: a }), null, opts({ keyring: null }));
  assert.equal(JSON.stringify(p).includes(a), false);
});

test("fromTransit: a local profile with another id is not its local key", () => {
  const other = { ...localWith(sentinel()), id: "p9" };
  assert.equal("apiKeySealed" in fromTransit(prof({ apiKeySealed: "keep" }), other, opts()), false);
});

test("fromTransit: a local legacy plaintext is sealed when kept (never lost, never ps1)", () => {
  const l = sentinel();
  const r = fromTransit(prof({ apiKeySealed: "keep" }), prof({ apiKey: l }), opts());
  assert.equal(readProfileKey(r, { kind, keyring: krA }), l);
  assert.equal(r.apiKey, "");
});

test("no storage-form output ever contains ps1:", () => {
  const a = sentinel();
  const outs = [
    sealProfileForStorage(prof({ apiKey: a }), { kind, keyring: krA }),
    fromTransit(prof({ apiKeySealed: wire(a) }), null, opts()),
    fromTransit(prof({ apiKeySealed: wire(a, "x") }), null, opts()),
    fromTransit(prof({ apiKeySealed: "keep" }), localWith(a), opts()),
    fromTransit(prof({ apiKey: a }), null, opts()),
    applySubmittedKey(prof(), a, { mode: "create", kind, keyring: krA }),
  ];
  for (const o of outs) assert.equal(JSON.stringify(o).includes("ps1:"), false);
});

test("a planted plaintext never appears in an error or in a returned value (except the read result)", () => {
  const a = sentinel();
  const trap = { open() { throw new Error(a); }, seal() { throw new Error(a); } };
  const run = (fn) => { try { return fn(); } catch (e) { assert.equal(`${e.message}${e.stack}`.includes(a), false); return null; } };
  const results = [
    run(() => sealProfileForStorage(prof({ apiKey: a }), { kind, keyring: trap })),
    run(() => toTransit(prof({ apiKey: a }), { settingKey: SK, kind, keyring: trap, seed })),
    run(() => fromTransit(prof({ apiKey: a }), null, opts({ keyring: trap }))),
    run(() => applySubmittedKey(prof(), a, { mode: "create", kind, keyring: trap })),
    run(() => toTransit(prof({ apiKey: a }), { settingKey: SK, kind, keyring: krA, seed })),
  ];
  for (const r of results) assert.equal(JSON.stringify(r ?? null).includes(a), false);
});

// ─── round 2 ─────────────────────────────────────────────────────────────────
test("none: a trimmed exact `none` is no key everywhere (stored as apiKey \"\", never sealed, never a failure)", () => {
  for (const none of ["none", "  none\n"]) {
    const out = sealProfileForStorage(prof({ apiKey: none }), { kind, keyring: krA });
    assert.equal(out.apiKey, "");
    assert.equal("apiKeySealed" in out, false);
    // Not even a keyring is needed: nothing is sealed.
    assert.equal(sealProfileForStorage(prof({ apiKey: none }), { kind, keyring: null }).apiKey, "");
    assert.equal(readProfileKey(prof({ apiKey: none }), { kind, keyring: krA }), null);
    const t = toTransit(prof({ apiKey: none }), { settingKey: SK, kind, keyring: krA, seed });
    assert.equal(t.refused, false);
    assert.equal(t.profile.apiKeySealed, CLEAR);
    // Inbound plaintext "none": a blank, so it never clears.
    const local = localWith(sentinel());
    assert.equal(fromTransitWithOutcome(prof({ apiKey: none }), local, opts()).outcome, "kept");
    assert.equal(fromTransit(prof({ apiKey: none }), local, opts({ senderCapable: false })).apiKeySealed, local.apiKeySealed);
    // A submitted "none" is an explicit no-key, in both modes.
    for (const mode of ["create", "edit"]) {
      const sub = applySubmittedKey(localWith(sentinel()), none, { mode, kind, keyring: krA });
      assert.equal("apiKeySealed" in sub, false);
      assert.equal(sub.apiKey, "");
    }
  }
  // The casing rule is P1a's: only the exact lower-case sentinel is "no key".
  const upper = sealProfileForStorage(prof({ apiKey: "None" }), { kind, keyring: krA });
  assert.match(upper.apiKeySealed, SK1);
});

test("none: a ps1 that opens to none is cleared, not failed, and never sealed", () => {
  const local = localWith(sentinel());
  const none = wire("none");
  const r = fromTransitWithOutcome(prof({ apiKeySealed: none }), local, opts({ senderCapable: false }));
  assert.equal(r.outcome, "cleared");
  assert.equal("apiKeySealed" in r.profile, false);
});

test("edit + blank re-normalises: stray ps1/keep dropped, legacy plaintext sealed, a sealed key kept", () => {
  const l = sentinel();
  const stray = applySubmittedKey(prof({ apiKeySealed: "keep" }), "", { mode: "edit", kind, keyring: krA });
  assert.equal("apiKeySealed" in stray, false);
  const ps = applySubmittedKey(prof({ apiKeySealed: wire(sentinel()) }), "  ", { mode: "edit", kind, keyring: krA });
  assert.equal(JSON.stringify(ps).includes("ps1:"), false);
  const legacy = applySubmittedKey(prof({ apiKey: l }), undefined, { mode: "edit", kind, keyring: krA });
  assert.equal(legacy.apiKey, "");
  assert.equal(readProfileKey(legacy, { kind, keyring: krA }), l);
  assert.equal(JSON.stringify(legacy).includes(l), false);
  const sealed = localWith(sentinel());
  assert.equal(applySubmittedKey(sealed, "", { mode: "edit", kind, keyring: krA }).apiKeySealed, sealed.apiKeySealed);
  assert.throws(() => applySubmittedKey(prof({ apiKey: l }), "", { mode: "edit", kind, keyring: null }),
    (e) => e.code === PROFILE_KEY_SEAL_UNAVAILABLE && !String(e.message).includes(l));
});

test("fromTransit: junk key fields are never blank: failed, local key kept", () => {
  const local = localWith(sentinel());
  for (const junk of [
    { apiKeySealed: 5 }, { apiKeySealed: {} }, { apiKeySealed: true }, { apiKeySealed: [] }, { apiKeySealed: null },
    { apiKeySealed: "" }, { apiKey: 7 }, { apiKey: null }, { apiKey: {} }, { apiKey: [] }, { apiKey: false },
    { apiKey: "", apiKeySealed: 0 },
  ]) {
    const r = fromTransitWithOutcome(prof(junk), local, opts({ senderCapable: true }));
    assert.equal(r.outcome, "failed", JSON.stringify(junk));
    assert.equal(r.profile.apiKeySealed, local.apiKeySealed);
  }
  // Genuinely blank forms keep the local key (only CLEAR removes it).
  for (const blank of [prof(), prof({ apiKey: "" })]) {
    assert.equal(fromTransitWithOutcome(blank, local, opts({ senderCapable: true })).outcome, "kept");
  }
});

test("seal: a non-string apiKey does not survive into storage", () => {
  for (const junk of [5, null, {}, [], true]) {
    const out = sealProfileForStorage(prof({ apiKey: junk }), { kind, keyring: krA });
    assert.equal(out.apiKey, "");
    assert.equal("apiKeySealed" in out, false);
    const withSealedKey = sealProfileForStorage(prof({ apiKey: junk, apiKeySealed: sealedOf(sentinel()) }), { kind, keyring: krA });
    assert.equal(withSealedKey.apiKey, "");
    assert.match(withSealedKey.apiKeySealed, SK1);
  }
});

test("submitted: an unknown or missing mode throws a value-free error and never drops the key", () => {
  const a = sentinel();
  const existing = localWith(a);
  for (const mode of [undefined, null, "", "update", "EDIT", 1]) {
    assert.throws(() => applySubmittedKey(existing, a, { mode, kind, keyring: krA }),
      (e) => e.code === "PROFILE_KEY_MODE_INVALID" && !String(e.message + e.stack).includes(a));
    assert.throws(() => applySubmittedKey(existing, "", { mode, kind, keyring: krA }), (e) => e.code === "PROFILE_KEY_MODE_INVALID");
  }
  assert.throws(() => applySubmittedKey(existing, "", {}), (e) => e.code === "PROFILE_KEY_MODE_INVALID");
});

test("fromTransit: with no valid incoming id there is no local key to keep", () => {
  const local = { ...localWith(sentinel()) };
  delete local.id;
  const noId = { name: "x", apiKeySealed: "keep" };
  assert.equal("apiKeySealed" in fromTransit(noId, local, opts()), false);
  for (const id of [5, null, "", "a".repeat(257), "\ud800"]) {
    const l = { ...localWith(sentinel()), id };
    const r = fromTransit({ ...noId, id }, l, opts());
    assert.equal("apiKeySealed" in r, false);
  }
});

// ─── static guard (design §4 Guards) ─────────────────────────────────────────
test.todo("static: no production file but profile-keys.js writes a non-empty apiKey into the four blobs " +
  "(not expressible yet: the settings sections, kiosk profiles.js and roles-api still write apiKey directly until the readers/writers are rewired in PR 3)");

test("the helper imports no identity or mint code and no other production module imports it", () => {
  const src = readFileSync(new URL("../servers/gateway/ai/profile-keys.js", import.meta.url), "utf8");
  assert.equal(/sharing\/identity|secret-box|createKeychainKey|loadKeychainKey/.test(src), false);
  const root = new URL("..", import.meta.url).pathname;
  const hits = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (["node_modules", ".git", "tests"].includes(e.name)) continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.m?js$/.test(e.name) && !p.endsWith("ai/profile-keys.js")) {
        if (/(?:from|import\(|require\()\s*["'][^"']*profile-keys\.js["']/.test(readFileSync(p, "utf8"))) hits.push(p.slice(root.length));
      }
    }
  };
  for (const d of ["servers", "scripts", "bundles"]) { try { walk(join(root, d)); } catch { /* absent */ } }
  assert.deepEqual(hits, []);
});
