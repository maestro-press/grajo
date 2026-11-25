/**
 * The profile-key transit box (`ps1:`, design §2.1) and the at-rest `sk1:` purpose of the
 * provider-key box (design §2.1, profile purpose). Every key here is a fixture.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { sealTransit, openTransit, TRANSIT_SETTING_KEYS } from "../servers/gateway/keychain/profile-key-transport.js";
import { seal, open, makeProfileKeyring, isProfileSlotId } from "../servers/gateway/keychain/provider-key-box.js";
import { loadKeychainKey, keychainKeyState } from "../servers/gateway/keychain/key.js";
import { sealSecret } from "../servers/sharing/secret-box.js";
import {
  hasProviderKey, isProviderKeyEnvelope, parseStoredKey, parseProfileEnvelope, isProfileKeyEnvelope,
} from "../servers/shared/provider-key-shape.js";

const scratch = mkdtempSync(join(tmpdir(), "crow-pk-transport-"));
after(() => { try { rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } });

const seed = randomBytes(32);
const sentinel = () => `sentinel-${randomUUID()}`;
const base = { seed, settingKey: "stt_profiles", profileId: "p1" };

test("transit: round trip, trimmed, and every setting key", () => {
  const k = sentinel();
  const env = sealTransit({ ...base, plaintext: `  ${k}\n` });
  assert.match(env, /^ps1:[A-Za-z0-9_-]+$/);
  assert.equal(openTransit({ ...base, stored: env }), k);
  for (const settingKey of TRANSIT_SETTING_KEYS) {
    const e = sealTransit({ ...base, settingKey, plaintext: k });
    assert.equal(openTransit({ ...base, settingKey, stored: e }), k);
  }
});

test("transit: layout is exactly gen(1) + nonce(12) + n + tag(16), no fingerprint, fresh nonce", () => {
  const k = sentinel();
  const a = sealTransit({ ...base, plaintext: k });
  const b = sealTransit({ ...base, plaintext: k });
  assert.notEqual(a, b);
  const blob = Buffer.from(a.slice(4), "base64url");
  assert.equal(blob.length, 1 + 12 + Buffer.byteLength(k) + 16);
  assert.equal(blob[0], 0x01);
  assert.notDeepEqual(blob.subarray(1, 13), Buffer.from(b.slice(4), "base64url").subarray(1, 13));
  // The plaintext's sha256 prefix appears nowhere in the value.
  const fp = createHash("sha256").update(k).digest("hex").slice(0, 16);
  assert.equal(a.includes(fp), false);
});

test("transit: wrong setting key, wrong profile id, wrong seed all open null", () => {
  const env = sealTransit({ ...base, plaintext: sentinel() });
  assert.equal(openTransit({ ...base, settingKey: "tts_profiles", stored: env }), null);
  assert.equal(openTransit({ ...base, profileId: "p2", stored: env }), null);
  assert.equal(openTransit({ ...base, seed: randomBytes(32), stored: env }), null);
});

test("transit: flipped or unknown generation byte, truncation, bad base64 all open null (never throw)", () => {
  const env = sealTransit({ ...base, plaintext: sentinel() });
  const blob = Buffer.from(env.slice(4), "base64url");
  const withGen = (g) => { const c = Buffer.from(blob); c[0] = g; return "ps1:" + c.toString("base64url"); };
  assert.equal(openTransit({ ...base, stored: withGen(0x02) }), null);
  assert.equal(openTransit({ ...base, stored: withGen(0x00) }), null);
  assert.equal(openTransit({ ...base, stored: withGen(0x81) }), null);
  assert.equal(openTransit({ ...base, stored: "ps1:" + blob.subarray(0, 20).toString("base64url") }), null);
  assert.equal(openTransit({ ...base, stored: "ps1:" }), null);
  assert.equal(openTransit({ ...base, stored: "ps1:!!!not base64!!!" }), null);
  assert.equal(openTransit({ ...base, stored: env + "=" }), null);
  const flipped = Buffer.from(blob); flipped[flipped.length - 1] ^= 1;
  assert.equal(openTransit({ ...base, stored: "ps1:" + flipped.toString("base64url") }), null);
  for (const junk of [undefined, null, 5, {}, "", "keep", "plain-key"]) {
    assert.equal(openTransit({ ...base, stored: junk }), null);
  }
  assert.equal(openTransit({ seed: null, settingKey: "stt_profiles", profileId: "p1", stored: env }), null);
  assert.equal(openTransit({ ...base, settingKey: "providers", stored: env }), null);
  assert.equal(openTransit(), null);
});

test("transit: profile ids are bounded and well-formed; the envelope is capped before decoding", () => {
  const k = sentinel();
  const long = "a".repeat(256);
  const env = sealTransit({ ...base, profileId: long, plaintext: k });
  assert.equal(openTransit({ ...base, profileId: long, stored: env }), k);
  for (const bad of ["a".repeat(257), "\ud800", "x\udc00y", ""]) {
    assert.throws(() => sealTransit({ ...base, profileId: bad, plaintext: k }));
    assert.equal(openTransit({ ...base, profileId: bad, stored: env }), null);
  }
  // 8 KiB cap: a huge (even valid-looking) value is refused without being decoded.
  assert.equal(openTransit({ ...base, stored: "ps1:" + "A".repeat(9000) }), null);
  const key = { id: "0123456789abcdef", seed: randomBytes(32) };
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: "sk1:0123456789abcdef:0123456789abcdef:" + "A".repeat(9000), key }), null);
  assert.equal(isProfileSlotId("stt/" + "a".repeat(256)), true);
  assert.equal(isProfileSlotId("stt/" + "a".repeat(257)), false);
  assert.equal(isProfileSlotId("stt/\ud800"), false);
  assert.throws(() => seal({ purpose: "profile", slotId: "stt/" + "a".repeat(257), plaintext: k, key }));
});

test("transit: seal refuses with fixed, value-free errors", () => {
  const k = sentinel();
  for (const args of [
    { ...base, plaintext: "" }, { ...base, plaintext: "   " }, { ...base, plaintext: 5 },
    { ...base, seed: null, plaintext: k }, { ...base, seed: Buffer.alloc(8), plaintext: k },
    { ...base, settingKey: "providers", plaintext: k }, { ...base, profileId: "", plaintext: k },
  ]) {
    assert.throws(() => sealTransit(args), (e) => !String(e.message).includes(k) && !String(e.stack).includes(k));
  }
});

test("transit: an sk1: is not a ps1: and a ps1: is not an sk1:; enc:v1: from the same seed does not open", () => {
  const key = { id: randomBytes(8).toString("hex"), seed: randomBytes(32) };
  const k = sentinel();
  const sk = seal({ purpose: "profile", slotId: "stt/p1", plaintext: k, key });
  assert.equal(openTransit({ ...base, stored: sk }), null);
  const ps = sealTransit({ ...base, plaintext: k });
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: ps, key }), null);
  assert.equal(openTransit({ ...base, stored: sealSecret(k, { seed }) }), null);
  // The same bytes re-prefixed do not cross over either.
  assert.equal(openTransit({ ...base, stored: "ps1:" + sk.split(":")[3] }), null);
});

// ─── sk1: at rest (the profile purpose of the P1a box) ───────────────────────
const keyA = { id: "0123456789abcdef", seed: randomBytes(32) };
const keyB = { id: "fedcba9876543210", seed: randomBytes(32) };

test("sk1: round trip, envelope shape, slot validation", () => {
  const k = sentinel();
  const env = seal({ purpose: "profile", slotId: "ai/p1", plaintext: k, key: keyA });
  assert.match(env, /^sk1:0123456789abcdef:[0-9a-f]{16}:[A-Za-z0-9_-]+$/);
  assert.equal(open({ purpose: "profile", slotId: "ai/p1", stored: env, key: keyA }), k);
  for (const kind of ["ai", "tts", "stt", "vision"]) assert.equal(isProfileSlotId(`${kind}/x`), true);
  for (const bad of ["x/p1", "ai", "ai/", "/p1", "", "provider/p1"]) {
    assert.equal(isProfileSlotId(bad), false);
    assert.throws(() => seal({ purpose: "profile", slotId: bad, plaintext: k, key: keyA }));
    assert.equal(open({ purpose: "profile", slotId: bad, stored: env, key: keyA }), null);
  }
});

test("sk1: another kind, another profile id, another key id, a tampered body all open null", () => {
  const k = sentinel();
  const env = seal({ purpose: "profile", slotId: "stt/p1", plaintext: k, key: keyA });
  assert.equal(open({ purpose: "profile", slotId: "tts/p1", stored: env, key: keyA }), null);
  assert.equal(open({ purpose: "profile", slotId: "stt/p2", stored: env, key: keyA }), null);
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: env, key: keyB }), null);
  const [pre, id, fp, body] = env.split(":");
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: `${pre}:${id}:${fp}:${body.slice(0, -2)}AA`, key: keyA }), null);
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: `${pre}:${id}:${"0".repeat(16)}:${body}`, key: keyA }), null);
});

test("sk1:/pk1: separation: the prefix is inside the AAD, so neither opens as the other", () => {
  const k = sentinel();
  // A provider slot id that happens to be profile-shaped, so the slot rule is not what refuses.
  const pk = seal({ slotId: "stt/p1", plaintext: k, key: keyA });
  const sk = seal({ purpose: "profile", slotId: "stt/p1", plaintext: k, key: keyA });
  assert.match(pk, /^pk1:/);
  const swap = (e, from, to) => to + e.slice(from.length);
  // Real values never cross-open (different parser prefix check):
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: pk, key: keyA }), null);
  assert.equal(open({ slotId: "stt/p1", stored: sk, key: keyA }), null);
  // And with the prefix rewritten to defeat the prefix check, the AAD still refuses:
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: swap(pk, "pk1", "sk1"), key: keyA }), null);
  assert.equal(open({ slotId: "stt/p1", stored: swap(sk, "sk1", "pk1"), key: keyA }), null);
  // Sanity: each opens as itself.
  assert.equal(open({ slotId: "stt/p1", stored: pk, key: keyA }), k);
  assert.equal(open({ purpose: "profile", slotId: "stt/p1", stored: sk, key: keyA }), k);
});

test("sk1: provider parsers are unchanged for pk1: and never accept sk1:", () => {
  const k = sentinel();
  const pk = seal({ slotId: "prov-1", plaintext: k, key: keyA });
  const sk = seal({ purpose: "profile", slotId: "ai/p1", plaintext: k, key: keyA });
  assert.equal(parseStoredKey(pk).kind, "envelope");
  assert.equal(isProviderKeyEnvelope(pk), true);
  // To the provider parsers an sk1: is an ordinary string, not an envelope.
  assert.equal(parseStoredKey(sk).kind, "plain");
  assert.equal(isProviderKeyEnvelope(sk), false);
  // The profile parser recognises only its own.
  assert.equal(parseProfileEnvelope(sk).kind, "envelope");
  assert.equal(isProfileKeyEnvelope(sk), true);
  assert.equal(isProfileKeyEnvelope(pk), false);
  assert.equal(parseProfileEnvelope(pk).kind, "none");
  assert.equal(parseProfileEnvelope("sk1:short").kind, "malformed");
  assert.equal(parseProfileEnvelope("none").kind, "none");
  assert.equal(parseProfileEnvelope(null).kind, "none");
  assert.equal(hasProviderKey("none"), false);
});

test("sk1: makeProfileKeyring seals and opens by slot; no key refuses closed", () => {
  const k = sentinel();
  const kr = makeProfileKeyring(keyA);
  const env = kr.seal("vision/v1", k);
  assert.equal(kr.open("vision/v1", env), k);
  assert.equal(kr.open("vision/v2", env), null);
  const none = makeProfileKeyring(null);
  assert.equal(none.open("vision/v1", env), null);
  assert.throws(() => none.seal("vision/v1", k), (e) => !String(e.message).includes(k));
});

// ─── gateway-only mint (design §2.8) ─────────────────────────────────────────
test("mint: the loader creates nothing in a stdio-like env with no key file", () => {
  const home = join(scratch, "stdio-home");
  const before = existsSync(home);
  assert.equal(loadKeychainKey({ crowHome: home }), null);
  assert.equal(keychainKeyState({ crowHome: home }).state, "missing");
  assert.equal(existsSync(home), before);
  assert.equal(existsSync(join(home, "secrets", "keychain.key")), false);
  // The CROW_HOME environment with no arguments (what a stdio process does).
  const envHome = join(scratch, "env-home");
  const prev = process.env.CROW_HOME;
  process.env.CROW_HOME = envHome;
  try {
    assert.equal(loadKeychainKey(), null);
    assert.equal(loadKeychainKey({}), null);
    assert.equal(keychainKeyState().state, "missing");
  } finally {
    if (prev === undefined) delete process.env.CROW_HOME; else process.env.CROW_HOME = prev;
  }
  assert.equal(existsSync(envHome), false);
  // The same with the home present but no secrets/ dir, and with an empty secrets dir.
  const home2 = mkdtempSync(join(scratch, "h2-"));
  assert.equal(loadKeychainKey({ crowHome: home2 }), null);
  assert.deepEqual(readdirSync(home2), []);
});

test("mint: the new modules import no minting or identity code and nothing in production calls them", () => {
  for (const f of ["servers/gateway/keychain/profile-key-transport.js", "servers/gateway/ai/profile-keys.js"]) {
    const src = readFileSync(new URL("../" + f, import.meta.url), "utf8");
    assert.equal(/createKeychainKey|ensureWriteKey|sharing\/identity|secret-box/.test(src), false, f);
  }
  // Inert: no production file imports either module (this PR is a library plus tests).
  assert.deepEqual(productionImportersOfNewModules(), []);
});
function productionImportersOfNewModules() {
  const root = new URL("..", import.meta.url).pathname;
  const hits = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === ".git" || e.name === "tests") continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(m?js)$/.test(e.name) && !/profile-key-transport\.js$|ai\/profile-keys\.js$/.test(p)) {
        const s = readFileSync(p, "utf8");
        if ((/(?:from|import\(|require\()\s*["'][^"']*(?:profile-key-transport|profile-keys)\.js["']/.test(s) || /makeProfileKeyring|PROFILE_KEY_PURPOSE|purpose:\s*["']profile["']/.test(s)) && !p.endsWith("keychain/provider-key-box.js")) hits.push(p.slice(root.length));
      }
    }
  };
  for (const d of ["servers", "scripts", "bundles"]) { try { walk(join(root, d)); } catch { /* absent */ } }
  return hits;
}
