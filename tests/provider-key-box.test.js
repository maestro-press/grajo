/**
 * The provider-key box (design §1.1 + §2.1 + §2.2): the envelope's shape, the
 * seal/open contract, the same-key comparison and the keyring installation.
 *
 * Every value here is a fixture: "sentinel-" + randomUUID, never a real key. The
 * suite's hygiene test (tests/provider-keys-sweep.test.js) asserts that no
 * surface ever repeats one; this file pins the contract itself.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  KEY_ENVELOPE_PREFIX,
  isProviderKeyEnvelope,
  hasProviderKey,
  parseStoredKey,
  providerKeyFp,
} from "../servers/shared/provider-key-shape.js";
import {
  clearProviderKeyring,
  installProviderKeyring,
  keyringOpen,
  keyringSeal,
  providerKeyringInstalled,
  PROVIDER_KEY_SEAL_UNAVAILABLE,
} from "../servers/shared/provider-keyring.js";
import {
  installGatewayProviderKeyring,
  open,
  seal,
  PROVIDER_KEY_HKDF_INFO,
} from "../servers/gateway/keychain/provider-key-box.js";
import { createKeychainKey } from "../servers/gateway/keychain/key.js";
import { sameKeyCell } from "../servers/shared/providers-db.js";
import { installTestKeyring } from "./fixtures/provider-keys.mjs";

const scratch = mkdtempSync(join(tmpdir(), "crow-pk-box-"));
after(() => { try { rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } });

const keyA = { id: "0123456789abcdef", seed: randomBytes(32) };
const keyB = { id: "fedcba9876543210", seed: randomBytes(32) };
const SLOT = "prov-1";
const ENVELOPE = /^pk1:[0-9a-f]{16}:[0-9a-f]{16}:[A-Za-z0-9_-]+$/;
const sentinel = () => `sentinel-${randomUUID()}`;

// ─── the shape module (§1.1) ────────────────────────────────────────────────

test("shape: the none sentinel is NULL, \"\" and exactly \"none\" — nothing else", () => {
  for (const value of [null, undefined, "", "none"]) {
    assert.deepEqual(parseStoredKey(value), { kind: "none" });
    assert.equal(hasProviderKey(value), false);
  }
  for (const value of ["none ", " none", "NONE", "0", "pk1"]) {
    assert.equal(hasProviderKey(value), true, `${JSON.stringify(value)} is not the sentinel`);
  }
});

test("shape: a plain value, an envelope and a malformed envelope are told apart", () => {
  const plain = "demo-test-not-a-real-key";
  assert.deepEqual(parseStoredKey(plain), { kind: "plain" });

  const envelope = seal({ slotId: SLOT, plaintext: plain, key: keyA });
  const parsed = parseStoredKey(envelope);
  assert.equal(parsed.kind, "envelope");
  assert.equal(parsed.keyId, keyA.id);
  assert.equal(parsed.fp, providerKeyFp(plain));
  assert.ok(parsed.payload.length > 0);
  assert.equal(isProviderKeyEnvelope(envelope), true);

  // Anything claiming the prefix but not matching the grammar is malformed —
  // never "plain", so a truncated envelope can never be sent as the key.
  for (const bad of [
    "pk1:",
    `pk1:${keyA.id}`,
    `pk1:${keyA.id}:${parsed.fp}`,
    `pk1:${keyA.id}:${parsed.fp}:`,
    `pk1:0123456789ABCDEF:${parsed.fp}:AAAA`,
    `pk1:${keyA.id}:${parsed.fp}:AA AA`,
    `pk1:${keyA.id}:${parsed.fp}:AAAA\n`,
  ]) {
    assert.deepEqual(parseStoredKey(bad), { kind: "malformed" }, JSON.stringify(bad));
    assert.equal(isProviderKeyEnvelope(bad), false);
    assert.equal(hasProviderKey(bad), true);
  }
  // A non-string cell is malformed, never plain.
  assert.deepEqual(parseStoredKey(42), { kind: "malformed" });
});

test("shape: the fingerprint is sha256 of the TRIMMED value, 16 hex", () => {
  const fp = providerKeyFp("  demo-test-key  ");
  assert.match(fp, /^[0-9a-f]{16}$/);
  assert.equal(fp, providerKeyFp("demo-test-key"));
  assert.equal(fp, providerKeyFp("\n demo-test-key \n"));
  assert.notEqual(fp, providerKeyFp("demo-test-kez"));
  for (const nothing of [null, undefined, 5, "", "   ", "none", " none "]) {
    assert.equal(providerKeyFp(nothing), null);
  }
});

// ─── sealing (§2.2) ────────────────────────────────────────────────────────

test("seal: the envelope carries the key id, the fingerprint and a random-nonce payload", () => {
  const plaintext = sentinel();
  const envelope = seal({ slotId: SLOT, plaintext, key: keyA });
  assert.match(envelope, ENVELOPE);
  assert.ok(envelope.startsWith(`${KEY_ENVELOPE_PREFIX}${keyA.id}:${providerKeyFp(plaintext)}:`));

  const parsed = parseStoredKey(envelope);
  // nonce(12) + ciphertext(length of the value) + tag(16)
  const blob = Buffer.from(parsed.payload, "base64url");
  assert.equal(blob.length, 12 + Buffer.byteLength(plaintext, "utf8") + 16);

  // Same plaintext, same key, different envelope: the nonce is fresh every time.
  const again = seal({ slotId: SLOT, plaintext, key: keyA });
  assert.notEqual(again, envelope);
  assert.equal(open({ slotId: SLOT, stored: again, key: keyA }), plaintext);
});

test("seal/open: the RAW bytes round trip — trimming is only the fingerprint's business", () => {
  for (const raw of ["  demo-test-padded  ", "\ndemo-test-newlines\n", "  leading", "trailing\t", "unicode-ключ-🔑"]) {
    const envelope = seal({ slotId: SLOT, plaintext: raw, key: keyA });
    assert.equal(open({ slotId: SLOT, stored: envelope, key: keyA }), raw, JSON.stringify(raw));
    const parsed = parseStoredKey(envelope);
    assert.equal(parsed.fp, providerKeyFp(raw), "the envelope's fp is the trimmed fingerprint");
  }
});

test("seal: HKDF info is the documented one, and a wrong purpose refuses", () => {
  assert.equal(PROVIDER_KEY_HKDF_INFO, "crow-provider-key-v1");
  for (const purpose of ["profile", "PROVIDER", "", null]) {
    assert.throws(() => seal({ purpose, slotId: SLOT, plaintext: sentinel(), key: keyA }),
      (err) => err.code === "PROVIDER_KEY_PURPOSE_UNSUPPORTED");
  }
  const envelope = seal({ slotId: SLOT, plaintext: sentinel(), key: keyA });
  // Only the provider purpose is implemented, so an open for any other purpose
  // refuses as well rather than guessing at a prefix.
  assert.throws(() => open({ purpose: "profile", slotId: SLOT, stored: envelope, key: keyA }),
    (err) => err.code === "PROVIDER_KEY_PURPOSE_UNSUPPORTED");
});

test("seal: no key, a damaged key, no slot, nothing to seal — each refuses without a value in the message", () => {
  const plaintext = sentinel();
  const cases = [
    () => seal({ slotId: SLOT, plaintext, key: null }),
    () => seal({ slotId: SLOT, plaintext, key: { id: keyA.id, seed: Buffer.alloc(16) } }),
    () => seal({ slotId: SLOT, plaintext, key: { id: "not-hex", seed: keyA.seed } }),
    () => seal({ slotId: "", plaintext, key: keyA }),
    () => seal({ slotId: SLOT, plaintext: "", key: keyA }),
    () => seal({ slotId: SLOT, plaintext: "   ", key: keyA }),
  ];
  for (const run of cases) {
    assert.throws(run, (err) => {
      assert.ok(!String(err.message).includes(plaintext), "the refusal never repeats a value");
      assert.ok(!String(err.message).includes(keyA.id), "the refusal never repeats a key id");
      return true;
    });
  }
});

test("open: another key id returns null WITHOUT touching the seed (no decrypt is attempted)", () => {
  const plaintext = sentinel();
  const envelope = seal({ slotId: SLOT, plaintext, key: keyA });
  let seedRead = false;
  const wrongKey = {
    id: keyB.id,
    get seed() { seedRead = true; throw new Error("seed must not be read for a key id mismatch"); },
  };
  assert.equal(open({ slotId: SLOT, stored: envelope, key: wrongKey }), null);
  assert.equal(seedRead, false);
  // The same, with a real second key: null, never a wrong plaintext.
  assert.equal(open({ slotId: SLOT, stored: envelope, key: keyB }), null);
});

test("open: a tampered, truncated or mislabelled envelope is null, never a partial value", () => {
  const plaintext = sentinel();
  const envelope = seal({ slotId: SLOT, plaintext, key: keyA });
  const parsed = parseStoredKey(envelope);
  const flip = (payload) => {
    const chars = payload.split("");
    chars[0] = chars[0] === "A" ? "B" : "A";
    return chars.join("");
  };
  const cases = [
    `${KEY_ENVELOPE_PREFIX}${parsed.keyId}:${parsed.fp}:${flip(parsed.payload)}`,
    `${KEY_ENVELOPE_PREFIX}${parsed.keyId}:${parsed.fp}:${parsed.payload.slice(0, -4)}`,
    // A different fp is different AAD: the tag no longer verifies.
    `${KEY_ENVELOPE_PREFIX}${parsed.keyId}:${"0".repeat(16)}:${parsed.payload}`,
    // Moved to another row: the slot is part of the AAD.
    envelope,
  ];
  for (let i = 0; i < cases.length; i += 1) {
    const slotId = i === cases.length - 1 ? "prov-2" : SLOT;
    assert.equal(open({ slotId, stored: cases[i], key: keyA }), null, `case ${i}`);
  }
  // …and the untouched envelope still opens, so the cases above are not vacuous.
  assert.equal(open({ slotId: SLOT, stored: envelope, key: keyA }), plaintext);
});

test("open: anything that is not an envelope for this key is null", () => {
  const plaintext = sentinel();
  assert.equal(open({ slotId: SLOT, stored: plaintext, key: keyA }), null);
  assert.equal(open({ slotId: SLOT, stored: "none", key: keyA }), null);
  assert.equal(open({ slotId: SLOT, stored: null, key: keyA }), null);
  assert.equal(open({ slotId: SLOT, stored: "", key: keyA }), null);
  assert.equal(open({ slotId: SLOT, stored: "pk1:0123456789abcdef:0000000000000000:AAAA", key: keyA }), null);
  assert.equal(open({ slotId: "", stored: seal({ slotId: SLOT, plaintext, key: keyA }), key: keyA }), null);
  assert.equal(open({ slotId: SLOT, stored: seal({ slotId: SLOT, plaintext, key: keyA }), key: null }), null);
});

// ─── the same-key comparison (§1.1, review round 1 L1) ────────────────

test("sameKeyCell: identity by OPENING the cell, constant-time, and never a false positive", () => {
  const { key, uninstall } = installTestKeyring({ key: keyA });
  try {
    const plaintext = "  sentinel-same-key  ";
    const envelope = seal({ slotId: SLOT, plaintext, key });
    // A sealed cell is OPENED and its plaintext's fp compared: re-saving the same
    // key with different surrounding whitespace is the same key.
    assert.equal(sameKeyCell(SLOT, envelope, plaintext), true);
    assert.equal(sameKeyCell(SLOT, envelope, plaintext.trim()), true);
    assert.equal(sameKeyCell(SLOT, envelope, "sentinel-another-key"), false);
    // The same envelope on ANOTHER row does not open (the slot is in the AAD).
    assert.equal(sameKeyCell("prov-2", envelope, plaintext), false);
    // A plaintext cell compares the same way, so a first pass over a plain DB is
    // not re-sealed for a whitespace difference either.
    assert.equal(sameKeyCell(SLOT, plaintext, plaintext.trim()), true);
    assert.equal(sameKeyCell(SLOT, "sentinel-a", "sentinel-b"), false);
    // Nothing stored, a malformed cell, and a value with nothing to fingerprint.
    assert.equal(sameKeyCell(SLOT, null, plaintext), false);
    assert.equal(sameKeyCell(SLOT, "none", plaintext), false);
    assert.equal(sameKeyCell(SLOT, "pk1:truncated", plaintext), false);
    assert.equal(sameKeyCell(SLOT, envelope, ""), false);
    assert.equal(sameKeyCell(SLOT, envelope, "   "), false);

    // With a key that is NOT the one that sealed it, the cell does not open.
    const other = installTestKeyring({ key: keyB });
    try {
      assert.equal(sameKeyCell(SLOT, envelope, plaintext), false, "another install's key is not this instance's key");
    } finally {
      other.uninstall();
    }
  } finally {
    uninstall();
  }
});

// ─── the keyring seam (§1.1) ───────────────────────────────────────────────

test("keyring: empty means reads are null and seals REFUSE (never a clear-text write)", () => {
  clearProviderKeyring();
  assert.equal(providerKeyringInstalled(), false);
  assert.equal(keyringOpen(SLOT, "pk1:0123456789abcdef:0000000000000000:AAAA"), null);
  assert.equal(keyringOpen(SLOT, ""), null);
  assert.equal(keyringSeal(SLOT, "none"), "none", "the none sentinel is passed through");
  assert.equal(keyringSeal(SLOT, ""), "");
  assert.throws(() => keyringSeal(SLOT, sentinel()), (err) => err.code === PROVIDER_KEY_SEAL_UNAVAILABLE);
});

test("keyring: a gateway key on disk is installed, and a home without one installs a REFUSING keyring", () => {
  const home = join(scratch, "home-with-key");
  createKeychainKey({ crowHome: home });
  assert.equal(installGatewayProviderKeyring({ crowHome: home }), true);
  assert.equal(providerKeyringInstalled(), true);

  const plaintext = sentinel();
  const envelope = keyringSeal(SLOT, plaintext);
  assert.match(envelope, ENVELOPE);
  assert.equal(keyringOpen(SLOT, envelope), plaintext);
  assert.equal(keyringOpen("another-row", envelope), null);

  clearProviderKeyring();
  const empty = join(scratch, "home-without-key");
  assert.equal(installGatewayProviderKeyring({ crowHome: empty }), false);
  assert.equal(keyringOpen(SLOT, envelope), null);
  assert.throws(() => keyringSeal(SLOT, plaintext), (err) => {
    assert.equal(err.code, PROVIDER_KEY_SEAL_UNAVAILABLE);
    assert.ok(!String(err.message).includes(plaintext));
    return true;
  });

  // An explicit installation is replaced wholesale, never merged.
  installProviderKeyring({ open: () => "opened", seal: () => "sealed" });
  assert.equal(keyringOpen(SLOT, "anything"), "opened");
  assert.equal(keyringSeal(SLOT, plaintext), "sealed");
  installProviderKeyring({ seal: null });
  assert.equal(keyringOpen(SLOT, "anything"), null);
  clearProviderKeyring();
});

test("H2: a key minted AFTER the gateway keyring was installed starts sealing without a restart", () => {
  const home = join(scratch, "late-key-home");
  clearProviderKeyring();
  // Boot order on a fresh install: the keyring is installed first, with no key.
  assert.equal(installGatewayProviderKeyring({ crowHome: home }), false);
  const plaintext = sentinel();
  assert.throws(() => keyringSeal(SLOT, plaintext), (err) => err.code === PROVIDER_KEY_SEAL_UNAVAILABLE);
  // The key appears later: the boot mint, a keychain save, the ops CLI.
  createKeychainKey({ crowHome: home });
  const envelope = keyringSeal(SLOT, plaintext);
  assert.match(envelope, ENVELOPE, "the first seal after the mint uses the new key");
  assert.equal(keyringOpen(SLOT, envelope), plaintext);
  clearProviderKeyring();
});