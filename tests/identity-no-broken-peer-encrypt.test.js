// The old encryptForPeer/decryptFromPeer pair derived mismatched keys (the sender hashed its own
// seed with the recipient's public key, the recipient the reverse), so nothing it encrypted could be
// opened. It was never called; it was deleted so nobody reaches for it as "the" peer encryption
// tool. This guard keeps it from coming back under either name.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

test("identity.js exports neither encryptForPeer nor decryptFromPeer", async () => {
  const mod = await import("../servers/sharing/identity.js");
  assert.equal("encryptForPeer" in mod, false);
  assert.equal("decryptFromPeer" in mod, false);
});

test("the old key-derivation label is gone from identity.js", () => {
  const src = readFileSync(join(root, "servers/sharing/identity.js"), "utf8");
  assert.equal(src.includes("crow-peer-encrypt-v1"), false);
});
