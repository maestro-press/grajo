// Public-repository hygiene for Crow Mail's own provider table and credential keys, WITHOUT git.
//
// tests/public-hygiene.test.js is the real guard: it scans every tracked file of the repository. It
// needs a git worktree, which an agent sandbox or a copied tree does not have, so this file runs the
// same content rules (scripts/check-public-hygiene.mjs, the same allowlist) over the handful of files
// this lane adds and edits. Redundant in CI by design; it is what tells a developer — or a sandbox —
// that a preset picked up a real mailbox, a phone number or a credential before it reaches a commit.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkContent, loadAllowlist } from "../scripts/check-public-hygiene.mjs";
import { PRESETS } from "../servers/gateway/mail/providers/presets.js";

/** The files a Crow Mail provider preset or credential change touches. */
const FILES = [
  "servers/gateway/mail/providers/presets.js",
  "servers/gateway/mail/credentials.js",
  "tests/mail-presets.test.js",
  "tests/mail-credentials.test.js",
  "scripts/public-hygiene-allowlist.txt",
];

test("the mail preset table and its credential keys obey the repository's hygiene rules", () => {
  const allow = loadAllowlist(readFileSync("scripts/public-hygiene-allowlist.txt", "utf8"));
  const violations = [];
  for (const file of FILES) {
    violations.push(...checkContent(file, readFileSync(file, "utf8"), { allow, denylist: [], hosts: [] }));
  }
  assert.deepEqual(violations, []);
});

test("the preset data itself carries no address, no phone number and no credential", () => {
  // The literal strings a preset ships are what a public repository would publish: the provider's own
  // pages and host names, a label and i18n keys — never a mailbox, a number or a token.
  const allow = loadAllowlist(readFileSync("scripts/public-hygiene-allowlist.txt", "utf8"));
  for (const preset of PRESETS) {
    const text = JSON.stringify(preset);
    assert.deepEqual(checkContent(`preset:${preset.id}`, text, { allow, denylist: [], hosts: [] }), []);
  }
});