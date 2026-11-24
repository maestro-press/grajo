/**
 * loadAddonSettings() turns an installed.json `id` into a PATH SEGMENT and then imports a file
 * under it: join(CROW_HOME, "bundles", id, "settings-section.js"). installed.json is the
 * operator's (and an add-on's installer writes it), so an id with a traversal segment — "../x" —
 * used to resolve OUTSIDE the bundles directory and be imported as code at boot.
 *
 * The fix is the gateway's own bundle-id rule (isValidBundleId) applied BEFORE the join, with a
 * record that fails it skipped and warned about (never thrown: one bad record must not cost the
 * other add-ons their settings section). This test pins both halves: the outsider file is never
 * imported, and a valid add-on next to it still registers.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Scratch CROW_HOME set BEFORE the import (the repo's co-hosted-instance pattern): the registry
// resolves installed.json and bundles/ through CROW_HOME on every call.
const scratch = mkdtempSync(join(tmpdir(), "settings-registry-id-"));
process.env.CROW_HOME = scratch;
process.env.CROW_DATA_DIR = join(scratch, "data");
mkdirSync(join(scratch, "data"), { recursive: true });

test("an installed.json id outside the bundle-id shape is skipped, warned about, and never imported", async () => {
  // What a "../x" record resolves to: join(CROW_HOME, "bundles", "../x", "settings-section.js")
  // is CROW_HOME/x/settings-section.js — outside bundles/, inside the instance home.
  mkdirSync(join(scratch, "x"), { recursive: true });
  writeFileSync(
    join(scratch, "x", "settings-section.js"),
    "export default { id: 'planted-traversal-section', label: 'Planted', render: () => '' };\n",
  );
  // A real installed add-on, so a blanket refusal cannot pass this test.
  mkdirSync(join(scratch, "bundles", "good-addon"), { recursive: true });
  writeFileSync(
    join(scratch, "bundles", "good-addon", "settings-section.js"),
    "export default { id: 'good-addon-section', label: 'Good', render: () => '' };\n",
  );
  writeFileSync(
    join(scratch, "installed.json"),
    JSON.stringify([
      { id: "../x", type: "bundle", installedAt: "2026-09-07T00:00:00Z" },
      { id: "Bad_Id", type: "bundle", installedAt: "2026-09-07T00:00:00Z" },
      { id: "good-addon", type: "bundle", installedAt: "2026-09-07T00:00:00Z" },
    ]),
  );

  const { loadAddonSettings, getSettingsSection } = await import(
    "../servers/gateway/dashboard/settings/registry.js"
  );

  const warnings = [];
  const realWarn = console.warn;
  console.warn = (...args) => warnings.push(args.map(String).join(" "));
  try {
    await loadAddonSettings();
  } finally {
    console.warn = realWarn;
  }

  assert.equal(
    getSettingsSection("planted-traversal-section"),
    undefined,
    "a '../x' id resolves to CROW_HOME/x/settings-section.js — it must never be imported",
  );
  assert.equal(
    getSettingsSection("good-addon-section")?.id,
    "good-addon-section",
    "a well-formed installed add-on still loads its settings section",
  );
  assert.ok(
    warnings.some((w) => w.includes("../x")),
    "the skipped record is reported, not swallowed silently: " + JSON.stringify(warnings),
  );
  assert.ok(
    warnings.some((w) => w.includes("Bad_Id")),
    "an id that is not the bundle-id shape is reported too: " + JSON.stringify(warnings),
  );
});