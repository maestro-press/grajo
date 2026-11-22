/**
 * The Nest's Fix-it section must not change (golden) while the cards move into
 * the new shell's Attention sheet. One shared card model, two renderers: this
 * file pins the Nest renderer's bytes and the flash banners it draws, so a change
 * meant for the sheet cannot quietly reshape the Nest.
 *
 * The golden fixture is written, never compared, when UPDATE_GOLDEN=1:
 *   UPDATE_GOLDEN=1 node --test tests/fix-it-nest-unchanged.test.js
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { escapeHtml } from "../servers/gateway/dashboard/shared/components.js";
import { t } from "../servers/gateway/dashboard/shared/i18n.js";

const REPO = join(import.meta.dirname, "..");
const FIXTURE = join(REPO, "tests", "fixtures", "fix-it-nest-cards.en.html");

const dir = mkdtempSync(join(tmpdir(), "fixit-nest-unchanged-"));
process.env.CROW_DATA_DIR = dir;
mkdirSync(join(dir, "home"), { recursive: true });
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

let db, idx, nestHtml;

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env }, stdio: "pipe", cwd: REPO,
  });
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
  idx = await import("../servers/gateway/fix-it/index.js");
  nestHtml = await import("../servers/gateway/dashboard/panels/nest/html.js");
  const seed = await import("./helpers/fix-it-seed.js");

  assert.equal(typeof idx.renderFixItCards, "function", "fix-it/index.js must still export renderFixItCards");
  idx.wireFixIt();
  await seed.seedFixItCards(db);
});

after(() => {
  try { db.close(); } catch {}
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
});

test("the Nest's Fix-it section is byte-identical to the golden fixture", async () => {
  const html = await idx.renderFixItCards(db, { lang: "en", req: { csrfToken: "tok" } });
  assert.ok(html.length > 0, "the seeded cards must render something");

  if (process.env.UPDATE_GOLDEN === "1") {
    mkdirSync(join(REPO, "tests", "fixtures"), { recursive: true });
    writeFileSync(FIXTURE, html);
    return;
  }

  assert.ok(existsSync(FIXTURE),
    `the golden fixture ${FIXTURE} is missing — regenerate it once with UPDATE_GOLDEN=1 node --test tests/fix-it-nest-unchanged.test.js`);

  const expected = readFileSync(FIXTURE, "utf8");
  if (html !== expected) {
    let at = 0;
    while (at < html.length && at < expected.length && html[at] === expected[at]) at += 1;
    assert.fail(
      `the Nest's Fix-it markup changed at byte ${at}: the Nest must render exactly what it rendered before the Attention sheet work.\n`
      + `expected: ${JSON.stringify(expected.slice(Math.max(0, at - 80), at + 160))}\n`
      + `     got: ${JSON.stringify(html.slice(Math.max(0, at - 80), at + 160))}`,
    );
  }
});

test("the Nest's flash banners keep their exact markup, including the new fixit_done", () => {
  const nestData = (flash, extra = {}) => ({
    pinnedItems: [], bundles: [], instances: [], trustedInstances: [], peerOverviews: [],
    ssoEnabled: false, healthSignals: null, flash, ...extra,
  });

  const expected = {
    backup_ok: { div: `<div class="nest-flash nest-flash--success">${escapeHtml(t("health.backupDone", "en"))}</div>` },
    backup_fail: { div: `<div class="nest-flash nest-flash--error">${escapeHtml(t("health.backupFailed", "en"))}</div>` },
    fixit_fixed: { div: `<div class="nest-flash nest-flash--success">Done — it's shared now.</div>` },
    fixit_done: { div: `<div class="nest-flash nest-flash--success">Done.</div>` },
    fixit_dismissed: { div: `<div class="nest-flash nest-flash--success">Dismissed for now.</div>` },
    fixit_error: { div: `<div class="nest-flash nest-flash--error">Couldn't apply that fix.</div>` },
    fixit_not_pending: { div: `<div class="nest-flash nest-flash--error">That card isn't open any more — nothing was changed.</div>` },
    // Started, not done: plain markup, no success or error class.
    fixit_retired_removing: { div: `<div class="nest-flash">${escapeHtml(t("health.retiredRemoving", "en"))}</div>` },
  };

  for (const [flash, { div }] of Object.entries(expected)) {
    const html = nestHtml.buildNestHTML(nestData(flash), "en");
    assert.ok(html.includes(div), `flash "${flash}" must render exactly ${div}`);
  }

  const plain = nestHtml.buildNestHTML(nestData("fixit_retired_removing"), "en");
  assert.equal(/nest-flash nest-flash--/.test(plain), false, "the removing flash keeps the plain nest-flash class");
});

test("a flash that is not a known code renders no banner at all", () => {
  const html = nestHtml.buildNestHTML({
    pinnedItems: [], bundles: [], instances: [], trustedInstances: [], peerOverviews: [],
    ssoEnabled: false, healthSignals: null, flash: "fixit_bogus",
  }, "en");
  assert.equal(html.includes("nest-flash"), false);
});

test("the Spanish Nest card renders the approved Spanish", async () => {
  const notNow = t("fixit.notNow", "es");
  assert.equal(notNow, "Ahora no", `fixit.notNow es is the operator-approved Spanish, got "${notNow}"`);

  const html = await idx.renderFixItCards(db, { lang: "es", req: { csrfToken: "tok" } });
  assert.ok(html.includes("Ahora no"), "the Spanish Nest card's dismiss button carries the approved copy");
});