/**
 * The Attention sheet itself: the welcome block, the flash banner, the links the
 * health signals carry, the collapsed status details, the all-good state and the
 * fix-it slot — plus the fragment route that serves it.
 *
 * The links filter (an in-dashboard path only) and the health detail cards are
 * shared with the Nest, so this file checks `healthLinkRows` and the Nest's own
 * strip too: the sheet must not invent a different rule.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { t } from "../servers/gateway/dashboard/shared/i18n.js";
import { UNWALLED_MESSAGE } from "../servers/gateway/fix-it/remedies/addon-unwall.js";

const REPO = join(import.meta.dirname, "..");
const dir = mkdtempSync(join(tmpdir(), "shell-attention-sheet-"));
process.env.CROW_DATA_DIR = dir;
mkdirSync(join(dir, "home"), { recursive: true });
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

let attentionSheetHtml, healthLinkRows, buildNestHTML;
let server, base;

const HEALTH = {
  ok: true,
  issues: [],
  links: [],
  details: [
    { label: "CPU", value: "3%", state: "ok" },
    { label: "Disk", value: "62%", state: "ok" },
  ],
};

const BACKUP_ISSUE = {
  id: "backup",
  severity: "info",
  label: "No backup yet",
  actionLabel: "Run backup now",
  actionHref: "/dashboard/nest?action=backup",
  ack: null,
};

/** Render the sheet with this test's defaults. */
function sheet(overrides = {}) {
  return attentionSheetHtml({ lang: "en", health: HEALTH, issues: [], fixItHtml: "", flash: null, ...overrides });
}

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env }, stdio: "pipe", cwd: REPO,
  });
  const attention = await import("../servers/gateway/dashboard/shell/attention.js");
  const nest = await import("../servers/gateway/dashboard/panels/nest/html.js");
  attentionSheetHtml = attention.attentionSheetHtml;
  healthLinkRows = nest.healthLinkRows;
  buildNestHTML = nest.buildNestHTML;

  assert.equal(typeof attentionSheetHtml, "function",
    "servers/gateway/dashboard/shell/attention.js must export attentionSheetHtml({ lang, health, issues, fixItHtml, flash, now })");
  assert.equal(typeof healthLinkRows, "function",
    "servers/gateway/dashboard/panels/nest/html.js must export healthLinkRows(health)");

  const { default: express } = await import("express");
  const { healthAttentionRouter } = await import("../servers/gateway/dashboard/panels/health.js");
  const { createDbClient } = await import("../servers/db.js");
  const app = express();
  // The route must take injected signals (as notificationsRouter does), so the
  // health side of the fragment is a known state in a test.
  app.use(healthAttentionRouter({ createDbClient, collectSignals: async () => HEALTH }));
  await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
  base = "http://127.0.0.1:" + server.address().port;
});

after(() => {
  if (server) server.close();
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
});

test("the welcome block carries the greeting and a long date", () => {
  const now = new Date(2026, 2, 4, 12, 0, 0); // local noon, so the day cannot shift
  const expectedDate = now.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric", year: "numeric" });
  const html = sheet({ now });
  assert.ok(html.includes(t("health.welcome", "en")), "the sheet greets the owner (health.welcome)");
  assert.ok(html.includes(expectedDate), `the sheet shows the long date (${expectedDate})`);
});

test("the all-good state shows only when health is ok AND no fix-it card is up", () => {
  const allgood = t("health.allgood", "en");
  assert.ok(sheet().includes(allgood), "healthy and nothing pending: the all-good line");
  assert.equal(
    sheet({ fixItHtml: '<div class="shell-fixit-card" data-fixit-item="1">x</div>' }).includes(allgood),
    false,
    "a pending fix-it card suppresses the all-good line",
  );
  assert.equal(
    sheet({ health: { ...HEALTH, ok: false } }).includes(allgood),
    false,
    "an unhealthy instance has no all-good line",
  );
});

test("the signal links render in the sheet and in the Nest, with the same filter", () => {
  const health = {
    ...HEALTH,
    links: [
      { text: "Notes is unwalled", label: "Open Extensions", href: "/dashboard/extensions" },
      { text: "A remote thing", label: "Go", href: "https://evil.example/x" },
      { text: "A protocol", label: "Go", href: "javascript:alert(1)" },
    ],
  };
  const html = sheet({ health });
  assert.ok(html.includes("Notes is unwalled"), "the link row's text is rendered");
  assert.ok(html.includes("Open Extensions"), "the link row's label is rendered");
  assert.ok(html.includes('href="/dashboard/extensions"'), "the in-dashboard link is rendered");
  assert.equal(html.includes("evil.example"), false, "a foreign href is dropped");
  assert.equal(html.includes("javascript:"), false, "a javascript: href is dropped");

  assert.deepEqual(healthLinkRows(health),
    [{ text: "Notes is unwalled", label: "Open Extensions", href: "/dashboard/extensions" }],
    "healthLinkRows is the one filter both renderers use");
  assert.deepEqual(healthLinkRows({}), []);
  assert.deepEqual(healthLinkRows(null), []);

  const nest = buildNestHTML({
    pinnedItems: [], bundles: [], instances: [], trustedInstances: [], peerOverviews: [],
    ssoEnabled: false, healthSignals: health, flash: null,
  }, "en");
  assert.ok(nest.includes("/dashboard/extensions"), "the Nest renders the in-dashboard link");
  assert.equal(nest.includes("evil.example"), false, "the Nest drops the foreign link too");
});

test("the status details are one collapsed block with a card per detail", () => {
  const html = sheet();
  assert.match(html, /<details class="shell-attn-details">/, "one collapsed details block");
  assert.equal(/<details[^>]*\bopen\b/.test(html), false, "it starts collapsed");
  assert.ok(html.includes(t("health.statusDetails", "en")), "its summary is the Status details label");
  for (const detail of HEALTH.details) {
    assert.ok(html.includes(detail.label), `detail "${detail.label}" is rendered`);
    assert.ok(html.includes(detail.value), `detail value "${detail.value}" is rendered`);
  }
});

test("the flash banner keeps its tone classes and escapes its text", () => {
  const success = sheet({ flash: { tone: "success", text: "Done." } });
  assert.match(success, /class="shell-attn-flash shell-attn-flash--success"/);
  assert.match(success, /role="status"/);
  assert.ok(success.includes("Done."));

  for (const tone of ["error", "info"]) {
    assert.match(sheet({ flash: { tone, text: "x" } }), new RegExp(`shell-attn-flash--${tone}`), `${tone} keeps its class`);
  }

  assert.equal(sheet({ flash: null }).includes("shell-attn-flash"), false, "no banner without a flash");

  const evil = sheet({ flash: { tone: "success", text: "<b>bold</b>" } });
  assert.ok(evil.includes("&lt;b&gt;bold&lt;/b&gt;"), "the flash text is escaped");
  assert.equal(evil.includes("<b>bold</b>"), false);
});

test("the backup issue's form carries return=sheet", () => {
  const html = sheet({ issues: [BACKUP_ISSUE], health: { ...HEALTH, ok: false, issues: [BACKUP_ISSUE] } });
  const form = html.match(/<form[^>]*action="\/dashboard\/nest\/backup"[\s\S]*?<\/form>/);
  assert.ok(form, "the backup issue keeps its own POST form");
  assert.ok(form[0].includes('name="return" value="sheet"'), "the backup form comes back to the sheet");
});

test("the Spanish sheet greets in Spanish", () => {
  const html = sheet({ lang: "es" });
  assert.ok(html.includes("Bienvenido al Nido del Cuervo"), "health.welcome es");
});

test("the fragment route renders the flash it is given, and nothing for an unknown code", async () => {
  const done = await (await fetch(base + "/dashboard/attention/fragment?flash=fixit_done")).text();
  assert.ok(done.includes("Done."), "flash=fixit_done renders the new Done. banner");
  assert.match(done, /shell-attn-flash--success/);

  const bogus = await (await fetch(base + "/dashboard/attention/fragment?flash=bogus")).text();
  assert.equal(bogus.includes("shell-attn-flash"), false, "an unknown flash renders no banner");

  const unwalled = await (await fetch(base + "/dashboard/attention/fragment?flash=fixit_addon_unwalled&addon=Bad%20Id")).text();
  assert.ok(unwalled.includes(UNWALLED_MESSAGE), "a bad add-on id falls back to the generic unwalled text");
  assert.equal(unwalled.includes("Bad Id"), false, "the bad id is never shown");
});

test("the fragment route shows the all-good state when nothing is pending and health is ok", async () => {
  const html = await (await fetch(base + "/dashboard/attention/fragment")).text();
  assert.ok(html.includes(t("health.allgood", "en")),
    "the fragment must take injected signals (like notificationsRouter) and show all-good when nothing is pending");
  assert.equal(html.includes("shell-fixit-card"), false, "no fix-it cards are pending in this file");
});