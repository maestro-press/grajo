// "More of Crow" follows the owner's nav settings: the drawer's grid is built
// from resolveNavGroups (the same groups the classic sidebar shows), so every
// panel the classic nav shows keeps a way in from the new shell — unless it
// moved somewhere else on purpose, or is an app in the launcher.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../node_modules/better-sqlite3/lib/index.js";
import { resolveNavGroups } from "../servers/gateway/dashboard/nav-registry.js";

const dir = mkdtempSync(join(tmpdir(), "shell-more-entries-"));
process.env.CROW_HOME = dir; // no installed.json: no federated bundle
const DASH = new URL("../servers/gateway/dashboard/", import.meta.url).pathname;

let shellDrawer, registry, corePanels, defaults;
before(async () => {
  ({ shellDrawer } = await import("../servers/gateway/dashboard/shell/chrome.js"));
  registry = await import("../servers/gateway/dashboard/panel-registry.js");
  // The same built-in panels dashboard/index.js registers, read from its own source.
  const src = readFileSync(DASH + "index.js", "utf8");
  const imp = {};
  for (const m of src.matchAll(/^import (\w+)(?:,\s*\{[^}]*\})? from "(\.\/panels\/[^"]+)"/gm)) imp[m[1]] = m[2];
  corePanels = [];
  for (const m of src.matchAll(/registerPanel\((\w+)\)/g)) {
    if (!imp[m[1]]) continue;
    const p = (await import(DASH + imp[m[1]])).default;
    registry.registerPanel(p);
    corePanels.push(p);
  }
  assert.ok(corePanels.length > 20, "read the built-in panel list from dashboard/index.js");
  // One default-config run: the built-in group order and assignments.
  defaults = await navGroupsFrom();
});
after(() => rmSync(dir, { recursive: true, force: true }));

// ─── A throwaway database, exactly what dashboard/index.js resolves over ─────

/** A fresh crow.db from scripts/init-db.js (CROW_DATA_DIR for that child only). */
function makeTempDb() {
  const dataDir = mkdtempSync(join(tmpdir(), "shell-more-nav-"));
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dataDir },
    stdio: "pipe",
  });
  return { db: new Database(join(dataDir, "crow.db")), dataDir };
}

/** resolveNavGroups uses db.execute({sql,args}); wrap better-sqlite3 in that shape. */
function wrapDb(db) {
  return {
    execute({ sql, args }) {
      const stmt = db.prepare(sql);
      const trimmed = sql.trimStart().toUpperCase();
      if (trimmed.startsWith("SELECT") || trimmed.startsWith("PRAGMA")) {
        return Promise.resolve({ rows: args && args.length ? stmt.all(...args) : stmt.all() });
      }
      const info = args && args.length ? stmt.run(...args) : stmt.run();
      return Promise.resolve({ rows: [], ...info });
    },
  };
}

function seedNav(db, groups, assignments) {
  const upsert = db.prepare(
    "INSERT INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  );
  upsert.run("nav_groups", JSON.stringify(groups));
  upsert.run("nav_panel_assignments", JSON.stringify(assignments));
}

/**
 * Resolve the nav the way a request does: seed the stored config in a fresh
 * database (nothing = the built-in defaults), then run resolveNavGroups over
 * the registered visible panels.
 */
async function navGroupsFrom({ groups, assignments } = {}) {
  const { db, dataDir } = makeTempDb();
  try {
    if (groups && assignments) seedNav(db, groups, assignments);
    return await resolveNavGroups(wrapDb(db), registry.getVisiblePanels());
  } finally {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

/** Resolve a nav config (default unless given) and render the drawer's More grid. */
async function drawer({ groups, assignments, navGroups, getPanel, lang = "en", forYouOwner } = {}) {
  const resolved = navGroups || await navGroupsFrom({ groups, assignments });
  return shellDrawer({ scope: { all: true }, projects: [], lang, getPanel, forYouOwner, navGroups: resolved });
}

/** The panel → group map that reproduces a resolved config exactly. */
const assignmentsOf = (groups) => Object.fromEntries(groups.flatMap((g) => g.panels.map((p) => [p.id, g.id])));

/** A resolved group list stripped back to the stored shape (no panels). */
const storedGroups = (groups) => groups.map((g) => ({ id: g.id, name: g.name, collapsed: g.collapsed }));

// ─── Reading the rendered grid ──────────────────────────────────────────────

/** The inside of <div class="shell-more"> ("" when the grid is not rendered). */
function moreInner(html) {
  const m = html.match(/<div class="shell-more">([\s\S]*?)<\/div>/);
  return m ? m[1] : "";
}

const moreHrefs = (html) =>
  [...moreInner(html).matchAll(/<a\b[^>]*class="shell-more-item"[^>]*>/g)]
    .map((m) => (m[0].match(/href="([^"]*)"/) || [])[1]);

const moreHeadings = (html) =>
  [...moreInner(html).matchAll(/<h4 class="shell-more-heading">([^<]*)<\/h4>/g)].map((m) => m[1]);

/** Headings and item hrefs in document order ("# Name" stands for a heading). */
const moreOrder = (html) =>
  [...moreInner(html).matchAll(/<h4 class="shell-more-heading">([^<]*)<\/h4>|<a\b[^>]*class="shell-more-item"[^>]*>/g)]
    .map((m) => (m[1] !== undefined ? `# ${m[1]}` : (m[0].match(/href="([^"]*)"/) || [])[1]));

const everyPanel = (id) => (pid) => (pid === id ? { name: id } : null);

// ─── Labels follow the classic sidebar's rule ───────────────────────────────

for (const [id, label] of [["contacts", "Contacts"], ["files", "Files"], ["blog", "Blog"], ["skills", "Skills"], ["metering", "Usage"]]) {
  test(`More of Crow lists ${id} when its panel is registered, labelled ${label}`, async () => {
    const html = await drawer({ navGroups: defaults, getPanel: everyPanel(id) });
    assert.ok(moreHrefs(html).includes(`/dashboard/${id}`), `${id} link`);
    assert.match(moreInner(html), new RegExp(`class="shell-more-item"[^>]*>${label}<`));
    const without = await drawer({ navGroups: defaults, getPanel: () => null });
    assert.ok(!moreHrefs(without).includes(`/dashboard/${id}`), "absent without the panel");
  });
}

test("fediverse shows only while a federated bundle is installed", async () => {
  writeFileSync(join(dir, "installed.json"), JSON.stringify({ x: { id: "x", tags: ["fediverse"] } }));
  let withBundle;
  try {
    // Visible with a federated bundle installed, so this nav config holds it.
    withBundle = await navGroupsFrom();
    const html = await drawer({ navGroups: withBundle });
    assert.ok(moreHrefs(html).includes("/dashboard/fediverse"), "federated bundle installed: shown");
    assert.match(moreInner(html), /class="shell-more-item"[^>]*>Fediverse Admin</);
  } finally {
    rmSync(join(dir, "installed.json"), { force: true });
  }
  const html = await drawer({ navGroups: withBundle });
  assert.ok(!moreHrefs(html).includes("/dashboard/fediverse"), "no federated bundle: hidden");
});

// ─── The owner's nav settings drive the grid ────────────────────────────────

test("More follows the stored group order, and a panel moved between groups moves with it", async () => {
  const assignments = assignmentsOf(defaults);
  const groups = storedGroups(defaults);
  const order = ["home", "connections", "agents", "workspace", "system"];
  const reordered = order.map((id) => groups.find((g) => g.id === id));
  assignments.blog = "connections"; // Blog leaves Workspace for Connections
  const html = await drawer({ groups: reordered, assignments });
  assert.deepEqual(moreOrder(html), [
    "# Home", "/dashboard/nest?open=1",
    "# Connections", "/dashboard/messages", "/dashboard/contacts", "/dashboard/blog",
    "# Agents", "/dashboard/bot-builder", "/dashboard/model-catalog", "/dashboard/skills",
    "# Workspace", "/dashboard/memory", "/dashboard/files", "/dashboard/metering", "/dashboard/schedule", "/dashboard/extensions",
  ]);
  assert.deepEqual(moreHeadings(html), ["Home", "Connections", "Agents", "Workspace"]);
});

test("a stored group name is escaped in its heading", async () => {
  const evil = '<b>x</b> & "y"';
  const groups = storedGroups(defaults).map((g) => (g.id === "home" ? { id: "my-group", name: evil, collapsed: false } : g));
  const assignments = { ...assignmentsOf(defaults), nest: "my-group" };
  const html = await drawer({ groups, assignments });
  assert.ok(moreHeadings(html).includes('&lt;b&gt;x&lt;/b&gt; &amp; &quot;y&quot;'), "the stored name, escaped, heads its group");
  assert.ok(!html.includes("<b>x</b>"), "no raw markup from a stored group name");
});

test("panels that moved elsewhere never appear, even when a group holds them", async () => {
  const groups = [
    { id: "moved", name: "Moved elsewhere", collapsed: false },
    { id: "only-moved", name: "Only moved", collapsed: false },
  ];
  // Memory keeps the first group alive; the "only-moved" group holds nothing but skips.
  const assignments = { memory: "moved", settings: "only-moved", projects: "only-moved", "bot-board": "only-moved", perch: "only-moved" };
  const html = await drawer({ groups, assignments });
  for (const id of ["settings", "projects", "bot-board", "perch"]) {
    assert.ok(!moreHrefs(html).some((h) => h.replace(/\?.*$/, "") === `/dashboard/${id}`), `${id} stays out of More`);
  }
  assert.ok(moreHrefs(html).includes("/dashboard/memory"), "a normal panel in the same group still renders");
  assert.ok(moreHeadings(html).includes("Moved elsewhere"), "the group's heading is there");
  assert.ok(!moreHeadings(html).includes("Only moved"), "a group left with only moved-on-purpose panels shows no heading");
});

test("For You and Mail lead More, only for the owner with the flags on", async () => {
  const saved = { forYou: process.env.CROW_FOR_YOU, mail: process.env.CROW_MAIL };
  delete process.env.CROW_FOR_YOU;
  delete process.env.CROW_MAIL;
  try {
    const off = await drawer({ navGroups: defaults, forYouOwner: true });
    assert.ok(!moreHrefs(off).includes("/dashboard/for-you"), "flags off: For You absent");
    assert.ok(!moreHrefs(off).includes("/dashboard/mail"), "flags off: Mail absent");

    process.env.CROW_FOR_YOU = "1";
    process.env.CROW_MAIL = "1";
    const notOwner = await drawer({ navGroups: defaults, forYouOwner: false });
    assert.ok(!moreHrefs(notOwner).includes("/dashboard/for-you"), "not the owner: For You absent");
    assert.ok(!moreHrefs(notOwner).includes("/dashboard/mail"), "not the owner: Mail absent");

    const html = await drawer({ navGroups: defaults, forYouOwner: true });
    const order = moreOrder(html);
    assert.deepEqual(order.slice(0, 2), ["/dashboard/for-you", "/dashboard/mail"], "both lead, without a heading");
    const firstHeading = order.findIndex((x) => x.startsWith("# "));
    assert.ok(firstHeading > 1, "the group headings come after both entries");
  } finally {
    if (saved.forYou === undefined) delete process.env.CROW_FOR_YOU;
    else process.env.CROW_FOR_YOU = saved.forYou;
    if (saved.mail === undefined) delete process.env.CROW_MAIL;
    else process.env.CROW_MAIL = saved.mail;
  }
});

test("a collapsed group still lists its panels", async () => {
  const groups = storedGroups(defaults);
  const assignments = { ...assignmentsOf(defaults), memory: "system" }; // System is collapsed by default
  const html = await drawer({ groups, assignments });
  assert.ok(groups.find((g) => g.id === "system").collapsed, "the group is collapsed");
  const order = moreOrder(html);
  const at = order.indexOf("# System");
  assert.ok(at > 0, "the collapsed group's heading is rendered");
  assert.equal(order[at + 1], "/dashboard/memory");
});

test("the nest entry asks for the nest explicitly", async () => {
  const html = await drawer({ navGroups: defaults });
  assert.ok(moreHrefs(html).includes("/dashboard/nest?open=1"), "nest opens with ?open=1");
  assert.ok(!moreHrefs(html).includes("/dashboard/nest"), "never the bare /dashboard/nest (a shell device would land in Chat)");
});

// ─── Coverage guard ────────────────────────────────────────────────────────

// Panels the new shell reaches some other way, on purpose.
const MOVED_ON_PURPOSE = {
  settings: { home: "the avatar menu", why: "account and instance settings live under the profile avatar" },
  projects: { home: "the drawer's project list", why: "projects are the drawer's own rows, with New and Archived links" },
  "bot-board": { home: "the Board tab", why: "the new shell's Board replaces the Bot Board page" },
  perch: { home: "the Chat tab", why: "Perch sessions open from Chat" },
};

/**
 * The panel ids the classic nav shows that More would not: a core panel that
 * fell out of navGroups (a bundle's panel is an app in the launcher instead).
 */
function missingFromMore(navGroups, getPanel = registry.getPanel) {
  const html = shellDrawer({ scope: { all: true }, projects: [], lang: "en", getPanel, navGroups });
  const inMore = new Set(moreHrefs(html).map((h) => h.replace(/\?.*$/, "")));
  return registry.getVisiblePanels()
    .filter((p) => !p.bundleId && !MOVED_ON_PURPOSE[p.id] && !inMore.has(p.route || `/dashboard/${p.id}`))
    .map((p) => p.id);
}

test("every panel the classic nav shows is in More of Crow, an app, or moved on purpose", () => {
  const missing = missingFromMore(defaults);
  assert.deepEqual(missing, [], `panel(s) dropped from the new shell: ${missing.join(", ")} (put the panel back in a nav group, or add it to MOVED_ON_PURPOSE here with a home and a reason)`);
});

test("the coverage guard catches a panel dropped from More", () => {
  const dropped = defaults.map((g) => ({ ...g, panels: g.panels.filter((p) => p.id !== "memory") }));
  assert.ok(defaults.some((g) => g.panels.some((p) => p.id === "memory")), "memory starts in a group");
  assert.deepEqual(missingFromMore(dropped), ["memory"]);
});

test("the moved-on-purpose list stays honest", () => {
  for (const [id, e] of Object.entries(MOVED_ON_PURPOSE)) {
    assert.ok(e.home && e.why, `${id} names a home and a reason`);
    assert.ok(registry.getPanel(id), `${id} is still a registered panel (drop the entry if the panel is gone)`);
  }
});

test("an empty nav config still lists the registry's visible panels", () => {
  const getPanel = (id) => ({ id, name: id });
  const html = shellDrawer({ scope: { all: true }, projects: [], lang: "en", getPanel, navGroups: [] });
  assert.ok(moreHrefs(html).length > 0, "an empty navGroups still renders a grid");
  assert.deepEqual(moreHeadings(html), [], "no group headings without nav groups");
  assert.deepEqual(missingFromMore([], getPanel), [], "the registry fallback covers every visible panel More should list");
});
