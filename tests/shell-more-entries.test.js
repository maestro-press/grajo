// "More of Crow" coverage: the new shell's drawer must keep a way to every panel the classic
// side menu shows. Each core panel is in MORE_ENTRIES, an app (a bundle's panel), or on the
// explicit "moved on purpose" list below, each with its new home and a reason.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "shell-more-entries-"));
process.env.CROW_HOME = dir; // no installed.json: no federated bundle
const DASH = new URL("../servers/gateway/dashboard/", import.meta.url).pathname;

let shellDrawer, registry, corePanels;
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
});
after(() => rmSync(dir, { recursive: true, force: true }));

const render = (getPanel = registry.getPanel) =>
  shellDrawer({ scope: { all: true }, projects: [], lang: "en", getPanel });
const moreHrefs = (html) => {
  const m = html.match(/<div class="shell-more">(.*?)<\/div>/s);
  return m ? [...m[1].matchAll(/href="([^"]+)"/g)].map((x) => x[1]) : [];
};
const everyPanel = (id) => (pid) => (pid === id ? { name: id } : null);

for (const [id, label] of [["contacts", "Contacts"], ["files", "Files"], ["blog", "Blog"], ["skills", "Skills"], ["metering", "Usage"]]) {
  test(`More of Crow lists ${id} when its panel is registered, labelled ${label}`, () => {
    const html = render(everyPanel(id));
    assert.ok(moreHrefs(html).includes(`/dashboard/${id}`), `${id} link`);
    assert.match(html, new RegExp(`class="shell-more-item">${label}<`));
    assert.ok(!moreHrefs(render(() => null)).includes(`/dashboard/${id}`), "absent without the panel");
  });
}

test("fediverse shows only while a federated bundle is installed", () => {
  const fed = (pid) => (pid === "fediverse" ? registry.getPanel("fediverse") : null);
  assert.ok(!moreHrefs(render(fed)).includes("/dashboard/fediverse"), "no federated bundle: hidden");
  writeFileSync(join(dir, "installed.json"), JSON.stringify({ x: { id: "x", tags: ["fediverse"] } }));
  try {
    const html = render(fed);
    assert.ok(moreHrefs(html).includes("/dashboard/fediverse"), "federated bundle installed: shown");
    assert.match(html, /class="shell-more-item">Fediverse Admin</);
  } finally { rmSync(join(dir, "installed.json"), { force: true }); }
});

// Panels the new shell reaches some other way, on purpose.
const MOVED_ON_PURPOSE = {
  settings: { home: "the avatar menu", why: "account and instance settings live under the profile avatar" },
  projects: { home: "the drawer's project list", why: "projects are the drawer's own rows, with New and Archived links" },
  "bot-board": { home: "the Board tab", why: "the new shell's Board replaces the Bot Board page" },
  perch: { home: "the Chat tab", why: "Perch sessions open from Chat" },
};

test("every panel the classic nav shows is in More of Crow, an app, or moved on purpose", () => {
  const inMore = new Set(moreHrefs(render()).map((h) => h.replace(/\?.*$/, "")));
  const missing = [];
  for (const p of registry.getVisiblePanels()) {
    if (p.bundleId) continue; // a bundle's panel is an app in the launcher
    if (MOVED_ON_PURPOSE[p.id]) continue;
    if (!inMore.has(p.route || `/dashboard/${p.id}`)) missing.push(p.id);
  }
  assert.deepEqual(missing, [], `panel(s) dropped from the new shell: ${missing.join(", ")} (add to MORE_ENTRIES in shell/chrome.js, or to MOVED_ON_PURPOSE here with a home and a reason)`);
});

test("the moved-on-purpose list stays honest", () => {
  for (const [id, e] of Object.entries(MOVED_ON_PURPOSE)) {
    assert.ok(e.home && e.why, `${id} names a home and a reason`);
    assert.ok(registry.getPanel(id), `${id} is still a registered panel (drop the entry if the panel is gone)`);
  }
});
