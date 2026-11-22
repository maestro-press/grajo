/**
 * Fix-it cards for a bundle that is GONE — tests/fix-it-uninstalled-bundle-cards.test.js
 *
 * An uninstall removes a docker bundle's folder and its installed.json record, but the
 * cards Crow raised about that bundle's own compose file and containers were only ever
 * answered by a detector loop over INSTALLED bundles. An id that is no longer installed is
 * never revisited, so its card stayed pending forever — motionEye's "settings file has an
 * update Crow did not apply" (source bundle-compose-image-change, key `bundle:motioneye`)
 * was still on the Attention sheet after motionEye had been removed.
 *
 * Two halves, both tested here:
 *
 *   the boot sweep   bundle-bind-drift's check() resolves a pending family card whose
 *                    bundle id is NOT in installed.json (a satellite entry counts as
 *                    installed) — but never on a pass for ONE bundle (`only`, which the
 *                    Start/stop/install re-check uses), and never when installed.json
 *                    cannot be read (a read failure must not mass-resolve anything);
 *   the uninstall    resolveCardsForBundle(store, id) resolves them right there, so the
 *                    Extensions page and the Attention sheet are clean as soon as the
 *                    uninstall's own reply arrives.
 *
 * The family is the five bundle-bind-drift sources plus the browser add-on's stale-image
 * card, which keys `bundle:browser:image-stale` and is about the INSTALLED copy's running
 * container. The retired-bundle card is deliberately NOT in it: it keys `retired:<id>`,
 * not `bundle:<id>`, and its own detector already answers it the moment the bundle is
 * gone.
 *
 * Docker is never real (the detector's `runner` is a stub) and CROW_HOME is a scratch
 * directory set BEFORE the dynamic imports.
 */
import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

function put(root, relPath, content) {
  const p = join(root, relPath);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
}

let home;
let mod;
let detector;
let SOURCE;
let COMPOSE_EDITED_SOURCE;
let REPO_DRIFT_SOURCE;
let COMPOSE_NEEDS_CONFIG_SOURCE;
let COMPOSE_IMAGE_CHANGE_SOURCE;
let BROWSER_IMAGE_STALE_SOURCE;
const silent = { warn() {}, log() {} };

before(async () => {
  home = mkdtempSync(join(tmpdir(), "crowhome-uninstalled-cards-"));
  process.env.CROW_HOME = home;
  mod = await import("../servers/gateway/fix-it/detectors/bundle-bind-drift.js");
  detector = mod.default;
  SOURCE = mod.SOURCE;
  COMPOSE_EDITED_SOURCE = mod.COMPOSE_EDITED_SOURCE;
  REPO_DRIFT_SOURCE = mod.REPO_DRIFT_SOURCE;
  COMPOSE_NEEDS_CONFIG_SOURCE = mod.COMPOSE_NEEDS_CONFIG_SOURCE;
  COMPOSE_IMAGE_CHANGE_SOURCE = mod.COMPOSE_IMAGE_CHANGE_SOURCE;
  ({ SOURCE: BROWSER_IMAGE_STALE_SOURCE } = await import("../servers/gateway/fix-it/detectors/browser-image-stale.js"));
});

after(() => {
  delete process.env.CROW_HOME;
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
});

beforeEach(() => {
  rmSync(join(home, "bundles"), { recursive: true, force: true });
  rmSync(join(home, "installed.json"), { force: true });
});

/** installed.json, as the gateway writes it. */
function setInstalled(entries) {
  put(home, "installed.json", JSON.stringify(entries));
}

/** An installed docker bundle in the scratch Crow home (folder + manifest + compose). */
function bundle(id, compose = 'services:\n  web:\n    image: x\n    ports:\n      - "127.0.0.1:8555:5000"\n') {
  put(home, `bundles/${id}/manifest.json`, JSON.stringify({
    id, name: id, version: "1.0.0", type: "bundle", docker: { composefile: "docker-compose.yml" },
  }));
  put(home, `bundles/${id}/docker-compose.yml`, compose);
}

/**
 * A store holding PENDING cards, recording what the detector resolved — the same shape
 * the gateway's bound store has (`resolveByKey(source, key)` and `listBySource(source)`).
 */
function cardStore(cards) {
  const rows = cards.map((c) => ({ status: "pending", ...c }));
  const resolved = [];
  const upserts = [];
  const store = {
    rows,
    resolved,
    upserts,
    async upsertItem(item) { upserts.push(item); return { id: upserts.length, notify: false }; },
    async resolveByKey(source, key) {
      resolved.push(`${source}|${key}`);
      for (const r of rows) if (r.source === source && r.dedupKey === key) r.status = "resolved";
    },
    async listBySource(source) { return rows.filter((r) => r.source === source); },
    async recordDuplicate() {},
    async recordSuppressed() {},
    async markResolved() {},
    statusOf(source, key) {
      const row = rows.find((r) => r.source === source && r.dedupKey === key);
      return row ? row.status : "missing";
    },
  };
  return store;
}

/** A `docker` CLI stand-in: nothing runs, so `ps` answers with no containers. */
function dockerStub() {
  const calls = [];
  const runner = async (cmd, args) => {
    calls.push({ cmd, args });
    if (args[0] === "ps") return { stdout: "", stderr: "" };
    return { stdout: "[]", stderr: "" };
  };
  runner.calls = calls;
  return runner;
}

const pass = (store, opts = {}) => detector.check(store, { crowHome: home, runner: dockerStub(), log: silent, ...opts });

describe("the boot sweep: a card for a bundle installed.json no longer lists", () => {
  test("(a) one boot pass resolves a pending image-change card for an uninstalled bundle", async () => {
    setInstalled([]);
    const store = cardStore([{ source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:motioneye" }]);

    const out = await pass(store);

    assert.deepEqual(store.resolved, [`${COMPOSE_IMAGE_CHANGE_SOURCE}|bundle:motioneye`]);
    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, "bundle:motioneye"), "resolved");
    assert.equal(out.swept.length, 1, "the pass reports what it answered");
    assert.deepEqual(out.swept[0], { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:motioneye" });
  });

  test("(b) an INSTALLED bundle's card is left exactly as it is", async () => {
    // A vendor entry with no folder on this machine: the per-bundle loop has nothing to
    // say about it, so anything that happens to its card here is the SWEEP's doing.
    setInstalled([{ id: "still-installed" }]);
    const store = cardStore([
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:still-installed" },
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:gone" },
    ]);

    await pass(store);

    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, "bundle:still-installed"), "pending");
    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, "bundle:gone"), "resolved", "control: the sweep did run");
  });

  test("(c) installed.json unreadable (or missing) → nothing is resolved", async () => {
    const key = "bundle:motioneye";
    const store = cardStore([{ source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: key }]);

    // Unparseable: a torn write or a hand-edited file.
    put(home, "installed.json", "{ this is not json");
    const lines = [];
    await pass(store, { log: { warn: (m) => lines.push(m), log() {} } });
    assert.deepEqual(store.resolved, [], "a read failure is not 'nothing is installed'");
    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, key), "pending");
    assert.ok(lines.some((l) => /installed\.json could not be read/.test(l)), `log: ${lines.join(" | ")}`);

    // Missing altogether: same refusal (never a mass-resolve on a fresh home).
    rmSync(join(home, "installed.json"), { force: true });
    await pass(store);
    assert.deepEqual(store.resolved, []);
    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, key), "pending");

    // Control: the file is readable and empty, so the card really was the sweep's to answer.
    setInstalled([]);
    await pass(store);
    assert.deepEqual(store.resolved, [`${COMPOSE_IMAGE_CHANGE_SOURCE}|${key}`]);
  });

  test("(f) a pass for ONE bundle (`only`) sweeps nothing", async () => {
    setInstalled([]);
    const store = cardStore([{ source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:motioneye" }]);
    await pass(store, { only: ["motioneye"] });
    assert.deepEqual(store.resolved, [], "the Start/stop/install re-check answers one bundle's own cards, never everybody's");
    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, "bundle:motioneye"), "pending");

    // Control: the same card, the same home, on a BOOT pass — which is the sweep's to answer.
    const bootStore = cardStore([{ source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:motioneye" }]);
    await pass(bootStore);
    assert.deepEqual(bootStore.resolved, [`${COMPOSE_IMAGE_CHANGE_SOURCE}|bundle:motioneye`]);
  });

  test("(e) a dedup key that does not name a valid bundle id is ignored", async () => {
    setInstalled([]);
    const store = cardStore([
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:Not_An_Id" },
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:" },
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:../escape" },
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:motioneye" },
    ]);

    await pass(store);

    assert.deepEqual(store.resolved, [`${COMPOSE_IMAGE_CHANGE_SOURCE}|bundle:motioneye`], "only the valid key's card");
    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, "bundle:Not_An_Id"), "pending");
  });
});

describe("the uninstall helper: every family card for this one bundle", () => {
  test("(d) resolveCardsForBundle resolves the whole family for that id and nothing else", async () => {
    const store = cardStore([
      // The whole family, for the bundle being removed.
      { source: SOURCE, dedupKey: "bundle:gone" },
      { source: COMPOSE_EDITED_SOURCE, dedupKey: "bundle:gone" },
      { source: REPO_DRIFT_SOURCE, dedupKey: "bundle:gone:repo" },
      { source: COMPOSE_NEEDS_CONFIG_SOURCE, dedupKey: "bundle:gone" },
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:gone" },
      // Another bundle's cards, and the browser add-on's (a different id).
      { source: SOURCE, dedupKey: "bundle:stays" },
      { source: COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: "bundle:stays" },
      { source: BROWSER_IMAGE_STALE_SOURCE, dedupKey: "bundle:browser:image-stale" },
    ]);

    const resolved = await mod.resolveCardsForBundle(store, "gone");

    assert.equal(resolved.length, 5);
    for (const source of [SOURCE, COMPOSE_EDITED_SOURCE, REPO_DRIFT_SOURCE, COMPOSE_NEEDS_CONFIG_SOURCE, COMPOSE_IMAGE_CHANGE_SOURCE]) {
      const key = source === REPO_DRIFT_SOURCE ? "bundle:gone:repo" : "bundle:gone";
      assert.equal(store.statusOf(source, key), "resolved", `${source} ${key}`);
    }
    assert.equal(store.statusOf(SOURCE, "bundle:stays"), "pending", "another bundle's card is not touched");
    assert.equal(store.statusOf(COMPOSE_IMAGE_CHANGE_SOURCE, "bundle:stays"), "pending");
    assert.equal(store.statusOf(BROWSER_IMAGE_STALE_SOURCE, "bundle:browser:image-stale"), "pending");

    // The browser add-on's stale-image card keys by ITS bundle id too, so it goes with it.
    const browser = await mod.resolveCardsForBundle(store, "browser");
    assert.equal(browser.length, 1);
    assert.equal(store.statusOf(BROWSER_IMAGE_STALE_SOURCE, "bundle:browser:image-stale"), "resolved");
  });

  test("(d) an id that is not a bundle id resolves nothing", async () => {
    const store = cardStore([{ source: SOURCE, dedupKey: "bundle:gone" }]);

    assert.deepEqual(await mod.resolveCardsForBundle(store, "../escape"), []);
    assert.deepEqual(await mod.resolveCardsForBundle(store, ""), []);
    assert.deepEqual(store.resolved, []);
  });
});