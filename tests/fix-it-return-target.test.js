/**
 * Where a Fix-it click sends the owner back, and what flash it carries.
 *
 * The `return` body field is the one client-supplied value in the redirect: it
 * may only ever select one of the two code-held targets, so `returnTargetOf`
 * answers "sheet" for the one accepted string and "nest" for everything else
 * (a path, a URL, a protocol, an array, an object). Built URLs therefore never
 * leave the dashboard.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { pairingTag } from "../servers/shared/peer-id.js";

const REPO = join(import.meta.dirname, "..");
const dir = mkdtempSync(join(tmpdir(), "fixit-return-"));
process.env.CROW_DATA_DIR = dir;
mkdirSync(join(dir, "home"), { recursive: true });
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

const SHEET_PREFIX = "/dashboard/perch?sheet=attention&";
const NEST_PREFIX = "/dashboard/nest?";

let db, idx, registry, store, flash, ALREADY_RESTARTING_FLASH;

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env }, stdio: "pipe", cwd: REPO,
  });
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
  idx = await import("../servers/gateway/fix-it/index.js");
  registry = await import("../servers/shared/fix-it/registry.js");
  store = await import("../servers/shared/fix-it/store.js");
  flash = await import("../servers/gateway/fix-it/flash.js");
  ALREADY_RESTARTING_FLASH = (await import("../servers/gateway/fix-it/remedies/restore-bundle-compose.js")).ALREADY_RESTARTING_FLASH;

  assert.equal(typeof flash.returnTargetOf, "function", "servers/gateway/fix-it/flash.js must export returnTargetOf(value)");
  assert.equal(typeof flash.returnUrl, "function", "servers/gateway/fix-it/flash.js must export returnUrl(target, flash, params)");
  assert.equal(typeof flash.flashBanner, "function", "servers/gateway/fix-it/flash.js must export flashBanner(flash, lang, opts)");
  assert.ok(Array.isArray(flash.FLASH_CODES), "servers/gateway/fix-it/flash.js must export the FLASH_CODES array");

  idx.wireFixIt();
});

after(() => {
  try { db.close(); } catch {}
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
});

beforeEach(async () => { await db.execute("DELETE FROM fix_it_items"); });

let seq = 0;
/** One pending card of this test's own (a fresh dedup key every time). */
async function card({ source = "remote-exposure", remedies = [], context = null } = {}) {
  seq += 1;
  const { id } = await store.upsertItem(db, {
    source,
    dedupKey: `test-card-${seq}`,
    title: `Card ${seq}`,
    why: "why",
    severity: "warn",
    remedies,
    context,
  });
  return id;
}

/** POST the action with a fake req/res; returns the redirect URL. */
async function click(body) {
  let redirected = null;
  await idx.handleFixItAction(
    { body },
    { redirectAfterPost: (url) => { redirected = url; } },
    { db },
  );
  assert.equal(typeof redirected, "string", "handleFixItAction must always redirect");
  return redirected;
}

test("returnTargetOf accepts exactly the one string and never leaves the dashboard", () => {
  assert.equal(flash.returnTargetOf("sheet"), "sheet");
  for (const value of [
    undefined, null, "", "nest", "SHEET", " sheet", "sheet ", "sheets",
    ["sheet"], { a: 1 }, true, 1,
    "//evil.example", "https://evil.example/x", "/dashboard/anything",
    "javascript:alert(1)", "/dashboard/perch?sheet=attention",
  ]) {
    assert.equal(flash.returnTargetOf(value), "nest",
      `returnTargetOf(${JSON.stringify(value)}) must be "nest" — a client-supplied value may only pick between the two code-held targets`);
  }
});

test("the two targets are the Nest and the sheet, and are frozen", () => {
  assert.deepEqual(Object.keys(flash.RETURN_TARGETS).sort(), ["nest", "sheet"]);
  assert.equal(flash.RETURN_TARGETS.nest, "/dashboard/nest");
  assert.equal(flash.RETURN_TARGETS.sheet, "/dashboard/perch?sheet=attention");
  assert.equal(Object.isFrozen(flash.RETURN_TARGETS), true, "RETURN_TARGETS is frozen");
});

test("returnUrl builds the two URLs from the code-held table only", () => {
  assert.equal(flash.returnUrl("nest", "fixit_dismissed"), "/dashboard/nest?flash=fixit_dismissed");
  assert.equal(flash.returnUrl("sheet", "fixit_dismissed"), "/dashboard/perch?sheet=attention&flash=fixit_dismissed");
  assert.equal(flash.returnUrl("sheet", "fixit_done"), "/dashboard/perch?sheet=attention&flash=fixit_done");
  assert.equal(flash.returnUrl("nest", "backup_ok"), "/dashboard/nest?flash=backup_ok");

  // An unknown code never reaches the URL: it degrades to the error flash.
  for (const target of ["nest", "sheet"]) {
    for (const bogus of ["bogus", "", null, undefined, "flash=fixit_done", "fixit_done&return=https://evil.example"]) {
      const url = flash.returnUrl(target, bogus);
      assert.ok(url.endsWith("flash=fixit_error"), `${target} + ${JSON.stringify(bogus)} → ${url}`);
    }
    // A target that is not one of the two is the Nest.
    assert.ok(flash.returnUrl("elsewhere", "fixit_done").startsWith(NEST_PREFIX));
    assert.ok(flash.returnUrl("//evil.example", "fixit_done").startsWith(NEST_PREFIX));
  }
});

test("returnUrl keeps the addon/key parameters only when they pass their checks", () => {
  const unwalled = flash.returnUrl("nest", "fixit_addon_unwalled", { addon: "browser" });
  assert.equal(unwalled, "/dashboard/nest?flash=fixit_addon_unwalled&addon=browser");
  for (const bad of ["Bad Id", "<script>", "", "Browser", "a/b", 5, null, undefined, ["browser"]]) {
    assert.equal(flash.returnUrl("nest", "fixit_addon_unwalled", { addon: bad }),
      "/dashboard/nest?flash=fixit_addon_unwalled",
      `a bad addon id (${JSON.stringify(bad)}) adds no &addon`);
  }

  const needsKey = flash.returnUrl("sheet", "fixit_compose_needs_key", { key: "VIKUNJA_DB_PASSWORD" });
  assert.equal(needsKey, "/dashboard/perch?sheet=attention&flash=fixit_compose_needs_key&key=VIKUNJA_DB_PASSWORD");
  for (const bad of ["2BAD", "-X", "", "A B", "X;rm -rf /", null, 7, { key: "X" }]) {
    assert.equal(flash.returnUrl("sheet", "fixit_compose_needs_key", { key: bad }),
      "/dashboard/perch?sheet=attention&flash=fixit_compose_needs_key",
      `a bad key (${JSON.stringify(bad)}) adds no &key`);
  }

  // A parameter that belongs to another flash is never added.
  assert.equal(flash.returnUrl("nest", "fixit_done", { addon: "browser", key: "X" }), "/dashboard/nest?flash=fixit_done");
});

test("dismiss goes back where the form asked, and only there", async () => {
  const id = await card();
  assert.equal(await click({ action: "dismiss", item_id: String(id), return: "sheet" }),
    "/dashboard/perch?sheet=attention&flash=fixit_dismissed");
  assert.equal((await store.getItem(db, id)).status, "dismissed");

  const other = await card();
  assert.equal(await click({ action: "dismiss", item_id: String(other) }),
    "/dashboard/nest?flash=fixit_dismissed");

  const third = await card();
  assert.equal(await click({ action: "dismiss", item_id: String(third), return: "//evil.example" }),
    "/dashboard/nest?flash=fixit_dismissed", "a client-supplied path is never used");
});

test("every redirect path honours the return target", async () => {
  const cases = [];

  // A bad item id.
  cases.push({ body: { action: "remedy", item_id: "abc" }, flash: "fixit_error" });
  // A missing item.
  cases.push({ body: { action: "remedy", item_id: "999999" }, flash: "fixit_error" });
  // An unknown action.
  cases.push({ body: { action: "frobnicate", item_id: "1" }, flash: "fixit_error" });
  // An unknown action_id on a real, pending card.
  const unknownActionId = await card({ remedies: [{ actionId: "test-fix-it-instant", kind: "instant", label: "Fix it" }] });
  cases.push({ body: { action: "remedy", item_id: String(unknownActionId), action_id: "no-such-remedy" }, flash: "fixit_error" });
  // A gated remedy.
  const gated = await card({ remedies: [{ actionId: "test-fix-it-instant", kind: "confirm", label: "Fix it" }] });
  cases.push({ body: { action: "remedy", item_id: String(gated), action_id: "test-fix-it-instant" }, flash: "fixit_error" });
  // A card that is no longer pending.
  const resolved = await card({ remedies: [{ actionId: "test-fix-it-instant", kind: "instant", label: "Fix it" }] });
  await store.markResolved(db, resolved);
  cases.push({ body: { action: "remedy", item_id: String(resolved), action_id: "test-fix-it-instant" }, flash: "fixit_not_pending" });
  // A remedy that throws.
  registry.registerRemedy("test-fix-it-throws", async () => { throw new Error("boom"); });
  const throws = await card({ remedies: [{ actionId: "test-fix-it-throws", kind: "instant", label: "Fix it" }] });
  cases.push({ body: { action: "remedy", item_id: String(throws), action_id: "test-fix-it-throws" }, flash: "fixit_error" });

  for (const { body, flash: expected } of cases) {
    assert.ok((await click(body)).startsWith(NEST_PREFIX),
      `without a return field: ${JSON.stringify(body)} lands on the Nest`);
    const url = await click({ ...body, return: "sheet" });
    assert.ok(url.startsWith(SHEET_PREFIX),
      `with return=sheet: ${JSON.stringify(body)} lands on the sheet (got ${url})`);
    assert.ok(url.endsWith(`flash=${expected}`), `${JSON.stringify(body)} → ${url} (expected flash=${expected})`);
  }
});

test("a resolving remedy ends in fixit_done, a sharing remedy in fixit_fixed", async () => {
  registry.registerRemedy("test-fix-it-resolves", async () => ({ resolved: true }));
  // A non-exposure card: the action handler now runs an expose action only on a
  // remote-exposure card, so a test remedy lives on a card of another source (the
  // sharing card below is a genuine remote-exposure one).
  const plain = await card({ source: "test-source", remedies: [{ actionId: "test-fix-it-resolves", kind: "instant", label: "Fix it" }] });
  assert.equal(await click({ action: "remedy", item_id: String(plain), action_id: "test-fix-it-resolves" }),
    "/dashboard/nest?flash=fixit_done");

  // The peer-exposure remedy grants an allowance: its flash stays fixit_fixed.
  const peerId = "peer-allow";
  const tokenHash = `test-token-hash-${peerId}`;
  await db.execute({
    sql: "INSERT OR REPLACE INTO crow_instances (id, name, crow_id, status, trusted, auth_token_hash) VALUES (?, ?, ?, 'active', 1, ?)",
    args: [peerId, "Peer allow", "crow-test", tokenHash],
  });
  const sharing = await card({
    remedies: [{
      actionId: "expose-capability-30d",
      kind: "instant",
      label: "Allow for 30 days",
      args: { capability: "funkwhale", requestingInstance: peerId, days: 30 },
    }],
    context: { capability: "funkwhale", requestingInstance: peerId, pairingTag: pairingTag(tokenHash) },
  });
  const url = await click({ action: "remedy", item_id: String(sharing), action_id: "expose-capability-30d", return: "sheet" });
  assert.equal(url, "/dashboard/perch?sheet=attention&flash=fixit_fixed",
    "a sharing remedy (expose-capability) keeps the fixit_fixed flash");
  assert.equal((await store.getItem(db, sharing)).status, "resolved");
});

test("flashBanner: tones and texts, and never a banner for a code the Nest does not know", () => {
  assert.deepEqual(flash.flashBanner("fixit_done", "en"), { tone: "success", text: "Done." });
  assert.deepEqual(flash.flashBanner("fixit_done", "es"), { tone: "success", text: "Listo." });
  assert.deepEqual(flash.flashBanner("fixit_fixed", "en"), { tone: "success", text: "Done — it's shared now." });
  assert.deepEqual(flash.flashBanner("fixit_dismissed", "en"), { tone: "success", text: "Dismissed for now." });
  assert.deepEqual(flash.flashBanner("fixit_error", "en"), { tone: "error", text: "Couldn't apply that fix." });
  assert.deepEqual(flash.flashBanner("fixit_not_pending", "en"), { tone: "error", text: "That card isn't open any more — nothing was changed." });
  assert.equal(flash.flashBanner("fixit_retired_removing", "en").tone, "info",
    "a removal that only started is neither a success nor an error");

  // A start already in flight is not a failure: the approved sentence, in both languages,
  // drawn by the same flashBanner that draws OWNER_ONLY_FLASH.
  assert.deepEqual(flash.flashBanner(ALREADY_RESTARTING_FLASH, "en"), {
    tone: "info",
    text: "This add-on is already restarting. Give it a few minutes.",
  });
  assert.deepEqual(flash.flashBanner(ALREADY_RESTARTING_FLASH, "es"), {
    tone: "info",
    text: "Este complemento ya se está reiniciando. Dale unos minutos.",
  });

  for (const code of flash.FLASH_CODES) {
    const banner = flash.flashBanner(code, "en");
    assert.ok(banner && typeof banner.text === "string" && banner.text.length > 0,
      `FLASH_CODES member "${code}" must render a banner`);
    assert.ok(["success", "error", "info"].includes(banner.tone),
      `FLASH_CODES member "${code}" has an unknown tone "${banner.tone}"`);
  }

  for (const unknown of ["bogus", undefined, null, ""]) {
    assert.equal(flash.flashBanner(unknown, "en"), null, `flashBanner(${JSON.stringify(unknown)}) is null`);
  }

  // The new code is part of the accepted set, and the old ones still are.
  for (const code of [
    "backup_ok", "backup_fail", "fixit_fixed", "fixit_dismissed", "fixit_error",
    "fixit_not_pending", "fixit_addon_stale", "fixit_addon_unwalled", "fixit_owner_only",
    "fixit_compose_needs_key", "fixit_retired_removed", "fixit_retired_removing", "fixit_done",
    "fixit_already_restarting",
  ]) {
    assert.ok(flash.FLASH_CODES.includes(code), `FLASH_CODES must still carry "${code}"`);
  }
});

test("index.js lets the already-restarting flash through to the redirect", () => {
  assert.ok(idx.REMEDY_FLASHES.includes(ALREADY_RESTARTING_FLASH),
    "REMEDY_FLASHES must carry the already-restarting flash, or the Nest drops it");
});

test("both backup redirects go through returnUrl/returnTargetOf (source shape)", () => {
  // The one allowed source-shape assertion: mounting the real dashboard router
  // needs a session, auth and the whole panel registry.
  const src = readFileSync(join(REPO, "servers/gateway/dashboard/index.js"), "utf8");
  assert.ok(/from\s+"\.\.\/fix-it\/flash\.js"/.test(src), "the dashboard routes import the flash helpers from fix-it/flash.js");
  assert.ok(src.includes("returnTargetOf"), "the backup route reads returnTargetOf for body.return");
  assert.ok(src.includes("returnUrl"), "the backup redirects are built with returnUrl");
  assert.ok((src.match(/returnUrl\(/g) || []).length >= 2,
    "both backup outcomes (ok and failed) are built with returnUrl");
  assert.equal(src.includes("/dashboard/nest?flash=backup_ok"), false,
    "the backup success redirect no longer hard-codes the Nest URL");
  assert.equal(src.includes("/dashboard/nest?flash=backup_fail"), false,
    "the backup failure redirect no longer hard-codes the Nest URL");
});