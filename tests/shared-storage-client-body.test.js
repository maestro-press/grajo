// The Shared Storage settings page's own client must post a body the dashboard can parse. The dashboard
// mounts only `express.urlencoded` (dashboard/index.js), so the page's former `new FormData()` (multipart)
// reached the section with no `action`: Save and Test never ran, the page re-rendered (HTTP 200, HTML),
// and the client then showed "Saved". This drives the page's real `apiCall` against an express app
// with the dashboard's parser.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import express from "express";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = readFileSync(join(REPO, "servers/gateway/dashboard/settings/sections/shared-storage.js"), "utf8");

function apiCallSource() {
  const start = SRC.indexOf("async function apiCall(");
  assert.ok(start > 0, "the page defines apiCall");
  let depth = 0;
  for (let i = SRC.indexOf("{", start); i < SRC.length; i++) {
    if (SRC[i] === "{") depth++;
    else if (SRC[i] === "}" && --depth === 0) return SRC.slice(start, i + 1);
  }
  throw new Error("apiCall is not closed");
}

async function withApp(handler, fn) {
  const app = express();
  app.use("/dashboard", express.urlencoded({ extended: false }));   // the dashboard's only body parser
  app.post("/dashboard/settings", handler);
  const server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  try { await fn(`http://127.0.0.1:${server.address().port}`); } finally { server.close(); }
}

function pageApiCall(base) {
  const ctx = vm.createContext({
    URLSearchParams, FormData, JSON,
    window: { location: { pathname: "/dashboard/settings", search: "?section=shared-storage" } },
    fetch: (url, init) => fetch(base + url, init),
  });
  vm.runInContext(apiCallSource(), ctx);
  return ctx.apiCall;
}

test("Save reaches the section's handler with its action and payload through the dashboard's parser", async () => {
  let seen = null;
  await withApp((req, res) => { seen = req.body; res.json({ ok: true, message: "saved" }); }, async (base) => {
    const r = await pageApiCall(base)("save", { endpoint: "minio:9000", access_key: "AK" });
    assert.equal(r.ok, true);
    assert.equal(r.json.message, "saved");
  });
  assert.equal(seen?.action, "save");
  assert.deepEqual(JSON.parse(seen.payload), { endpoint: "minio:9000", access_key: "AK" });
});

test("a page re-rendered as HTML (the action was not handled) is a failure, never a Saved", async () => {
  await withApp((_req, res) => { res.status(200).type("html").send("<!doctype html><p>settings</p>"); }, async (base) => {
    const r = await pageApiCall(base)("save", {});
    assert.equal(r.ok, false);
  });
});

test("a handler error keeps its JSON error for the page to show", async () => {
  await withApp((_req, res) => { res.status(400).json({ error: "endpoint required" }); }, async (base) => {
    const r = await pageApiCall(base)("test", {});
    assert.equal(r.ok, false);
    assert.equal(r.json.error, "endpoint required");
  });
});
