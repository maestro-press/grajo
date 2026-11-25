/**
 * The panel's default seams, which is what production runs: the gateway injects neither
 * `isLocalSession` nor `is2faEnabled`, so every route meets the two defaults in
 * `bundles/coinbase/panel/routes.js` and the Connect routes met the one `routes.js` hands them.
 *
 * Both underlying dashboard checks are async, so a default that compares the promise itself is
 * always false — every local-session-gated route would refuse, and 2FA would always read as off.
 * These tests drop the injected seams (through the harness's `seams` escape hatch) and stub the
 * module loaders instead, so the real defaults run against a stub that answers true or false.
 *
 * The last test is a static guard over the panel's own sources: a call to either check that is
 * neither awaited nor handed on unmodified (a bare `return <call>;`, or an arrow given to `.then`
 * whose promise the chain picks up) is a bug of exactly that shape.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import express from "express";

import {
  scaffold,
  cleanupScratch,
  LOCAL_LOGIN_CODE,
  CROW_HOME,
  REPO,
} from "./helpers/coinbase-panel-harness.mjs";

const { createConnectRoutes } = await import("../bundles/coinbase/panel/connect.js");

/** A stubbed dashboard local-session module whose one check answers `answer`. */
const localSessionModule = (answer) => async () => ({
  isLocalPasswordSessionOn: async () => answer,
});

/** A stubbed dashboard totp module whose 2FA switch answers `answer`. */
const totpModule = (answer) => async () => ({
  is2faEnabled: async () => answer,
});

/** The seams that remove an injected default and put a module loader in its place. */
function defaultSeams(overrides) {
  return {
    isLocalSession: undefined,
    is2faEnabled: undefined,
    ...overrides,
  };
}

after(cleanupScratch);

// ---- 1. the kill switch's default local-session read --------------------------------------------

test("test_kill_default_local_session_true_lets_the_kill_through", async () => {
  const h = await scaffold({
    seams: defaultSeams({
      localSessionModule: localSessionModule(true),
      is2faEnabled: async () => true,
    }),
  });
  try {
    const killed = await h.post("/api/coinbase/kill", { confirm: true });
    assert.notEqual(killed.json?.code, LOCAL_LOGIN_CODE, killed.text);
    assert.equal(killed.status, 200, killed.text);
    assert.equal(killed.json?.ok, true, killed.text);
    assert.equal(h.fake.calls("POST", "/kill").length, 1, "the engine was asked to stop");
  } finally {
    await h.close();
  }
});

test("test_kill_default_local_session_false_refuses", async () => {
  const h = await scaffold({
    seams: defaultSeams({
      localSessionModule: localSessionModule(false),
      is2faEnabled: async () => true,
    }),
  });
  try {
    const refused = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.json?.ok, false, refused.text);
    assert.equal(refused.json?.code, LOCAL_LOGIN_CODE, refused.text);
    assert.equal(h.fake.calls("POST", "/kill").length, 0, "nothing was stopped");
  } finally {
    await h.close();
  }
});

// ---- 2. the Connect routes get the panel's own default ------------------------------------------

test("test_connect_route_meets_the_panel_default_local_session", async () => {
  const on = await scaffold({
    seams: defaultSeams({
      localSessionModule: localSessionModule(true),
      is2faEnabled: async () => true,
    }),
  });
  let off = null;
  try {
    const allowed = await on.get("/api/coinbase/tiingo/state");
    assert.notEqual(allowed.json?.code, LOCAL_LOGIN_CODE, allowed.text);
    assert.equal(allowed.status, 200, allowed.text);
    assert.equal(allowed.json?.ok, true, allowed.text);

    off = await scaffold({
      seams: defaultSeams({
        localSessionModule: localSessionModule(false),
        is2faEnabled: async () => true,
      }),
    });
    const refused = await off.get("/api/coinbase/tiingo/state");
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.json?.code, LOCAL_LOGIN_CODE, refused.text);
  } finally {
    await on.close();
    if (off) await off.close();
  }
});

// ---- 3. the Connect routes' own default, with no isLocalSession at all --------------------------

test("test_connect_routes_default_local_session_alone", async () => {
  const h = await scaffold();
  const servers = [];
  try {
    for (const answer of [true, false]) {
      const { router } = createConnectRoutes({
        db: h.db,
        crowHome: CROW_HOME,
        authMiddleware: (req, _res, next) => {
          req.dashboardSession = "coinbase-defaults-session";
          next();
        },
        localSessionModule: localSessionModule(answer),
      });

      const app = express();
      app.use(router);
      const server = app.listen(0, "127.0.0.1");
      servers.push(server);
      await new Promise((resolve) => server.once("listening", resolve));
      const base = `http://127.0.0.1:${server.address().port}`;

      const res = await fetch(base + "/api/coinbase/connect/state");
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* not JSON */ }

      if (answer) {
        assert.notEqual(json?.code, LOCAL_LOGIN_CODE, text);
        assert.equal(res.status, 200, text);
        assert.equal(json?.ok, true, text);
      } else {
        assert.equal(res.status, 403, text);
        assert.equal(json?.code, LOCAL_LOGIN_CODE, text);
      }
    }
  } finally {
    for (const server of servers) {
      await new Promise((resolve) => {
        let done = false;
        const finish = () => { if (!done) { done = true; resolve(); } };
        try { server.close(finish); } catch { finish(); }
        setTimeout(finish, 2000).unref();
      });
    }
    await h.close();
  }
});

// ---- 4. the panel's 2FA default ----------------------------------------------------------------

test("test_panel_two_factor_default_reads_the_totp_module", async () => {
  const on = await scaffold({
    seams: defaultSeams({
      isLocalSession: async () => true,
      totpModule: totpModule(true),
    }),
  });
  let off = null;
  try {
    const panelOn = await on.get("/api/coinbase/panel");
    assert.equal(panelOn.status, 200, panelOn.text);
    assert.equal(panelOn.json?.two_factor, true, panelOn.text);

    off = await scaffold({
      seams: defaultSeams({
        isLocalSession: async () => true,
        totpModule: totpModule(false),
      }),
    });
    const panelOff = await off.get("/api/coinbase/panel");
    assert.equal(panelOff.status, 200, panelOff.text);
    assert.equal(panelOff.json?.two_factor, false, panelOff.text);
  } finally {
    await on.close();
    if (off) await off.close();
  }
});

// ---- 5. no un-awaited read of either check anywhere in the panel --------------------------------

const PANEL_DIR = join(REPO, "bundles", "coinbase", "panel");
const CALL_ONE = /\b(?:isLocalPasswordSessionOn|is2faEnabled)\(/;
const CALL_ALL = new RegExp(CALL_ONE.source, "g");

// `await <ident.>*` right before the call, with any parentheses the expression opens.
const AWAITED = /await\s*\(?\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*$/;
// `return <ident.>*` right before the call: the promise is returned unmodified.
const BARE_RETURN = /^\s*return\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)*$/;
// An arrow given to `.then(...)`: whatever it returns, the chain picks up as a promise.
const THEN_CHAIN = /\.then\(\s*(?:\(\s*(?:[A-Za-z_$][\w$]*\s*)?\)|[A-Za-z_$][\w$]*)\s*=>\s*$/;
const NOTHING_AFTER = /^\s*;?\s*$/;

/** The index of the `)` that closes the `(` at `openIndex`, or -1. */
function closeParen(line, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < line.length; index += 1) {
    const char = line[index];
    if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

/**
 * How one call at `at` is handled: a label when the promise is awaited or handed on unmodified,
 * null when the line reads it as a value of its own (which is the bug).
 */
function callVerdict(line, at) {
  const before = line.slice(0, at);
  if (AWAITED.test(before)) return "awaited";
  if (THEN_CHAIN.test(before)) return "chained into .then";
  const open = line.indexOf("(", at);
  const close = open === -1 ? -1 : closeParen(line, open);
  if (close === -1) return null;
  if (BARE_RETURN.test(before) && NOTHING_AFTER.test(line.slice(close + 1))) {
    return "promise returned";
  }
  return null;
}

/** The verdict for the first such call in one line of text. */
function verdictOf(line) {
  const match = CALL_ONE.exec(line);
  return match ? callVerdict(line, match.index) : "no call";
}

/** Every such call in the panel's sources that reads the promise instead of waiting for it. */
function scanPanelSources() {
  const files = readdirSync(PANEL_DIR).filter((name) => name.endsWith(".js")).sort();
  const seen = [];
  const flagged = [];
  for (const name of files) {
    const text = readFileSync(join(PANEL_DIR, name), "utf8");
    text.split("\n").forEach((line, index) => {
      for (const match of line.matchAll(CALL_ALL)) {
        seen.push({ file: name, line: index + 1 });
        if (!callVerdict(line, match.index)) {
          flagged.push({ file: name, line: index + 1, text: line.trim() });
        }
      }
    });
  }
  return { files, seen, flagged };
}

test("test_panel_sources_never_read_either_check_as_a_value", () => {
  // The guard's own self-check: the buggy shape is flagged, and every accepted shape is not.
  const buggy = [
    "        return module.is2faEnabled() === true;",
    "        return module.isLocalPasswordSessionOn(database, req) === true;",
    "        twoFactorOn = is2faEnabled() === true;",
    "        const on = module.is2faEnabled();",
  ];
  for (const line of buggy) {
    assert.equal(verdictOf(line), null, `not flagged: ${line}`);
  }

  const accepted = [
    "        return (await module.isLocalPasswordSessionOn(database, req)) === true;",
    "        return (await module.is2faEnabled()) === true;",
    "      return isLocalPasswordSessionOn(database, req);",
    "      return module.is2faEnabled();",
    "        twoFactorOn = (await is2faEnabled()) === true;",
    "          .then(() => is2faEnabled())",
  ];
  for (const line of accepted) {
    assert.notEqual(verdictOf(line), null, `flagged but fine: ${line}`);
  }
  assert.equal(verdictOf("const local = await loadLocalSession();"), "no call");

  const { files, seen, flagged } = scanPanelSources();
  assert.deepEqual(flagged, [], `un-awaited checks: ${JSON.stringify(flagged)}`);
  assert.ok(files.includes("routes.js") && files.includes("connect.js"), files.join(", "));
  // A pattern that stopped matching would pass this file silently, so the calls it must see.
  assert.ok(seen.length >= 6, `only ${seen.length} checks found in the panel sources`);
});