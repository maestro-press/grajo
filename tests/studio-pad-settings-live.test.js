/**
 * Studio — where the selected pad's settings sit beside the pads.
 *
 * The Pads widget has always stacked its parts: the header, the bank tabs, the
 * 4x4 pad grid, the tools, the live bar (HOLD, ROLL, the interval, Pause and
 * Normal/Chromatic) and then the selected pad's settings. On a wide Pads widget
 * the settings are meant to move BESIDE the grid: a split wrapper `.st-pads-split`
 * holding `.st-pads-main` (the grid and the tools) and `.st-pads-side` (the live
 * bar, then the settings panel), with the side column sticky. The switch is the
 * WIDGET's own width — a CSS container query on the host element — and not the
 * screen: a 1280 px window with a 700 px widget stacks, and a 760 px widget sits
 * beside.
 *
 * Every case here measures real rectangles on the page a real headless Chrome
 * laid out (tests/fixtures/headless-chrome.mjs), against a real session hub on a
 * scratch database behind the panel's own routes and WebSocket. The harness is
 * the one the shell's other live cases use. No browser: every case skips, unless
 * CROW_REQUIRE_TEST_CHROME=1, which makes the fixture throw instead.
 *
 * A case sets the Pads widget's own width with an inline style, so the container
 * the layout asks about is the one under test, and reads back where the grid,
 * the live bar's controls, the settings panel, the side column and the host
 * really are.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient } from "@libsql/client";
import express from "express";
import { WebSocket, WebSocketServer } from "ws";
import { AclError } from "../servers/shared/project-acl.js";
import { createHub } from "../bundles/studio/server/hub.js";
import { initStudioTables } from "../bundles/studio/server/init-tables.js";
import { createStudioWeb } from "../bundles/studio/server/web.js";
import studioPanel from "../bundles/studio/panel/studio.js";
import { startHeadlessChrome } from "./fixtures/headless-chrome.mjs";

/** The project the song lives in, and its storage prefix. */
const PROJECT = 64;
const PREFIX = "projects/64/";

/** The fixture song's one track (a sampler) and its pattern clip. */
const TRACK = "kit";
const CLIP = "pc";

/** The author a browser command carries (server/web.js's own constant). */
const HUMAN = { kind: "human", id: "local", label: "You" };

/** The sample the fixture puts on pad 1 of the kit's bank. */
const SAMPLE = "3a2f5c1e-9b7d-4c8e-8f1a-2d3e4f5a6b71";

/** The bundle directory the asset routes read from. */
const BUNDLE_DIR = new URL("../bundles/studio", import.meta.url).pathname.replace(/\/$/, "");

/** The dashboard's CSRF helper, as the layout serves it (`<script src="/csrf-client.js">`). */
const CSRF_CLIENT_FILE = new URL(
  "../servers/gateway/public/csrf-client.js",
  import.meta.url,
).pathname;

/**
 * The token the stand-in dashboard auth accepts, and the layout delivers.
 *
 * The real layout renders the SERVER-BOUND token into `<meta name="crow-csrf">`
 * and loads /csrf-client.js, which is what makes `window.crowCsrf()` answer on
 * the page. The Studio client echoes that token in its WebSocket hello frame, so
 * a stand-in layout without those two lines is not a stand-in for the dashboard
 * at all: the hub closes the socket 4401 and the page never gets its song.
 */
const CSRF = "csrf-ok";

/** The stand-in dashboard layout: a bare document around the panel content. */
function minimalLayout({ title, content }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
    + `<meta name="crow-csrf" content="${CSRF}">`
    + `<script src="/csrf-client.js"></script>`
    + `<title>${title}</title></head><body>${content}</body></html>`;
}

// ---- the hub, the server and the browser ---------------------------------

let chrome = null;
let server = null;
let upgrades = null;
let db = null;
let hub = null;
let base = "";
let songId = "";
let dir = "";

/** The pad row and the sample are put on the song once, for every case. */
let fixtureReady = false;

/** One session hub ACL: this project exists and needs no capability check. */
function fakeAcl() {
  async function assertProjectExists(_db, projectId) {
    if (Number(projectId) !== PROJECT) throw new AclError(`Project #${projectId} not found`, "not_found");
    return { id: PROJECT };
  }
  async function assertCapability(database, projectId) {
    return assertProjectExists(database, projectId);
  }
  async function appendAudit() {}
  return { assertProjectExists, assertCapability, appendAudit };
}

/** @returns {string|null} one cookie's value out of a Cookie header. */
function cookieOf(header, name) {
  for (const part of String(header || "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

before(async () => {
  chrome = await startHeadlessChrome({ extraArgs: ["--autoplay-policy=no-user-gesture-required"] });
  if (!chrome) return;

  dir = mkdtempSync(join(tmpdir(), "studio-pad-settings-live-"));
  db = createClient({ url: "file:" + join(dir, "crow.db") });
  await db.execute(
    "CREATE TABLE IF NOT EXISTS project_spaces (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, status TEXT, archived_at TEXT, storage_prefix TEXT)",
  );
  await db.execute({
    sql: "INSERT INTO project_spaces (id, name, storage_prefix) VALUES (?, ?, ?)",
    args: [PROJECT, "Studio project", PREFIX],
  });
  await initStudioTables(db);

  const webRef = { web: null };
  hub = createHub({
    db,
    acl: fakeAcl(),
    onBroadcast: (id, payload) => webRef.web?.broadcast(id, payload),
  });

  const web = createStudioWeb({
    hub,
    Router: express.Router,
    WebSocketServer,
    auth: {
      isAllowedNetwork: () => true,
      sessionFromRequest: (req) => cookieOf(req.headers.cookie, "crow_session"),
      verifySession: async (token) => token === "good",
      csrfTokenAccepted: (_req, presented) => presented === CSRF,
      classifyPeer: () => ({ via: "local" }),
    },
    crowHome: join(dir, "home"),
    bundleDir: BUNDLE_DIR,
  });
  webRef.web = web;

  const created = await hub.createSong({ project_id: PROJECT, title: "Pads layout song", author: HUMAN });
  assert.equal(created.ok, true, `createSong was refused: ${created.error}`);
  songId = created.song_id;

  for (const [command, args] of [
    ["song.set_meta", { bpm: 120 }],
    ["track.add", { id: TRACK, name: "Kit", kind: "sampler" }],
    ["scene.add", { id: "verse", name: "Verse" }],
    [
      "clip.add_pattern",
      { clip_id: CLIP, track_id: TRACK, scene_id: "verse", name: "Beat", length_steps: 16 },
    ],
  ]) {
    const result = await hub.runCommand({ song_id: songId, cmd_id: null, command, args, author: HUMAN });
    assert.equal(result.ok, true, `${command} was refused: ${result.error}`);
  }

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  // The gateway's own Content-Security-Policy for the Studio page and its
  // assets, so the engine's worklet and WebAssembly load here.
  app.use((req, res, next) => {
    if (req.path.startsWith("/dashboard/studio")) {
      res.setHeader("Content-Security-Policy", [
        "default-src 'self'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src https://fonts.gstatic.com",
        "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
        "img-src 'self' data: blob:",
        "media-src 'self' https: blob:",
        "connect-src 'self'",
        "frame-src 'self' https:",
      ].join("; "));
    }
    next();
  });
  app.get("/sw.js", (_req, res) => {
    res.setHeader("content-type", "application/javascript");
    res.end("self.addEventListener('install', function () {});");
  });
  // The dashboard's CSRF helper, served for real: the page's token is the
  // layout's <meta name="crow-csrf"> tag read through it, never a cookie.
  app.get("/csrf-client.js", (_req, res) => {
    res.setHeader("content-type", "application/javascript");
    res.end(readFileSync(CSRF_CLIENT_FILE, "utf8"));
  });
  const dashboardAuth = (req, res, next) => {
    if (!cookieOf(req.headers.cookie, "crow_session")) return res.status(401).json({ error: "unauthorized" });
    return next();
  };
  app.use(web.router(dashboardAuth));
  app.get("/dashboard/studio", async (req, res, next) => {
    try {
      await studioPanel.handler(req, res, { db, layout: minimalLayout });
    } catch (err) {
      next(err);
    }
  });

  server = createServer(app);
  upgrades = web.attachUpgrade(server);
  await new Promise((resolve) => server.listen(0, chrome.bindHost ?? "127.0.0.1", resolve));
  base = `http://${chrome.pageHost ?? "127.0.0.1"}:${server.address().port}`;
});

after(async () => {
  if (upgrades) upgrades.close();
  if (server) {
    try {
      server.closeAllConnections?.();
    } catch {
      // Nothing left to close.
    }
    await new Promise((resolve) => server.close(resolve));
  }
  if (chrome) await chrome.close();
  try {
    db?.close?.();
  } catch {
    // Already gone.
  }
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/** The song page's URL. */
function songUrl() {
  return `${base}/dashboard/studio?song=${encodeURIComponent(songId)}`;
}

/**
 * Open one page in the private browser at a given viewport, with the dashboard's
 * session cookies, and return its CDP handle.
 * @param {string} url
 * @param {{width?: number, height?: number}} [viewport]
 * @returns {Promise<object>}
 */
async function openPage(url, { width = 1280, height = 900 } = {}) {
  const tab = await (await fetch(chrome.cdp + "/json/new?about:blank", { method: "PUT" })).json();
  const socket = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  socket.on("message", (raw) => {
    const message = JSON.parse(String(raw));
    if (message.method === "Runtime.exceptionThrown") {
      console.error(
        "PAGE exception:",
        JSON.stringify(
          message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text,
        ).slice(0, 500),
      );
    }
  });
  let nextId = 0;
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const mine = (nextId += 1);
      const onMessage = (raw) => {
        const message = JSON.parse(String(raw));
        if (message.id !== mine) return;
        socket.off("message", onMessage);
        if (message.error) reject(new Error(JSON.stringify(message.error)));
        else resolve(message.result || {});
      };
      socket.on("message", onMessage);
      socket.send(JSON.stringify({ id: mine, method, params }));
    });

  const evaluate = async (expression) => {
    const outcome = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (outcome.exceptionDetails) throw new Error(JSON.stringify(outcome.exceptionDetails));
    return outcome.result?.value;
  };

  await send("Page.enable");
  await send("Network.enable");
  await send("Runtime.enable");
  await send("Emulation.setDeviceMetricsOverride", {
    // The page decides its size class from window.innerWidth alone, so the
    // viewport is emulated as a desktop one of that width: a mobile emulation
    // would lay the page out at the 980 px it falls back to without a viewport
    // meta, and the width under test would never reach the page.
    width, height, deviceScaleFactor: 1, mobile: false,
  });
  // The session cookie, and deliberately NOT a CSRF cookie: crow_csrf is
  // retired, and the page's token comes from the layout's meta tag through
  // /csrf-client.js. A page that had to read a cookie would fail here.
  await send("Network.setCookie", { name: "crow_session", value: "good", url: `${base}/` });
  await send("Page.navigate", { url });

  return {
    evaluate,
    send,
    close: async () => {
      try {
        socket.close();
      } catch {
        // Already closed.
      }
      try {
        await fetch(chrome.cdp + "/json/close/" + tab.id);
      } catch {
        // The tab is going away either way.
      }
    },
  };
}

/**
 * Poll a page until `expression` is truthy.
 * @returns {Promise<any>} the last value, or false after the timeout
 */
async function waitFor(page, expression, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  let last = false;
  while (Date.now() < deadline) {
    try {
      last = await page.evaluate(expression);
    } catch {
      last = false;
    }
    if (last) return last;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return last;
}

/** @returns {Promise<void>} after `ms` milliseconds */
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The expression that reads one element's own rectangle, in page pixels, or
 * null while it has no rectangle to press (absent, or laid out with no size).
 * @param {string} selector
 * @returns {string}
 */
function boxExpression(selector) {
  return `(function () {
    var node = document.querySelector(${JSON.stringify(selector)});
    if (!node) return null;
    var rect = node.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return null;
    return {
      x: rect.left + rect.width / 2,
      y: rect.top + rect.height / 2,
      w: rect.width,
      h: rect.height
    };
  })()`;
}

/** @returns {boolean} whether two rectangles are the same place and size */
function sameBox(one, other) {
  const near = (a, b) => Math.abs(a - b) < 0.5;
  return near(one.x, other.x) && near(one.y, other.y)
    && near(one.w, other.w) && near(one.h, other.h);
}

/**
 * A real mouse press and release at one rectangle's middle.
 * @param {(method: string, params?: object) => Promise<any>} send
 * @param {{x: number, y: number}} box
 */
async function clickBox(send, box) {
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: box.x, y: box.y, button: "none" });
  await send("Input.dispatchMouseEvent", {
    type: "mousePressed", x: box.x, y: box.y, button: "left", clickCount: 1,
  });
  await send("Input.dispatchMouseEvent", {
    type: "mouseReleased", x: box.x, y: box.y, button: "left", clickCount: 1,
  });
}

/**
 * One control's rectangle once it has stopped moving: the same on two reads
 * `settleMs` apart. A rectangle that never stands still in time answers with the
 * last one read (pressing that is what a person's own press would do), and a
 * control that is not on the page answers null.
 * @returns {Promise<{x: number, y: number, w: number, h: number}|null>}
 */
async function settledBox(page, selector, settleMs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let previous = null;
  let latest = null;
  for (;;) {
    try {
      latest = await page.evaluate(boxExpression(selector));
    } catch {
      latest = null;
    }
    if (latest && previous && sameBox(previous, latest)) return latest;
    previous = latest;
    if (Date.now() + settleMs >= deadline) return latest;
    await pause(settleMs);
  }
}

/** Wait until the song page is up: the top bar mounted and the grid drawn. */
async function waitForStudio(page) {
  assert.ok(
    await waitFor(page, "!!document.querySelector('.studio [data-role=studio-top]')", 30000),
    "the studio shell mounted",
  );
  // The token the page echoes in its WebSocket hello is the layout's own (the
  // <meta name="crow-csrf"> tag through /csrf-client.js), never a cookie.
  assert.equal(
    await waitFor(
      page,
      "(function () { return typeof window.crowCsrf === 'function' ? window.crowCsrf() : ''; })()",
      10000,
    ),
    CSRF,
    "the page carries the dashboard layout's server-bound CSRF token",
  );
  assert.ok(
    await waitFor(page, "!!document.querySelector('[data-role=grid] .st-corner')", 30000),
    "the session grid rendered (the page's Yjs replica did not load)",
  );
  assert.ok(
    await waitFor(page, "!!document.querySelector('[data-role=studio-widgets]')", 20000),
    "the widget area filled in",
  );
}

// ---- the fixture: a pattern clip open, and one sound on pad 1 -------------

/**
 * Select the fixture's pattern clip, which opens the pads (and the steps with
 * them).
 * @param {object} page
 */
async function selectPatternClip(page) {
  // The grid is its own scroller (a phone's grid is wider than the window), so
  // the cell is brought into the viewport before it is measured and pressed: a
  // press outside the viewport is a press on nothing.
  assert.ok(
    await page.evaluate(`(function () {
      var cell = document.querySelector('[data-role=grid] [data-clip-id=${CLIP}]');
      if (!cell) return false;
      cell.scrollIntoView({ block: 'center', inline: 'center' });
      return true;
    })()`),
    "the fixture's clip cell is on the page",
  );
  await pause(300);
  const clipCell = await settledBox(page, `[data-role=grid] [data-clip-id=${CLIP}]`, 250, 20000);
  assert.ok(clipCell, "the fixture's clip cell has a rectangle to press");
  await clickBox(page.send, clipCell);
  // The sixteen pads are the pads host's own count at every width (a phone's
  // steps host pages its steps, so the steps' count is not a width-neutral
  // signal that the pattern clip opened).
  assert.ok(
    await waitFor(page, "document.querySelectorAll('[data-act=pad]').length === 16", 20000),
    "the pattern clip opened: the sixteen pads are on the page",
  );
  await pause(500);
}

/**
 * Put one sound on pad 1 of the kit's bank, so pad 1 is the selected pad and
 * `.st-pad-settings` holds its own fields. Done once for the whole file: the
 * commands are the song's own and a second `sample.add` of the same id is not a
 * thing the hub would take again.
 * @param {object} page
 */
async function putSoundOnFirstPad(page) {
  const bankId = await page.evaluate(`(function () {
    var node = document.querySelector('[data-bank-id]');
    return node ? node.getAttribute('data-bank-id') : null;
  })()`);
  assert.ok(bankId, "the pads widget names the bank it is showing");

  // Set before the commands so a refusal is reported by the first case that
  // runs and is never replayed by the ones after it.
  fixtureReady = true;

  const sampleAdded = await hub.runCommand({
    song_id: songId,
    cmd_id: null,
    command: "sample.add",
    args: {
      sample: {
        id: SAMPLE,
        storage_key: PREFIX + "studio/s1.wav",
        rate: 48000,
        channels: 2,
        frames: 48000,
        name: "knock",
        origin: "import",
        author_label: "You",
      },
    },
    author: HUMAN,
    internal: true,
  });
  assert.equal(sampleAdded.ok, true, `sample.add was refused: ${sampleAdded.error}`);

  const padAssigned = await hub.runCommand({
    song_id: songId,
    cmd_id: null,
    command: "pad.assign",
    args: { track_id: TRACK, bank_id: bankId, index: 0, sample_id: SAMPLE },
    author: HUMAN,
    internal: true,
  });
  assert.equal(padAssigned.ok, true, `pad.assign was refused: ${padAssigned.error}`);
}

/**
 * Open the song page with a pattern clip open and pad 1's settings drawn.
 * @param {{width?: number, height?: number}} [viewport]
 * @returns {Promise<object>} the page handle
 */
async function openPadsPage(viewport) {
  const page = await openPage(songUrl(), viewport);
  try {
    await waitForStudio(page);
    await pause(1000);
    await selectPatternClip(page);
    if (!fixtureReady) await putSoundOnFirstPad(page);
    await pause(500);
    assert.ok(
      await waitFor(page, "!!document.querySelector('.st-pad-settings [data-pad-field]')", 20000),
      "the selected pad's settings hold their fields",
    );
    return page;
  } catch (err) {
    await page.close();
    throw err;
  }
}

// ---- what the page is asked about, and how it answers ---------------------

/**
 * Set the Pads widget's OWN width, and let the page lay out again. The host is
 * the container the layout asks about, so this is the width under test — a
 * window of any size around it changes nothing about it.
 * @param {object} page
 * @param {number} px
 */
async function padsHostWidth(page, px) {
  const width = Number(px);
  const ok = await page.evaluate(`(function () {
    var host = document.querySelector('[data-role=sampler-pads]');
    if (!host) return false;
    host.style.width = ${JSON.stringify(String(width) + "px")};
    host.style.maxWidth = ${JSON.stringify(String(width) + "px")};
    host.style.boxSizing = 'border-box';
    return true;
  })()`);
  assert.ok(ok, "the Pads widget is on the page");
  await pause(200);
}

/**
 * The rectangles (getBoundingClientRect) of the parts a case asks about: the
 * union of the sixteen pads (the grid), the selected pad's settings panel, the
 * live bar (`[data-act=pad-hold]`'s own `.st-pad-bar` parent) and the row of
 * tools the client draws under the grid (`.st-sampler-tools`), the live bar's
 * five controls, the mode buttons, the side column and the host.
 * @param {object} page
 */
function rects(page) {
  return page.evaluate(`(function () {
    function rectOf(node) {
      if (!node) return null;
      var r = node.getBoundingClientRect();
      if (r.width <= 0 && r.height <= 0) return null;
      return { left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
    }
    var pads = document.querySelectorAll('[data-act=pad]');
    var grid = null;
    for (var i = 0; i < pads.length; i += 1) {
      var r = pads[i].getBoundingClientRect();
      if (r.width <= 0 && r.height <= 0) continue;
      if (!grid) grid = { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
      else {
        if (r.left < grid.left) grid.left = r.left;
        if (r.top < grid.top) grid.top = r.top;
        if (r.right > grid.right) grid.right = r.right;
        if (r.bottom > grid.bottom) grid.bottom = r.bottom;
      }
    }
    if (grid) {
      grid.width = grid.right - grid.left;
      grid.height = grid.bottom - grid.top;
    }
    var modeNodes = document.querySelectorAll('[data-act=pad-mode]');
    var modes = [];
    for (var m = 0; m < modeNodes.length; m += 1) modes.push(rectOf(modeNodes[m]));
    return {
      pads: pads.length,
      grid: grid,
      settings: rectOf(document.querySelector('.st-pad-settings')),
      side: rectOf(document.querySelector('.st-pads-side')),
      tools: rectOf(document.querySelector('.st-sampler-tools')),
      bar: (function () {
        var hold = document.querySelector('[data-act=pad-hold]');
        return rectOf(hold && hold.parentNode ? hold.parentNode : null);
      })(),
      hold: rectOf(document.querySelector('[data-act=pad-hold]')),
      roll: rectOf(document.querySelector('[data-act=pad-roll]')),
      interval: rectOf(document.querySelector('[data-act=roll-interval]')),
      pause: rectOf(document.querySelector('[data-act=pad-pause]')),
      mode: rectOf(modeNodes.length > 0 ? modeNodes[0] : null),
      modes: modes,
      host: rectOf(document.querySelector('[data-role=sampler-pads]'))
    };
  })()`);
}

// ---- the cases -----------------------------------------------------------

test("at an 800 px Pads widget the settings sit beside the grid", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPadsPage({ width: 1280, height: 900 });
  try {
    await padsHostWidth(page, 800);
    const r = await rects(page);
    assert.equal(r.pads, 16, "the sixteen pads are on the page");
    assert.ok(r.grid, "the pad grid has a rectangle");
    assert.ok(r.settings, "the selected pad's settings have a rectangle");
    assert.ok(
      r.settings.left >= r.grid.right - 1,
      `the settings start at or right of the grid's right edge (settings left ${r.settings.left}, grid right ${r.grid.right})`,
    );
    assert.ok(
      r.settings.top < r.grid.bottom,
      `the settings sit beside the grid, not under it (settings top ${r.settings.top}, grid bottom ${r.grid.bottom})`,
    );
  } finally {
    await page.close();
  }
});

test("at a 700 px Pads widget the settings sit below the grid", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPadsPage({ width: 1280, height: 900 });
  try {
    await padsHostWidth(page, 700);
    const r = await rects(page);
    assert.equal(r.pads, 16, "the sixteen pads are on the page");
    assert.ok(r.grid, "the pad grid has a rectangle");
    assert.ok(r.settings, "the selected pad's settings have a rectangle");
    assert.ok(
      r.settings.top >= r.grid.bottom - 1,
      `the settings start at or below the grid's bottom edge (settings top ${r.settings.top}, grid bottom ${r.grid.bottom})`,
    );
    assert.ok(
      r.settings.left < r.grid.right,
      `the settings are not pushed past the grid's own right edge (settings left ${r.settings.left}, grid right ${r.grid.right})`,
    );
  } finally {
    await page.close();
  }
});

test("the 760 px threshold is the widget's own width, not the screen", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPadsPage({ width: 1280, height: 900 });
  try {
    await padsHostWidth(page, 759);
    const below = await rects(page);
    assert.ok(below.grid && below.settings, "the grid and the settings are on the page");
    assert.ok(
      below.settings.top >= below.grid.bottom - 1,
      `a 759 px Pads widget stacks (settings top ${below.settings.top}, grid bottom ${below.grid.bottom})`,
    );

    await padsHostWidth(page, 760);
    const beside = await rects(page);
    assert.ok(beside.grid && beside.settings, "the grid and the settings are on the page");
    assert.ok(
      beside.settings.left >= beside.grid.right - 1,
      `a 760 px Pads widget sets the settings beside the grid (settings left ${beside.settings.left}, grid right ${beside.grid.right})`,
    );
    assert.ok(
      beside.settings.top < beside.grid.bottom,
      `and not under it (settings top ${beside.settings.top}, grid bottom ${beside.grid.bottom})`,
    );
    assert.ok(beside.side, "the settings column has a rectangle");
    assert.ok(
      beside.side.width >= 260,
      `a 760 px Pads widget leaves the settings column at least 260 px wide (column ${beside.side.width})`,
    );
  } finally {
    await page.close();
  }
});

test("HOLD, ROLL, the interval, Pause and Normal/Chromatic sit at the top of the settings column", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPadsPage({ width: 1280, height: 900 });
  try {
    await padsHostWidth(page, 800);
    const r = await rects(page);
    assert.ok(r.grid, "the pad grid has a rectangle");
    assert.ok(r.settings, "the selected pad's settings have a rectangle");
    assert.ok(r.side, "the Pads widget has a settings column beside the pads");

    for (const [name, box] of [
      ["HOLD", r.hold],
      ["ROLL", r.roll],
      ["the ROLL interval", r.interval],
      ["Pause", r.pause],
      ["the first pad mode button", r.mode],
    ]) {
      assert.ok(box, `${name} is on the page`);
      assert.ok(
        box.left >= r.side.left - 1 && box.right <= r.side.right + 1,
        `${name} sits inside the settings column (${box.left}..${box.right}, column ${r.side.left}..${r.side.right})`,
      );
      assert.ok(
        box.bottom <= r.settings.top + 1,
        `${name} sits above the settings panel (its bottom ${box.bottom}, settings top ${r.settings.top})`,
      );
    }
    assert.ok(
      r.hold.top - r.grid.top <= 80,
      `HOLD keeps to the top of the column, level with the top of the grid (hold top ${r.hold.top}, grid top ${r.grid.top})`,
    );
  } finally {
    await page.close();
  }
});

test("the settings column is sticky", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPadsPage({ width: 1280, height: 900 });
  try {
    await padsHostWidth(page, 800);
    const layout = await page.evaluate(`(function () {
      var side = document.querySelector('.st-pads-side');
      if (!side) return null;
      var style = window.getComputedStyle(side);
      // A sticky box follows its nearest scroll container, so any ancestor that
      // scrolls (or hides what runs past it) would hold the column where it is
      // instead of letting it follow the window. This walks every one of them.
      var scrollers = [];
      var node = side.parentElement;
      while (node) {
        var up = window.getComputedStyle(node);
        var sideways = up.overflowX;
        var down = up.overflowY;
        var scrolls = ['hidden', 'auto', 'scroll'];
        if (scrolls.indexOf(sideways) >= 0 || scrolls.indexOf(down) >= 0) {
          var where = String(node.tagName || '').toLowerCase();
          var cls = node.getAttribute('class');
          if (cls) where += '.' + String(cls).trim().split(/\\s+/).join('.');
          scrollers.push(where + ' (overflow-x: ' + sideways + ', overflow-y: ' + down + ')');
        }
        if (node === document.documentElement) break;
        node = node.parentElement;
      }
      var box = side.getBoundingClientRect();
      return {
        position: style.position,
        top: style.top,
        height: box.height,
        viewport: window.innerHeight,
        scrollers: scrollers
      };
    })()`);
    assert.ok(layout, "the settings column is on the page");
    assert.equal(layout.position, "sticky", "the settings column follows the page with position: sticky");
    assert.deepEqual(
      layout.scrollers,
      [],
      `no ancestor of the settings column scrolls, or the column could not follow the window (found ${layout.scrollers.join("; ")})`,
    );
    assert.ok(
      layout.height <= layout.viewport - 16 + 1,
      `the settings column is never taller than the window (column ${layout.height} px, window ${layout.viewport} px)`,
    );
    assert.equal(layout.top, "8px", "the settings column keeps 8 px under the top of the window");
  } finally {
    await page.close();
  }
});

test("a phone is unchanged", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPadsPage({ width: 390, height: 800 });
  try {
    // A phone shows one widget at a time: the pads are behind their own tab.
    const tab = await settledBox(page, "[data-widget-tab=pads]", 250, 20000);
    assert.ok(tab, "a phone offers a Pads tab");
    await clickBox(page.send, tab);
    await pause(400);

    const r = await rects(page);
    assert.equal(r.pads, 16, "the sixteen pads are on the page");
    assert.ok(r.grid, "the pad grid has a rectangle");
    assert.ok(r.settings, "the selected pad's settings have a rectangle");
    assert.ok(r.hold, "HOLD is on the page");

    assert.ok(
      r.settings.top >= r.grid.bottom - 1,
      `a phone stacks the settings under the grid (settings top ${r.settings.top}, grid bottom ${r.grid.bottom})`,
    );
    assert.ok(
      r.hold.top > r.grid.bottom - 1,
      `the live bar sits below the grid (hold top ${r.hold.top}, grid bottom ${r.grid.bottom})`,
    );
    assert.ok(
      r.hold.bottom <= r.settings.top + 1,
      `and above the settings panel (hold bottom ${r.hold.bottom}, settings top ${r.settings.top})`,
    );

    // The stack's own rhythm: the tools row under the grid, then the live bar,
    // then the settings, each 10 px from the one before it. Measured as the
    // rectangles' own gaps, so a split that lost its gap (the tools row pressed
    // against the live bar) is caught, and not just a missing class.
    assert.ok(r.tools, "the row of pad tools under the grid has a rectangle");
    assert.ok(r.bar, "the live bar has a rectangle");
    const toolsToBar = r.bar.top - r.tools.bottom;
    assert.ok(
      toolsToBar >= 9 && toolsToBar <= 11,
      `the live bar sits 10 px under the pad tools row (tools bottom ${r.tools.bottom}, bar top ${r.bar.top}, gap ${toolsToBar})`,
    );
    const barToSettings = r.settings.top - r.bar.bottom;
    assert.ok(
      barToSettings >= 9 && barToSettings <= 11,
      `the settings panel sits 10 px under the live bar (bar bottom ${r.bar.bottom}, settings top ${r.settings.top}, gap ${barToSettings})`,
    );

    assert.ok(
      await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"),
      "the phone page has no horizontal scroll",
    );

    const targets = [
      ["HOLD", r.hold],
      ["ROLL", r.roll],
      ["the ROLL interval", r.interval],
      ["Pause", r.pause],
    ];
    r.modes.forEach((box, at) => targets.push([`pad mode button ${at + 1}`, box]));
    for (const [name, box] of targets) {
      assert.ok(box, `${name} is on the page`);
      assert.ok(
        box.width >= 44 && box.height >= 44,
        `${name} is a 44 px target (${box.width} x ${box.height})`,
      );
    }
  } finally {
    await page.close();
  }
});

test("no horizontal scroll at a wide widget", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPadsPage({ width: 1280, height: 900 });
  try {
    await padsHostWidth(page, 800);
    assert.ok(
      await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"),
      "the page has no horizontal scroll",
    );
  } finally {
    await page.close();
  }
});