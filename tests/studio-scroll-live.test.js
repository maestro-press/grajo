/**
 * Studio — the page's own scroll position while a person works on it.
 *
 * The harness is the one tests/studio-panel-shell-live.test.js uses: a real
 * session hub on a scratch database behind the panel's own routes and
 * WebSocket, and a private headless Chrome (tests/fixtures/headless-chrome.mjs)
 * loading the page the handler renders. No browser: every case skips, unless
 * CROW_REQUIRE_TEST_CHROME=1, which makes the fixture throw instead.
 *
 * Both cases put the window somewhere in a page taller than the viewport, act
 * with a real mouse on a control that is not where the person is looking, and
 * read `window.scrollY` back. The first one arms the keyboard on the Pads
 * controls first, the way an operator who just played a pad leaves it, and then
 * picks a step far below them. The second one launches a scene from Perform with
 * the launch button centred.
 *
 * Each case also carries a CONTROL that moves the page with a plain browser
 * default (`focus()` without `preventScroll`, and `window.scrollTo(0, 0)`), so
 * the comparison a case is decided by is one that does flag a move when the
 * page really moves.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
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
const PROJECT = 62;
const PREFIX = "projects/62/";

/** The fixture song's one track, its clip and its two scenes. */
const TRACK = "kit";
const CLIP = "pc";

/** The author a browser command carries (server/web.js's own constant). */
const HUMAN = { kind: "human", id: "local", label: "You" };

/** The sample the fixture puts on pad 1 of the kit's bank. */
const SAMPLE = "6f1c1f7a-8f7e-4a4e-9a1d-2b3c4d5e6f70";

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
 * The real layout (servers/gateway/dashboard/shared/layout.js) renders the
 * SERVER-BOUND token into `<meta name="crow-csrf">` and loads
 * /csrf-client.js, which is what makes `window.crowCsrf()` answer on the page.
 * The Studio client echoes that token in its WebSocket hello frame, so a
 * stand-in layout without those two lines is not a stand-in for the dashboard
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

  dir = mkdtempSync(join(tmpdir(), "studio-scroll-live-"));
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

  const created = await hub.createSong({ project_id: PROJECT, title: "Scroll song", author: HUMAN });
  assert.equal(created.ok, true, `createSong was refused: ${created.error}`);
  songId = created.song_id;

  for (const [command, args] of [
    ["song.set_meta", { bpm: 120 }],
    ["track.add", { id: TRACK, name: "Kit", kind: "sampler" }],
    ["scene.add", { id: "verse", name: "Verse" }],
    ["scene.add", { id: "chorus", name: "Chorus" }],
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
 * Open one page in the private browser at a given viewport, with the
 * dashboard's session cookies, and return its CDP handle.
 * @param {string} url
 * @param {{width?: number, height?: number}} [viewport]
 * @returns {Promise<object>}
 */
async function openPage(url, { width = 1280, height = 700 } = {}) {
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

/** The ids of the frames the widget area is showing right now, in page order. */
const VISIBLE_WIDGETS = `(function () {
  var area = document.querySelector('[data-role=studio-widgets]');
  if (!area) return [];
  var ids = [];
  for (var i = 0; i < area.children.length; i += 1) {
    var node = area.children[i];
    var id = node.getAttribute ? node.getAttribute('data-widget') : null;
    if (!id) continue;
    if (node.hasAttribute('hidden')) continue;
    ids.push(id);
  }
  return ids;
})()`;

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
 * `settleMs` apart. A rectangle that never stands still in time answers with
 * the last one read (pressing that is what a person's own press would do), and
 * a control that is not on the page answers null.
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

/** @returns {Promise<boolean>} one read of `doneExpression`, false if it throws */
async function isDone(page, expression) {
  try {
    return !!(await page.evaluate(expression));
  } catch {
    return false;
  }
}

/**
 * Wait until the page is ready for a press: the control is on the page, the
 * song's own title has replaced the placeholder the page draws before its first
 * snapshot (`Song`), the replica has drawn the session grid, and the page's own
 * handlers are attached (the client sets `window.__crowStudioLatency` on the
 * line after it adds them).
 * @param {object} page
 * @param {string} selector the control about to be pressed
 * @param {number} timeoutMs
 * @returns {Promise<boolean>} whether the page got there in time
 */
async function waitForPressable(page, selector, timeoutMs) {
  const ready = `(function () {
    if (!document.querySelector(${JSON.stringify(selector)})) return false;
    var title = document.querySelector('[data-role=title]');
    var text = title ? String(title.textContent || '').trim() : '';
    if (text === '' || text === 'Song') return false;
    if (!document.querySelector('[data-role=grid] .st-corner')) return false;
    return !!window.__crowStudioLatency;
  })()`;
  return !!(await waitFor(page, ready, timeoutMs));
}

/**
 * Press a top-bar control once, on a page that is ready for it: the page's own
 * conditions first, then the control's rectangle standing still, then exactly
 * one real press. What the press should change is the CALLER's to wait for.
 * @param {object} page
 * @param {string} selector
 * @param {{already?: string, settleMs?: number, timeoutMs?: number}} [options]
 * @returns {Promise<{x: number, y: number, w: number, h: number}|null>} the box
 *   that was pressed, null when the control never became pressable
 */
async function pressSettled(page, selector, options = {}) {
  const settleMs = options.settleMs ?? 250;
  const timeoutMs = options.timeoutMs ?? 20000;
  if (!(await waitForPressable(page, selector, timeoutMs))) return null;
  const box = await settledBox(page, selector, settleMs, timeoutMs);
  if (!box) return null;
  if (options.already && (await isDone(page, options.already))) return box;
  await clickBox(page.send, box);
  return box;
}

/** Wait until the song page is up: the top bar mounted and the grid drawn. */
async function waitForStudio(page) {
  assert.ok(
    await waitFor(page, "!!document.querySelector('.studio [data-role=studio-top]')", 30000),
    "the studio shell mounted",
  );
  // The token the page echoes in its WebSocket hello is the layout's own
  // (the <meta name="crow-csrf"> tag through /csrf-client.js), never a cookie.
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
    await waitFor(page, VISIBLE_WIDGETS + ".length > 0", 20000),
    "the widget area filled in",
  );
}

// ---- F1: a step picked from far below the Pads controls ------------------

test("picking a step while the transport is stopped keeps the page where it is", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPage(songUrl(), { width: 1280, height: 700 });
  try {
    await waitForStudio(page);
    await pause(1000);

    // Select the fixture's pattern clip, which is what opens its 16 steps.
    const clipCell = await settledBox(page, `[data-role=grid] [data-clip-id=${CLIP}]`, 250, 20000);
    assert.ok(clipCell, "the fixture's clip cell is on the page");
    await clickBox(page.send, clipCell);
    assert.ok(
      await waitFor(page, "document.querySelectorAll('[data-act=step]').length === 16", 20000),
      "the clip's 16 steps are on the page",
    );

    // One sound on pad 1 of the kit's bank, so the Pads controls are the ones a
    // person who just played a pad has the keyboard on.
    const bankId = await page.evaluate(`(function () {
      var node = document.querySelector('[data-bank-id]');
      return node ? node.getAttribute('data-bank-id') : null;
    })()`);
    assert.ok(bankId, "the pads widget names the bank it is showing");
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
    await pause(1000);

    // The keyboard on the Pads control, as an operator who just used the Pads
    // controls leaves it: scrolled to, and focused without the page moving.
    assert.ok(
      await page.evaluate(`(function () {
        var node = document.querySelector('[data-act=pad-hold]');
        if (!node) return false;
        node.scrollIntoView({ block: 'center' });
        return true;
      })()`),
      "the Pads control is on the page",
    );
    await pause(300);
    assert.ok(
      await page.evaluate(`(function () {
        var node = document.querySelector('[data-act=pad-hold]');
        if (!node) return false;
        node.focus({ preventScroll: true });
        return true;
      })()`),
      "the Pads control takes the keyboard",
    );
    assert.equal(
      await page.evaluate("document.activeElement === document.querySelector('[data-act=pad-hold]')"),
      true,
      "the keyboard is on the Pads control",
    );

    // The step far below them, about 300 px down from the top of the viewport.
    assert.ok(
      await page.evaluate(`(function () {
        var node = document.querySelector("[data-act=step][data-at='3']");
        if (!node) return false;
        window.scrollBy(0, node.getBoundingClientRect().top - 300);
        return true;
      })()`),
      "the step at position 4 is on the page",
    );
    await pause(300);
    const before = await page.evaluate("window.scrollY");
    assert.ok(
      before > 1500,
      `the steps really are far below the Pads controls (the window is at ${before})`,
    );

    // So a move to the Pads control is a move a person would see.
    const distance = await page.evaluate(`(function () {
      var pad = document.querySelector('[data-act=pad-hold]');
      var step = document.querySelector("[data-act=step][data-at='3']");
      if (!pad || !step) return null;
      return {
        padTop: pad.getBoundingClientRect().top,
        apart: Math.abs(step.getBoundingClientRect().top - pad.getBoundingClientRect().top)
      };
    })()`);
    assert.ok(distance, "both the Pads control and the step are on the page");
    assert.ok(
      distance.padTop < -400 || distance.apart > 600,
      `the Pads control is far from the step (its top is ${distance.padTop}, they are ${distance.apart} px apart)`,
    );

    // A real mouse press on the step.
    const stepBox = await settledBox(page, "[data-act=step][data-at='3']", 250, 10000);
    assert.ok(stepBox, "the step is on the page and has a rectangle");
    await clickBox(page.send, stepBox);
    assert.ok(
      await waitFor(page, `(function () {
        var node = document.querySelector("[data-act=step][data-at='3']");
        return !!node && node.getAttribute('data-step-on') === 'true';
      })()`, 20000),
      "the press turned the step on",
    );
    await pause(500);

    const after = await page.evaluate("window.scrollY");
    assert.ok(
      Math.abs(after - before) <= 2,
      `picking the step kept the page where it was (was ${before}, is ${after})`,
    );

    // The comparison above flags a move the browser makes on its own: focusing
    // the Pads control without `preventScroll` takes the page back up to it.
    // The keyboard is taken off the Pads control first: the step press left it
    // as the focused element, and focusing an element that already has focus
    // never scrolls, so without the blur the control would report no move.
    await page.evaluate(`(function () {
      var active = document.activeElement;
      if (active && active !== document.body && active.blur) active.blur();
      var node = document.querySelector('[data-act=pad-hold]');
      if (node) node.focus();
    })()`);
    await pause(300);
    const control = await page.evaluate("window.scrollY");
    assert.ok(
      Math.abs(control - before) > 100,
      `the comparison flags a move to the Pads control (was ${before}, is ${control})`,
    );
  } finally {
    await page.close();
  }
});

// ---- F5: a scene launched from Perform -----------------------------------

test("launching a scene in Perform keeps the page where it is", async (t) => {
  if (!chrome) return t.skip("no headless Chrome available");

  const page = await openPage(songUrl(), { width: 1280, height: 700 });
  try {
    await waitForStudio(page);
    await pause(1000);

    const performBox = await pressSettled(page, "[data-mode=perform]");
    assert.ok(performBox, "the Perform button was on the page and was pressed");
    await pause(800);

    const tall = await page.evaluate("document.documentElement.scrollHeight > window.innerHeight + 600");
    assert.ok(tall, "the Perform page is taller than the viewport, so the window has room to move");

    // The chorus launch button, centred in the viewport.
    assert.ok(
      await page.evaluate(`(function () {
        var node = document.querySelector('[data-scene-id=chorus] [data-act=launch-scene]');
        if (!node) return false;
        node.scrollIntoView({ block: 'center' });
        return true;
      })()`),
      "the chorus launch button is on the page",
    );
    await pause(300);
    const before = await page.evaluate("window.scrollY");
    assert.ok(before > 100, `the window is scrolled to the launch button (at ${before})`);

    const launchBox = await settledBox(
      page, "[data-scene-id=chorus] [data-act=launch-scene]", 250, 10000,
    );
    assert.ok(launchBox, "the chorus launch button has a rectangle to press");
    await clickBox(page.send, launchBox);

    // Where the window is at each of these moments after the press.
    const polled = [];
    let elapsed = 0;
    for (const at of [50, 300, 800, 1500]) {
      await pause(at - elapsed);
      elapsed = at;
      polled.push({ at, y: await page.evaluate("window.scrollY") });
    }
    const moved = polled.filter((read) => Math.abs(read.y - before) > 2);
    assert.deepEqual(
      moved,
      [],
      `launching the scene kept the page where it was (was ${before}, then ${
        polled.map((read) => `${read.at}ms: ${read.y}`).join(", ")})`,
    );

    // The same comparison flags a snap to the top of the page.
    await page.evaluate("window.scrollTo(0, 0)");
    await pause(100);
    const control = await page.evaluate("window.scrollY");
    assert.ok(
      Math.abs(control - before) > 100,
      `the comparison flags a snap to the top (was ${before}, is ${control})`,
    );
  } finally {
    await page.close();
  }
});