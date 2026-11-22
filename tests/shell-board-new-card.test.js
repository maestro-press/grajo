/**
 * The Board tab's "New card" button, sheet and client (red first — the
 * feature does not exist yet).
 *
 * Pure: no scratch DB. The markup comes from boardHtml() over hand-built
 * board objects (the shape tests/shell-board-lanes.test.js and
 * tests/shell-board-panel.test.js already use), the styles from boardCss(),
 * and the client from boardClientJs() — the emitted <script> blocks lifted
 * out and run for real in linkedom + node:vm, with fetch stubbed, so the
 * exact request body and the dialog/status/focus behaviour are asserted
 * rather than guessed from the source.
 *
 * Nothing here quotes client code: the emitted scripts are run, never re-quoted.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { parseHTML } from "linkedom";

import { boardHtml } from "../servers/gateway/dashboard/panels/board/html.js";
import { boardCss } from "../servers/gateway/dashboard/panels/board/css.js";
import { boardClientJs } from "../servers/gateway/dashboard/panels/board/client.js";
import { DEFAULT_BOARD_DEF } from "../servers/gateway/routes/board-defs.js";
import { escapeHtml } from "../servers/gateway/dashboard/shared/components.js";
import { t } from "../servers/gateway/dashboard/shared/i18n.js";

const EN = (key) => t(key, "en");
const ES = (key) => t(key, "es");

const PROJECTS = Object.freeze([
  { id: 1, slug: "alpha", name: "Alpha" },
  { id: 2, slug: "beta", name: "Beta" },
]);

const CARD = Object.freeze({
  id: 5, title: "alpha-five", status: "pending", priority: 3, project_id: 1,
  autonomy: "gated", action_needed: null, data_json: "{}",
});

/** A board with one card in Up next. */
function boardWithCards() {
  return {
    counts: { needs_you: 0, working: 0, up_next: 1, done: 0 },
    lanes: { needs_you: [], working: [], up_next: [CARD], done: [] },
    defs: new Map([[null, DEFAULT_BOARD_DEF]]),
    lockMap: new Map([[5, false]]),
    threads: new Map(),
    birds: new Map(),
    hrefByCard: new Map(),
    slugByProject: new Map([[1, "alpha"]]),
  };
}

/** The empty board: every count 0, every lane empty. */
function emptyBoard() {
  return {
    counts: { needs_you: 0, working: 0, up_next: 0, done: 0 },
    lanes: { needs_you: [], working: [], up_next: [], done: [] },
    defs: new Map([[null, DEFAULT_BOARD_DEF]]),
    lockMap: new Map(),
    threads: new Map(),
    birds: new Map(),
    hrefByCard: new Map(),
    slugByProject: new Map(),
  };
}

function dom(html) {
  const { window, document } = parseHTML(`<html><body>${html}</body></html>`);
  return { window, document };
}

/** The new-card sheet in a rendered board, or null. */
function sheetOf(document) {
  return document.querySelector("dialog[data-sb-newcard-sheet]");
}

/** The new-card sheet, with a clear failure when the feature is absent. */
function sheetIn(document) {
  const sheet = sheetOf(document);
  assert.ok(sheet, "the new-card sheet is rendered");
  return sheet;
}

/** The two openers: the phone's round button and the desktop header button. */
function newCardButtons(document) {
  return {
    all: [...document.querySelectorAll("button[data-sb-newcard]")],
    fab: document.querySelector("button.sb-fab[data-sb-newcard]"),
    header: document.querySelector("button.sb-newcard-btn[data-sb-newcard]"),
  };
}

/** A label inside a subtree whose text mentions `text`. */
function labelSaying(root, text) {
  return [...root.querySelectorAll("label")].find((l) => l.textContent.includes(text)) || null;
}

/* ------------------------------------------------------------------ markup */

test("a full board carries the phone button, the header button and the sheet", () => {
  const { document } = dom(boardHtml(boardWithCards(), "en", { all: true }, PROJECTS));
  const { all, fab, header } = newCardButtons(document);

  assert.ok(fab, "the phone round button is rendered");
  assert.ok(header, "the desktop header button is rendered");
  assert.equal(all.length, 2, "exactly two openers: the phone button and the header button");
  for (const btn of [fab, header]) {
    assert.equal(btn.getAttribute("type"), "button");
    assert.equal(btn.getAttribute("aria-haspopup"), "dialog");
  }
  assert.equal(fab.getAttribute("aria-label"), EN("botboard.drawerNewCard"), "the round button is named for a screen reader");
  assert.equal(fab.textContent.trim(), "+");
  assert.equal(header.textContent.trim(), "+ " + EN("botboard.drawerNewCard"));

  const sheet = sheetIn(document);
  assert.ok(sheet.classList.contains("sb-sheet"), "it is one of the tab's sheets");
  assert.ok(sheet.classList.contains("sb-newcard"), "and the new-card one");
});

test("the empty board renders both buttons, the sheet and the client's hooks", () => {
  const { document } = dom(boardHtml(emptyBoard(), "en", { all: true }, PROJECTS));
  const root = document.querySelector("[data-sb-board]");
  assert.ok(root, "the empty board's root carries data-sb-board, so the client binds to it");
  const { fab, header } = newCardButtons(document);
  assert.ok(fab && root.contains(fab), "the phone button is inside the board");
  assert.ok(header && root.contains(header), "the header button too");
  assert.ok(root.contains(sheetIn(document)), "and the sheet");

  const status = root.querySelector("[data-sb-status]");
  assert.ok(status, "the status line exists on an empty board (a created card is announced there)");
  assert.equal(status.getAttribute("role"), "status");
  assert.equal(status.getAttribute("aria-live"), "polite");
  assert.ok(status.classList.contains("sb-status"));
});

test("the sheet's fields: title, description, autonomy, and More options", () => {
  const { document } = dom(boardHtml(boardWithCards(), "en", { all: true }, PROJECTS));
  const sheet = sheetIn(document);
  const form = sheet.querySelector("form");
  assert.ok(form, "the sheet holds a form");

  assert.ok(sheet.querySelector("h1,h2,h3,h4,h5,h6"), "the sheet has a heading");
  const heading = [...sheet.querySelectorAll("h1,h2,h3,h4,h5,h6")]
    .some((h) => h.textContent.includes(EN("botboard.drawerNewCard")));
  assert.ok(heading, "the heading is the New card title");

  const title = sheet.querySelector("[data-sb-nc-title]");
  assert.ok(title, "a title field");
  assert.equal(title.tagName.toLowerCase(), "input");
  assert.ok(title.hasAttribute("required"), "the title is required");
  assert.ok(labelSaying(form, EN("botboard.labelTitle")), "labelled Title");

  const desc = sheet.querySelector("[data-sb-nc-desc]");
  assert.ok(desc, "a description field");
  assert.equal(desc.tagName.toLowerCase(), "textarea");
  assert.equal(desc.getAttribute("rows"), "3");
  assert.ok(labelSaying(form, EN("botboard.labelDescription")), "labelled Description");

  const autonomy = sheet.querySelector("select[data-sb-nc-autonomy]");
  assert.ok(autonomy, "an autonomy select");
  assert.ok(labelSaying(form, EN("board.autonomy")), "labelled Autonomy");
  const options = [...autonomy.querySelectorAll("option")].map((o) => ({ value: o.getAttribute("value"), text: o.textContent.trim() }));
  assert.deepEqual(options, [
    { value: "gated", text: EN("board.autonomyGated") },
    { value: "auto", text: EN("board.autonomyAuto") },
  ]);
  assert.equal(autonomy.value, "gated", "gated is the default");

  const details = sheet.querySelector("details.sb-nc-more");
  assert.ok(details, "a More options disclosure");
  assert.equal(details.querySelector("summary").textContent.trim(), EN("shell.newCardMore"));
  for (const [attr, key] of [["data-sb-nc-due", "botboard.labelDueDate"], ["data-sb-nc-owner", "botboard.labelOwner"], ["data-sb-nc-tags", "botboard.labelTags"]]) {
    const field = details.querySelector(`[${attr}]`);
    assert.ok(field, attr + " lives in More options");
    assert.equal(field.tagName.toLowerCase(), "input");
    assert.ok(labelSaying(details, EN(key)), attr + " is labelled");
  }
  // Title, Description and Autonomy stay out of the disclosure.
  for (const sel of ["[data-sb-nc-title]", "[data-sb-nc-desc]", "[data-sb-nc-autonomy]"]) {
    assert.equal(details.querySelector(sel), null, sel + " is not inside More options");
  }

  const err = sheet.querySelector("[data-sb-nc-error]");
  assert.ok(err, "an error line");
  assert.equal(err.tagName.toLowerCase(), "p");
  assert.equal(err.getAttribute("role"), "alert");
  assert.ok(err.classList.contains("sb-nc-error"));

  const buttons = (sel) => sheet.querySelector(`button${sel}`);
  assert.equal(buttons("[data-sb-nc-save]").textContent.trim(), EN("botboard.btnCreateCard"));
  assert.equal(buttons("[data-sb-nc-save]").getAttribute("type"), "button");
  assert.equal(buttons("[data-sb-nc-cancel]").textContent.trim(), EN("common.cancel"));
  assert.equal(buttons("[data-sb-nc-cancel]").getAttribute("type"), "button");
  assert.equal(buttons("[data-sb-nc-close]").textContent.trim(), EN("common.close"));
  assert.equal(buttons("[data-sb-nc-close]").getAttribute("type"), "button");
});

test("the sheet has no bot, assignee or give-to field at all", () => {
  const { document } = dom(boardHtml(boardWithCards(), "en", { all: true }, PROJECTS));
  const html = sheetIn(document).outerHTML;
  assert.ok(!html.includes("data-sb-nc-bot"), "no bot field");
  assert.ok(!html.includes("assigned_bot"), "no assigned_bot field");
  // No attribute NAME and no attribute VALUE of the sheet mentions a bot.
  assert.doesNotMatch(html, /[\s"'<][a-zA-Z-]*bot[a-zA-Z-]*\s*=/i, "no attribute name in the sheet names a bot");
  assert.doesNotMatch(html, /="[^"]*bot[^"]*"/i, "no attribute value in the sheet names a bot");
  assert.doesNotMatch(html, /give\s+to/i, "no give-to control");
});

test("a project scope says where the card goes and sends no project select", () => {
  const { document } = dom(boardHtml(boardWithCards(), "en", { projectId: 1 }, PROJECTS));
  const sheet = sheetIn(document);
  const goes = sheet.querySelector("[data-sb-nc-goes]");
  assert.ok(goes, "the 'goes in' line is rendered");
  assert.equal(goes.tagName.toLowerCase(), "p");
  assert.ok(goes.classList.contains("sb-nc-goes"));
  assert.equal(goes.textContent.trim(), EN("shell.newCardGoesIn").replace("{project}", "Alpha"));
  assert.equal(sheet.querySelector("[data-sb-nc-project]"), null, "no project picker inside a project");
  assert.equal(sheet.querySelector("form").getAttribute("data-project-id"), "1", "the form carries the scope's project");
});

test("Everything and Unassigned offer a project picker, No project first and selected", () => {
  for (const scope of [{ all: true }, { unassigned: true }]) {
    const { document } = dom(boardHtml(boardWithCards(), "en", scope, PROJECTS));
    const sheet = sheetIn(document);
    assert.equal(sheet.querySelector("[data-sb-nc-goes]"), null, "no 'goes in' line outside a project scope");
    const select = sheet.querySelector("select[data-sb-nc-project]");
    assert.ok(select, "a project picker");
    assert.ok(labelSaying(sheet.querySelector("form"), EN("shell.newCardProject")), "labelled Project");
    const options = [...select.querySelectorAll("option")].map((o) => ({
      value: o.getAttribute("value"), text: o.textContent.trim(), selected: o.hasAttribute("selected"),
    }));
    assert.deepEqual(options, [
      { value: "", text: EN("shell.newCardUnassigned"), selected: true },
      { value: "1", text: "Alpha", selected: false },
      { value: "2", text: "Beta", selected: false },
    ]);
    assert.equal(sheet.querySelector("form").getAttribute("data-project-id"), null, "the form carries no project");
  }
});

test("a projectId that names no live project falls back to the picker", () => {
  const { document } = dom(boardHtml(boardWithCards(), "en", { projectId: 999 }, PROJECTS));
  const sheet = sheetIn(document);
  assert.equal(sheet.querySelector("[data-sb-nc-goes]"), null, "no 'goes in' line for a project the operator cannot pick");
  assert.ok(sheet.querySelector("select[data-sb-nc-project]"), "the picker instead");
});

test("Spanish: the button, the sheet and the scope line", () => {
  const { document } = dom(boardHtml(boardWithCards(), "es", { projectId: 1 }, PROJECTS));
  const { fab, header } = newCardButtons(document);
  assert.equal(fab.getAttribute("aria-label"), ES("botboard.drawerNewCard"));
  assert.equal(header.textContent.trim(), "+ " + ES("botboard.drawerNewCard"));
  const sheet = sheetIn(document);
  assert.equal(sheet.querySelector("[data-sb-nc-goes]").textContent.trim(), ES("shell.newCardGoesIn").replace("{project}", "Alpha"));
  assert.equal(sheet.querySelector("summary").textContent.trim(), ES("shell.newCardMore"));
  assert.equal(sheet.querySelector("button[data-sb-nc-save]").textContent.trim(), ES("botboard.btnCreateCard"));
  assert.equal(sheet.querySelector("button[data-sb-nc-cancel]").textContent.trim(), ES("common.cancel"));
  assert.equal(sheet.querySelector("button[data-sb-nc-close]").textContent.trim(), ES("common.close"));
  // The picker's own strings, in Spanish, on the widening scope.
  const all = dom(boardHtml(boardWithCards(), "es", { all: true }, PROJECTS)).document;
  const select = sheetIn(all).querySelector("select[data-sb-nc-project]");
  assert.equal(select.querySelector("option").textContent.trim(), ES("shell.newCardUnassigned"));
  assert.ok(labelSaying(sheetIn(all).querySelector("form"), ES("shell.newCardProject")));
});

test("the six new strings, word for word in both languages", () => {
  const table = [
    ["shell.newCardMore", "More options", "Más opciones"],
    ["shell.newCardProject", "Project", "Proyecto"],
    ["shell.newCardUnassigned", "No project", "Sin proyecto"],
    ["shell.newCardGoesIn", "Goes in {project}.", "Va en {project}."],
    ["shell.cardCreated", "Card created.", "Tarjeta creada."],
    ["shell.cardCreateFailed", "That card wasn't created. Try again.", "No se pudo crear la tarjeta. Inténtalo de nuevo."],
  ];
  for (const [key, en, es] of table) {
    assert.equal(t(key, "en"), en, key + " (en)");
    assert.equal(t(key, "es"), es, key + " (es)");
  }
});

test("a hostile project name is escaped in the picker and in the 'goes in' line", () => {
  const XSS = "<img src=x onerror=alert(1)>";
  const AMP = 'A & "B"';
  const projects = [
    { id: 7, slug: "xss", name: XSS },
    { id: 8, slug: "amp", name: AMP },
  ];

  const all = boardHtml(boardWithCards(), "en", { all: true }, projects);
  assert.ok(all.includes("&lt;img src=x onerror=alert(1)&gt;"), "the option text is escaped");
  assert.ok(!all.includes("<img src=x"), "never the raw tag");
  assert.ok(all.includes("A &amp; &quot;B&quot;"), "quotes and ampersands are escaped");
  assert.ok(!all.includes('>A & "B"<'), "never raw ampersand text");

  const one = boardHtml(boardWithCards(), "en", { projectId: 7 }, projects);
  assert.ok(one.includes("Goes in &lt;img src=x onerror=alert(1)&gt;."), "the 'goes in' line is escaped");
  assert.ok(!one.includes("<img src=x"), "never the raw tag");

  const other = boardHtml(boardWithCards(), "en", { projectId: 8 }, projects);
  assert.ok(other.includes("Goes in A &amp; &quot;B&quot;."), "the quote-bearing name is escaped");
  assert.ok(!other.includes('Goes in A & "B".'), "never raw");
});

test("the sheet's client messages ride on escaped data attributes", () => {
  const html = boardHtml(boardWithCards(), "en", { all: true }, PROJECTS);
  for (const [attr, key] of [
    ["data-msg-title-required", "botboard.jsTitleRequired"],
    ["data-msg-created", "shell.cardCreated"],
    ["data-msg-failed", "shell.cardCreateFailed"],
  ]) {
    assert.ok(html.includes(attr + '="' + escapeHtml(EN(key)) + '"'), attr + " is the escaped string");
  }
  const { document } = dom(html);
  const sheet = sheetIn(document);
  assert.equal(sheet.getAttribute("data-msg-title-required"), EN("botboard.jsTitleRequired"));
  assert.equal(sheet.getAttribute("data-msg-created"), EN("shell.cardCreated"));
  assert.equal(sheet.getAttribute("data-msg-failed"), EN("shell.cardCreateFailed"));
});

/* --------------------------------------------------------------------- css */

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/g;

/** Every rule whose selector contains `sel`: {selector, body}. */
function ruleBodies(css, sel) {
  const out = [];
  const re = new RegExp("([^{}]*" + sel.replace(REGEX_SPECIALS, "\\$&") + "[^{}]*)\\{([^}]*)\\}", "g");
  let m;
  while ((m = re.exec(css))) out.push({ selector: m[1].trim(), body: m[2] });
  return out;
}

/** The `{...}` block starting at the first `{` at or after `from`. */
function braceBlock(text, from) {
  const start = text.indexOf("{", from);
  if (start < 0) return "";
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return text.slice(start);
}

/** Everything outside any @media block. */
function withoutMedia(css) {
  let out = "";
  let i = 0;
  while (i < css.length) {
    const at = css.indexOf("@media", i);
    if (at < 0) { out += css.slice(i); break; }
    out += css.slice(i, at);
    const block = braceBlock(css, at);
    i = at + block.length;
  }
  return out;
}

test("the phone's round button is fixed, and the desktop shows the header button instead", () => {
  const css = boardCss();

  const fabRules = ruleBodies(css, ".sb-fab");
  assert.ok(fabRules.length, ".sb-fab has a rule");
  assert.ok(fabRules.some((r) => /position:\s*fixed/.test(r.body)), "the round button is fixed positioned");

  assert.ok(ruleBodies(css, ".sb-newcard-btn").length, ".sb-newcard-btn has a rule");
  assert.ok(css.includes("@media (min-width: 1024px)"), "the desktop media block exists");
  const desktop = braceBlock(css, css.indexOf("@media (min-width: 1024px)"));
  assert.ok(desktop.length > 2, "the desktop media block is read");
  assert.ok(desktop.includes(".sb-fab"), "the phone button is handled there");
  const fabInDesktop = ruleBodies(desktop, ".sb-fab");
  assert.ok(fabInDesktop.some((r) => /display:\s*none/.test(r.body)), ".sb-fab is hidden from 1024 px");

  const outside = withoutMedia(css);
  const headerOutside = ruleBodies(outside, ".sb-newcard-btn");
  assert.ok(headerOutside.some((r) => /display:\s*none/.test(r.body)), "the header button is hidden on the phone");
});

/* ------------------------------------------------------------------ client */

const CLIENT_SCRIPTS = [...boardClientJs().matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);

const jsonResponse = (status, body) => ({ ok: status < 400, status, json: () => Promise.resolve(body) });

/**
 * The page the handler would serve, with the emitted scripts run for real in a
 * vm: <dialog> gets the showModal/close/open it needs, fields get a writable
 * value, focus is recorded, and fetch is a stub that answers with what the
 * server would.
 */
function boot(html, { fetchImpl, href = "https://crow.test/dashboard/board" } = {}) {
  const { window: dom, document } = parseHTML(`<html><body>${html}</body></html>`);

  for (const dialog of document.querySelectorAll("dialog")) {
    Object.defineProperty(dialog, "open", {
      configurable: true,
      get: () => dialog.hasAttribute("open"),
      set: (on) => { if (on) dialog.setAttribute("open", ""); else dialog.removeAttribute("open"); },
    });
    dialog.showModal = function showModal() { this.setAttribute("open", ""); };
    dialog.close = function close() {
      if (!this.hasAttribute("open")) return;
      this.removeAttribute("open");
      this.dispatchEvent(new dom.Event("close"));
    };
  }

  // linkedom's fields expose `value` as a getter only (tests/mail-reader-client.test.js).
  for (const field of document.querySelectorAll("input, select, textarea")) {
    let current = String(field.value == null ? "" : field.value);
    Object.defineProperty(field, "value", {
      configurable: true,
      get: () => current,
      set: (next) => { current = String(next); },
    });
  }

  const focuses = [];
  for (const focusable of document.querySelectorAll("button, input, select, textarea")) {
    focusable.focus = () => { focuses.push(focusable); };
  }

  const calls = [];
  const visits = [];
  const reloads = [];
  const timers = [];
  const location = {
    href,
    reload: () => reloads.push("reload"),
    assign: (url) => visits.push(String(url)),
  };
  const windowStub = {
    document,
    location,
    Turbo: { visit: (url) => visits.push(String(url)) },
    matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
    addEventListener() {},
    removeEventListener() {},
    Event: dom.Event,
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearTimeout() {},
    requestAnimationFrame: (fn) => { timers.push({ fn, ms: 0 }); return timers.length; },
    cancelAnimationFrame() {},
  };
  const fetchStub = (url, init) => {
    const options = init || {};
    const call = {
      url: String(url),
      method: options.method == null ? "GET" : String(options.method),
      credentials: options.credentials,
      headers: options.headers || {},
      body: options.body == null ? null : JSON.parse(String(options.body)),
    };
    calls.push(call);
    const answer = fetchImpl ? fetchImpl(call) : jsonResponse(200, { ok: true, id: 1 });
    return answer && typeof answer.then === "function" ? answer : Promise.resolve(answer);
  };

  const ctx = vm.createContext({
    window: windowStub,
    document,
    location,
    console,
    fetch: fetchStub,
    setTimeout: windowStub.setTimeout,
    clearTimeout: windowStub.clearTimeout,
    requestAnimationFrame: windowStub.requestAnimationFrame,
    cancelAnimationFrame: windowStub.cancelAnimationFrame,
  });
  for (const script of CLIENT_SCRIPTS) vm.runInContext(script, ctx);

  const settle = async () => { for (let i = 0; i < 12; i += 1) await new Promise((resolve) => setImmediate(resolve)); };
  // The timers the page asked for, run once: a focus or a reload deferred to
  // the next frame is still a focus or a reload.
  const flush = () => { for (const timer of timers.splice(0)) timer.fn(); };
  const click = (node) => { node.dispatchEvent(new dom.Event("click", { bubbles: true, cancelable: true })); return node; };
  return { document, calls, visits, reloads, timers, focuses, settle, flush, click };
}

/** A board page for the client tests, with the sheet's scope chosen by `scope`. */
function page(scope = { all: true }, lang = "en") {
  return boardHtml(boardWithCards(), lang, scope, PROJECTS);
}

/** Click the phone's round button, the ordinary way in on a phone. */
function openSheet(rig) {
  const opener = rig.document.querySelector("button.sb-fab[data-sb-newcard]");
  rig.click(opener);
  return opener;
}

test("save with an empty title: no request, the sheet says the title is required and stays open", async () => {
  const rig = boot(page());
  const sheet = sheetIn(rig.document);
  openSheet(rig);
  assert.ok(sheet.hasAttribute("open"), "the sheet opens on the button");

  rig.click(rig.document.querySelector("[data-sb-nc-save]"));
  await rig.settle();

  assert.equal(rig.calls.length, 0, "nothing is sent");
  assert.equal(rig.document.querySelector("[data-sb-nc-error]").textContent, EN("botboard.jsTitleRequired"));
  assert.ok(sheet.hasAttribute("open"), "the sheet stays open");
});

test("a card in a project scope posts the exact body the API takes", async () => {
  const rig = boot(page({ projectId: 1 }));
  openSheet(rig);
  const doc = rig.document;
  doc.querySelector("[data-sb-nc-title]").value = "  Buy milk  ";
  rig.click(doc.querySelector("[data-sb-nc-save]"));
  await rig.settle();

  assert.equal(rig.calls.length, 1, "one request");
  const call = rig.calls[0];
  assert.equal(call.url, "/dashboard/bot-board-api/card");
  assert.equal(call.method, "POST");
  assert.equal(call.credentials, "same-origin");
  assert.equal(call.headers["Content-Type"], "application/json");
  assert.deepEqual(Object.keys(call.body).sort(), ["autonomy", "description", "due_date", "owner", "project_id", "tags", "title"], "exactly these keys");
  assert.deepEqual(call.body, {
    title: "Buy milk",
    description: null,
    due_date: null,
    owner: null,
    tags: null,
    project_id: 1,
    autonomy: "gated",
  }, "the title is trimmed, the blanks are null, the scope's project id is a number");
});

test("in Everything scope, No project sends project_id null and blanks stay null", async () => {
  const rig = boot(page({ all: true }));
  openSheet(rig);
  const doc = rig.document;
  doc.querySelector("[data-sb-nc-title]").value = "a card";
  doc.querySelector("[data-sb-nc-desc]").value = "a note";
  assert.equal(doc.querySelector("[data-sb-nc-project]").value, "", "No project is the default");
  rig.click(doc.querySelector("[data-sb-nc-save]"));
  await rig.settle();

  assert.equal(rig.calls.length, 1);
  assert.deepEqual(rig.calls[0].body, {
    title: "a card",
    description: "a note",
    due_date: null,
    owner: null,
    tags: null,
    project_id: null,
    autonomy: "gated",
  });
});

test("in Everything scope a chosen project is sent as a number, with the rest of the fields", async () => {
  const rig = boot(page({ all: true }));
  openSheet(rig);
  const doc = rig.document;
  doc.querySelector("[data-sb-nc-title]").value = "on beta";
  doc.querySelector("[data-sb-nc-desc]").value = "why";
  doc.querySelector("[data-sb-nc-due]").value = "2026-02-01";
  doc.querySelector("[data-sb-nc-owner]").value = "alex";
  doc.querySelector("[data-sb-nc-tags]").value = "one,two";
  doc.querySelector("[data-sb-nc-autonomy]").value = "auto";
  doc.querySelector("[data-sb-nc-project]").value = "2";
  rig.click(doc.querySelector("[data-sb-nc-save]"));
  await rig.settle();

  assert.equal(rig.calls.length, 1);
  assert.deepEqual(rig.calls[0].body, {
    title: "on beta",
    description: "why",
    due_date: "2026-02-01",
    owner: "alex",
    tags: "one,two",
    project_id: 2,
    autonomy: "auto",
  });
});

test("a refused create keeps the sheet open and shows the server's reason", async () => {
  const rig = boot(page(), { fetchImpl: () => jsonResponse(409, { ok: false, reason: "bot is working this card" }) });
  const sheet = sheetIn(rig.document);
  openSheet(rig);
  rig.document.querySelector("[data-sb-nc-title]").value = "held";
  rig.click(rig.document.querySelector("[data-sb-nc-save]"));
  await rig.settle();

  assert.equal(rig.document.querySelector("[data-sb-nc-error]").textContent, "bot is working this card");
  assert.ok(sheet.hasAttribute("open"), "still open");
  assert.equal(rig.visits.length + rig.reloads.length, 0, "nothing reloads");
});

test("a refusal that only carries `error` shows that; an empty body shows the generic failure", async () => {
  const withError = boot(page(), { fetchImpl: () => jsonResponse(400, { error: "title is required" }) });
  openSheet(withError);
  withError.document.querySelector("[data-sb-nc-title]").value = "x";
  withError.click(withError.document.querySelector("[data-sb-nc-save]"));
  await withError.settle();
  assert.equal(withError.document.querySelector("[data-sb-nc-error]").textContent, "title is required");

  const generic = boot(page(), { fetchImpl: () => jsonResponse(500, {}) });
  openSheet(generic);
  generic.document.querySelector("[data-sb-nc-title]").value = "x";
  generic.click(generic.document.querySelector("[data-sb-nc-save]"));
  await generic.settle();
  assert.equal(generic.document.querySelector("[data-sb-nc-error]").textContent, EN("shell.cardCreateFailed"));
});

test("a fetch that rejects shows the generic failure and keeps the sheet open", async () => {
  const rig = boot(page(), { fetchImpl: () => Promise.reject(new Error("offline")) });
  const sheet = sheetIn(rig.document);
  openSheet(rig);
  rig.document.querySelector("[data-sb-nc-title]").value = "x";
  rig.click(rig.document.querySelector("[data-sb-nc-save]"));
  await rig.settle();

  assert.equal(rig.document.querySelector("[data-sb-nc-error]").textContent, EN("shell.cardCreateFailed"));
  assert.ok(sheet.hasAttribute("open"), "still open");
});

test("a created card closes the sheet, says so in the status line and reloads the tab", async () => {
  const rig = boot(page(), { fetchImpl: () => jsonResponse(200, { ok: true, id: 77 }) });
  const sheet = sheetIn(rig.document);
  openSheet(rig);
  rig.document.querySelector("[data-sb-nc-title]").value = "make the coffee";
  rig.click(rig.document.querySelector("[data-sb-nc-save]"));
  await rig.settle();
  rig.flush();
  await rig.settle();

  assert.ok(!sheet.hasAttribute("open"), "the sheet closes");
  assert.equal(rig.document.querySelector("[data-sb-status]").textContent, EN("shell.cardCreated"), "the status line says the card was created");
  assert.ok(rig.visits.length + rig.reloads.length > 0, "the tab is reloaded (Turbo visit or location.reload)");
});

test("closing the sheet gives focus back to the button that opened it", async () => {
  const rig = boot(page());
  const sheet = sheetIn(rig.document);
  const opener = openSheet(rig);
  assert.ok(sheet.hasAttribute("open"));

  rig.click(rig.document.querySelector("[data-sb-nc-cancel]"));
  await rig.settle();
  rig.flush();
  await rig.settle();

  assert.ok(!sheet.hasAttribute("open"), "cancel closes the sheet");
  assert.equal(rig.focuses[rig.focuses.length - 1], opener, "focus is back on the opener");
});