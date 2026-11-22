// The shell's avatar sheet ends in a Log out row. With a CSRF token in hand it
// is a POST form to /dashboard/logout (a logout must not be a state-changing
// GET); without one it falls back to the plain link to the GET confirm page,
// which changes nothing on its own. A full shell renderLayout must hand its
// token down to the sheet.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "shell-avatar-logout-"));
process.env.CROW_HOME = dir; // no installed.json, no flags: a plain sheet

let shellAvatarSheet, renderLayout;
before(async () => {
  ({ shellAvatarSheet } = await import("../servers/gateway/dashboard/shell/chrome.js"));
  ({ renderLayout } = await import("../servers/gateway/dashboard/shared/layout.js"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

/** The rendered avatar dialog, from <dialog> to </dialog>. */
function sheet(opts = {}) {
  const html = shellAvatarSheet({ lang: "en", ...opts });
  const m = html.match(/<dialog id="shell-avatar"[\s\S]*?<\/dialog>/);
  assert.ok(m, "the avatar sheet rendered");
  return m[0];
}

/** Everything after `piece` — what follows the sheet's last row. */
const tailAfter = (html, piece) => html.slice(html.indexOf(piece) + piece.length);
const closesTheSheet = (rest) => /^\s*<\/div>\s*<\/dialog>\s*$/.test(rest);

const logoutForm = (html) => {
  const m = html.match(/<form\b[^>]*action="\/dashboard\/logout"[^>]*>[\s\S]*?<\/form>/);
  assert.ok(m, "a form posting to /dashboard/logout");
  return m[0];
};

const logoutLink = (html) => {
  const m = html.match(/<a\b[^>]*href="\/dashboard\/logout"[^>]*>[\s\S]*?<\/a>/);
  assert.ok(m, "a link to /dashboard/logout");
  return m[0];
};

test("the last row is the logout POST form, carrying the token (en)", () => {
  const html = sheet({ csrf: "tok123" });
  const form = logoutForm(html);
  assert.match(form, /method="post"/i);
  assert.match(form, /data-turbo="false"/);
  assert.match(form, /class="shell-mode-form"/);
  assert.match(form, /<input type="hidden" name="_csrf" value="tok123">/);
  assert.match(form, /class="shell-sheet-link shell-mode-btn"[^>]*>Logout<\/button>/);
  assert.ok(closesTheSheet(tailAfter(html, form)), "nothing follows the logout form but the closing tags");
});

test("the last row is the logout POST form, labelled in Spanish", () => {
  const html = sheet({ lang: "es", csrf: "tok123" });
  const form = logoutForm(html);
  assert.match(form, /class="shell-sheet-link shell-mode-btn"[^>]*>Cerrar sesión<\/button>/);
  assert.ok(closesTheSheet(tailAfter(html, form)), "the Spanish form is the last row too");
});

test("the token is HTML-escaped", () => {
  const html = sheet({ csrf: '<x> & "y"' });
  assert.ok(html.includes('value="&lt;x&gt; &amp; &quot;y&quot;"'), "the token goes through escapeHtml");
  assert.ok(!html.includes("<x>"), "no raw markup from a token");
});

test("without a token the sheet falls back to the GET confirm-page link", () => {
  for (const csrf of [undefined, ""]) {
    const html = sheet({ csrf });
    const link = logoutLink(html);
    assert.match(link, /class="shell-sheet-link"/);
    assert.match(link, /data-turbo="false"/);
    assert.match(link, />Logout<\/a>/);
    assert.ok(closesTheSheet(tailAfter(html, link)), "the link is the last row");
    assert.ok(!html.includes('action="/dashboard/logout"'), "no logout POST form without a token");
  }
});

test("the classic-mode switch and the close button stay above the logout row", () => {
  const html = sheet({ csrf: "tok123" });
  assert.match(html, /<button\b[^>]*class="shell-sheet-close"[^>]*>/, "the close button is still there");
  const mode = html.indexOf('action="/dashboard/mode"');
  const logout = html.indexOf('action="/dashboard/logout"');
  assert.ok(mode > 0, "the Use classic form is still there");
  assert.ok(html.includes('name="mode" value="classic"'), "it still posts mode=classic");
  assert.ok(logout > mode, "logout comes after the classic switch");
});

test("a full shell page carries its csrf token into the avatar sheet", () => {
  const html = renderLayout({
    title: "Board",
    content: "<p>hello</p>",
    activePanel: "board",
    panels: [{ id: "board", name: "Board", icon: "board", route: "/dashboard/board", navOrder: 1 }],
    lang: "en",
    variant: "shell",
    csrf: "tok123",
    shell: { scope: { all: true }, projects: [], tab: "board", getPanel: () => null },
  });
  const dialog = html.match(/<dialog id="shell-avatar"[\s\S]*?<\/dialog>/);
  assert.ok(dialog, "the shell page renders the avatar dialog");
  const form = logoutForm(dialog[0]);
  assert.match(form, /<input type="hidden" name="_csrf" value="tok123">/);
  assert.ok(closesTheSheet(tailAfter(dialog[0], form)), "the form is the dialog's last row");
});