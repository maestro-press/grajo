/**
 * The Reports list and report page client (Crow Recurring Reports, task 9b).
 *
 * The pages are server-rendered; this script only wires the clicks and the one form to the owner API
 * (routes/reports-api.js), which is where every decision is made:
 *
 *   data-rp-action="pause" | "resume" | "run-now"   POST /dashboard/api/reports/<id>/<action>
 *   data-rp-action="preview"                        POST /dashboard/api/reports/<id>/preview (202)
 *   data-rp-action="go-live"                        POST .../go-live with the usable preview's run id and
 *                                                   the sender account id the button carries
 *                                                   (data-rp-sender), when the page carries a preview,
 *                                                   else .../preview first
 *   data-rp-action="send-rest" + data-rp-run         POST .../runs/<runId>/send-rest (201)
 *   data-rp-action="approve" | "refuse" | "revoke"
 *                    + data-rp-recipient            POST .../recipients/<rid>/<action>
 *   data-rp-action="revoke-links" + data-rp-recipient + data-rp-name
 *                                                   POST .../recipients/<rid>/link/revoke, after the
 *                                                   owner confirms the sentence naming that person
 *   the schedule form (data-rp-schedule)             PUT  .../schedule {cron, tz}
 *   the settings form (data-rp-settings)             PUT  .../settings {settings}
 *
 * Every request sends the dashboard's server-bound CSRF token in X-Crow-Csrf (window.crowCsrf, the
 * <meta> tag the layout writes), never a cookie read. A write that succeeds re-renders the page from the
 * server, so the chips and the next run show what was stored. A refusal shows the API's own message
 * sentence as text, or the page's generic line; a 409 go_live_needed shows the line that points at the
 * report page, which is where the preview and go live are, and every other refusal with a message (a
 * 409 conflict included) shows that message. One exception: a settings save refused because the account
 * cannot send writes its line in the form, above its Save; a go-live refused for that reason is not the
 * form's, so it shows the API's sentence like any other write.
 *
 * The script is emitted as a <script> string, so it is written from single-quoted source lines and holds
 * no backtick and no dollar-brace sequence anywhere. Every value it writes goes in as textContent or as
 * a JSON body; nothing from the page is ever turned into markup.
 *
 * What the page needs to translate is delivered in the inert JSON block (projectReportsDataScript), from
 * the same i18n table the server renders with, so the client never carries a UI sentence of its own.
 */
import { t } from "../../shared/i18n.js";

/** The copy the client itself can show: the preview line, the revoke-links pair, the settings save's
 *  answers and the failure lines. */
const CLIENT_KEYS = [
  "projectReports.previewStarted",
  "projectReports.recipients.revokeLinksConfirm",
  "projectReports.recipients.linksRevoked",
  "projectReports.settings.saved",
  "projectReports.settings.savedPaused",
  "projectReports.settings.windowRange",
  "projectReports.settings.nothingChanged",
  "projectReports.settings.senderNotReady",
  "projectReports.error.generic",
  "projectReports.error.goLiveNeeded",
];

/** What the client needs from the page, exactly as project-services carries it in its own JSON block. */
export function projectReportsData({ project, lang = "en" } = {}) {
  const strings = {};
  for (const key of CLIENT_KEYS) strings[key] = t(key, lang);
  return {
    project: { slug: project?.slug || "" },
    lang,
    strings,
  };
}

/** The data as an inert JSON block, safe inside HTML (no raw "<", ">", "&" or line separators). */
export function projectReportsDataScript(view, lang = "en") {
  const json = JSON.stringify(projectReportsData({ ...view, lang }))
    .replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  return '<script type="application/json" data-rp-data>' + json + '</script>';
}

/**
 * The client source, one line per entry. Written this way so the file holds no backtick at all: the
 * script is joined and handed back inside its own element.
 */
const CLIENT_LINES = [
  '(function () {',
  '  var root = document.querySelector("[data-rp]");',
  '  if (!root || root.getAttribute("data-rp-bound")) return;',
  '  root.setAttribute("data-rp-bound", "1");',
  '  var API = "/dashboard/api/reports/";',
  '  var HAS = Object.prototype.hasOwnProperty;',
  '',
  '  var DATA = null;',
  '  try {',
  '    var dn = document.querySelector("script[data-rp-data]");',
  '    DATA = dn ? JSON.parse(dn.textContent || "null") : null;',
  '  } catch (e) { DATA = null; }',
  '  var S = (DATA && DATA.strings) || {};',
  '  function T(k) { return HAS.call(S, k) ? S[k] : k; }',
  '',
  '  // The server-bound CSRF token (window.crowCsrf, from the page meta tag). Never a cookie.',
  '  function csrf() {',
  '    try { return window.crowCsrf ? window.crowCsrf() : ""; } catch (e) { return ""; }',
  '  }',
  '  function reload() { location.reload(); }',
  '',
  '  function say(el, text, isError) {',
  '    if (!el) return;',
  '    el.className = isError ? "rp-status rp-status--error" : "rp-status";',
  '    el.textContent = text || "";',
  '  }',
  '',
  '  function status(text, isError) {',
  '    say(root.querySelector("[data-rp-status]"), text, isError);',
  '  }',
  '',
  '  // A settings save re-renders the page, so the answer it leaves is kept for one reload and read once.',
  '  // The key names the report, so the answer only ever appears on the page that saved it.',
  '  var MSG_KEY = "rp-settings-msg:" + (root.getAttribute("data-rp-report-id") || "");',
  '  function remember(msg) {',
  '    try { sessionStorage.setItem(MSG_KEY, msg); } catch (e) { return; }',
  '  }',
  '  function takeMessage() {',
  '    try {',
  '      var msg = sessionStorage.getItem(MSG_KEY);',
  '      if (msg === null) return "";',
  '      sessionStorage.removeItem(MSG_KEY);',
  '      return msg;',
  '    } catch (e) { return ""; }',
  '  }',
  '  var left = takeMessage();',
  '  if (left) say(root.querySelector("[data-rp-settings-result]"), left);',
  '',
  '  function api(reportId, rest) {',
  '    return API + encodeURIComponent(reportId) + rest;',
  '  }',
  '',
  '  function request(url, method, body) {',
  '    return fetch(url, {',
  '      method: method,',
  '      credentials: "same-origin",',
  '      headers: { "Content-Type": "application/json", "X-Crow-Csrf": csrf() },',
  '      body: JSON.stringify(body || {})',
  '    }).then(function (r) {',
  '      return r.json().then(function (j) { return { status: r.status, j: j }; }, function () { return { status: r.status, j: null }; });',
  '    }, function () { return { status: 0, j: null }; });',
  '  }',
  '',
  '  // A refusal: the sender a settings save could not use, the go-live line, the API sentence, else the',
  '  // generic line. Only the settings save has its own line for an account that cannot send (above its',
  '  // Save): a go-live refused for that same reason shows the API sentence, like every other write.',
  '  function fail(res, fromSettings) {',
  '    var j = res.j;',
  '    if (fromSettings && j && j.error === "sender_not_ready") {',
  '      var copy = T("projectReports.settings.senderNotReady");',
  '      var note = root.querySelector("[data-rp-settings-note]");',
  '      if (note) say(note, copy, true);',
  '      else status(copy, true);',
  '      return;',
  '    }',
  '    if (res.status === 409 && j && j.error === "go_live_needed") {',
  '      status(T("projectReports.error.goLiveNeeded"), true);',
  '      return;',
  '    }',
  '    if (j && typeof j.message === "string" && j.message) { status(j.message, true); return; }',
  '    status(T("projectReports.error.generic"), true);',
  '  }',
  '',
  '  function busy(btn, on) {',
  '    if (!btn || !btn.setAttribute) return;',
  '    if (on) btn.setAttribute("disabled", "");',
  '    else btn.removeAttribute("disabled");',
  '  }',
  '',
  '  // A write that lands re-renders the page; a refusal keeps it and says why. Only the settings save',
  '  // passes fromSettings, because its answer has a line of its own in the form.',
  '  function write(btn, reportId, rest, method, body, done, fromSettings) {',
  '    busy(btn, true);',
  '    status("");',
  '    request(api(reportId, rest), method, body).then(function (res) {',
  '      busy(btn, false);',
  '      if (res.status >= 200 && res.status < 400) {',
  '        if (done) done(res);',
  '        return;',
  '      }',
  '      fail(res, fromSettings);',
  '    }, function () {',
  '      busy(btn, false);',
  '      status(T("projectReports.error.generic"), true);',
  '    });',
  '  }',
  '',
  '  function preview(btn, reportId) {',
  '    write(btn, reportId, "/preview", "POST", {}, function () {',
  '      status(T("projectReports.previewStarted"));',
  '    });',
  '  }',
  '',
  '  function goLive(btn, reportId) {',
  '    var previewRunId = root.getAttribute("data-rp-preview") || "";',
  '    if (!previewRunId) { preview(btn, reportId); return; }',
  '    var expectedSenderAccountId = btn.getAttribute("data-rp-sender");',
  '    if (expectedSenderAccountId === null) expectedSenderAccountId = "";',
  '    write(btn, reportId, "/go-live", "POST", {',
  '      previewRunId: previewRunId,',
  '      expectedSenderAccountId: expectedSenderAccountId',
  '    }, reload);',
  '  }',
  '',
  '  function sendRest(btn, reportId, runId) {',
  '    if (!runId) return;',
  '    write(btn, reportId, "/runs/" + encodeURIComponent(runId) + "/send-rest", "POST", {}, reload);',
  '  }',
  '',
  '  function decide(btn, reportId, action, recipientId) {',
  '    if (!recipientId) return;',
  '    write(btn, reportId, "/recipients/" + encodeURIComponent(recipientId) + "/" + action, "POST", {}, reload);',
  '  }',
  '',
  '  // Revoke links names the person the page showed (the display name, else the address) and asks first:',
  '  // the links already in a mail stop working, and the next report sends new ones. A yes shows the line',
  '  // and re-renders the page, like every other decision.',
  '  function revokeLinks(btn, reportId, recipientId) {',
  '    if (!recipientId) return;',
  '    var name = btn.getAttribute("data-rp-name") || "";',
  '    var ask = T("projectReports.recipients.revokeLinksConfirm").split("{name}").join(name);',
  '    if (!window.confirm(ask)) return;',
  '    write(btn, reportId, "/recipients/" + encodeURIComponent(recipientId) + "/link/revoke", "POST", {}, function () {',
  '      status(T("projectReports.recipients.linksRevoked"));',
  '      reload();',
  '    });',
  '  }',
  '',
  '  function saveSchedule(form) {',
  '    var reportId = form.getAttribute("data-rp-report") || "";',
  '    if (!reportId) return;',
  '    var cron = form.querySelector("[data-rp-cron]");',
  '    var tz = form.querySelector("[data-rp-tz]");',
  '    var btn = form.querySelector("button[type=submit]");',
  '    status("");',
  '    busy(btn, true);',
  '    request(api(reportId, "/schedule"), "PUT", {',
  '      cron: cron ? cron.value.trim() : "",',
  '      tz: tz ? tz.value.trim() : ""',
  '    }).then(function (res) {',
  '      busy(btn, false);',
  '      if (res.status >= 200 && res.status < 400) { reload(); return; }',
  '      fail(res);',
  '    }, function () {',
  '      busy(btn, false);',
  '      status(T("projectReports.error.generic"), true);',
  '    });',
  '  }',
  '',
  '  // The settings form: only the fields whose value moved from the one the page rendered, one PUT, then',
  '  // the answer is kept for the reload the page does next. A bad number or no change sends nothing.',
  '  function saveSettings(form) {',
  '    var reportId = form.getAttribute("data-rp-report") || "";',
  '    if (!reportId) return;',
  '    var btn = form.querySelector("button[type=submit]");',
  '    var windowLine = form.querySelector("[data-rp-window-error]");',
  '    var noteLine = form.querySelector("[data-rp-settings-note]");',
  '    var resultLine = form.querySelector("[data-rp-settings-result]");',
  '    say(windowLine, "", true);',
  '    say(noteLine, "", true);',
  '    say(resultLine, "");',
  '    status("");',
  '    var patch = {};',
  '    var count = 0;',
  '    var fields = form.querySelectorAll("[data-rp-setting]");',
  '    for (var i = 0; i < fields.length; i++) {',
  '      var field = fields[i];',
  '      var key = field.getAttribute("data-rp-setting") || "";',
  '      var current = field.getAttribute("data-rp-current");',
  '      if (current === null) current = "";',
  '      var value = field.value == null ? "" : String(field.value);',
  '      if (!key || value === current) continue;',
  '      if (key === "comment_window_runs") {',
  '        var runs = value.trim();',
  '        if (!/^[0-9]+$/.test(runs) || Number(runs) < 1 || Number(runs) > 50) {',
  '          say(windowLine, T("projectReports.settings.windowRange"), true);',
  '          return;',
  '        }',
  '        patch[key] = Number(runs);',
  '        count++;',
  '        continue;',
  '      }',
  '      if (key === "ai_commentary") { patch[key] = value === "1"; count++; continue; }',
  '      if (key === "sender_account_id") {',
  '        if (value === "") continue;',
  '      }',
  '      patch[key] = value;',
  '      count++;',
  '    }',
  '    if (!count) {',
  '      say(resultLine, T("projectReports.settings.nothingChanged"));',
  '      return;',
  '    }',
  '    var wasLive = form.getAttribute("data-rp-live") === "1";',
  '    write(btn, reportId, "/settings", "PUT", { settings: patch }, function (res) {',
  '      var report = res && res.j && res.j.report ? res.j.report : null;',
  '      var paused = wasLive && report && report.status === "paused";',
  '      remember(T(paused ? "projectReports.settings.savedPaused" : "projectReports.settings.saved"));',
  '      reload();',
  '    }, true);',
  '  }',
  '',
  '  root.addEventListener("click", function (e) {',
  '    var btn = e.target && e.target.closest ? e.target.closest("[data-rp-action]") : null;',
  '    if (!btn || btn.disabled) return;',
  '    var action = btn.getAttribute("data-rp-action") || "";',
  '    var reportId = btn.getAttribute("data-rp-report") || "";',
  '    if (!reportId) return;',
  '    if (action === "pause" || action === "resume" || action === "run-now") {',
  '      write(btn, reportId, "/" + action, "POST", {}, reload);',
  '      return;',
  '    }',
  '    if (action === "preview") { preview(btn, reportId); return; }',
  '    if (action === "go-live") { goLive(btn, reportId); return; }',
  '    if (action === "send-rest") { sendRest(btn, reportId, btn.getAttribute("data-rp-run") || ""); return; }',
  '    if (action === "revoke-links") { revokeLinks(btn, reportId, btn.getAttribute("data-rp-recipient") || ""); return; }',
  '    if (action === "approve" || action === "refuse" || action === "revoke") {',
  '      decide(btn, reportId, action, btn.getAttribute("data-rp-recipient") || "");',
  '    }',
  '  });',
  '',
  '  root.addEventListener("submit", function (e) {',
  '    var form = e.target;',
  '    if (!form || !form.hasAttribute) return;',
  '    if (form.hasAttribute("data-rp-settings")) { e.preventDefault(); saveSettings(form); return; }',
  '    if (!form.hasAttribute("data-rp-schedule")) return;',
  '    e.preventDefault();',
  '    saveSchedule(form);',
  '  });',
  '',
  '  // Turbo keeps a copy of the page for Back: the bound flag never goes into it, so a restored snapshot',
  '  // binds again.',
  '  document.addEventListener("turbo:before-cache", function uncache() {',
  '    document.removeEventListener("turbo:before-cache", uncache);',
  '    root.removeAttribute("data-rp-bound");',
  '  });',
  '})();',
];

/** The client JS, in its own element. No backtick anywhere in the script it carries. */
export function projectReportsClientJs() {
  return '<script>\n' + CLIENT_LINES.join("\n") + '\n</script>';
}