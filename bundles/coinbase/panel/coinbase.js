/**
 * The Trading panel — the page the owner opens at /dashboard/coinbase.
 *
 * The handler renders a shell and nothing else: it reads no secret, makes no
 * engine call and answers without the database. Everything the page shows comes
 * from `GET /api/coinbase/panel`, which the small script below asks for every
 * 8 seconds and draws in plain words: whether Crow is connected, what a bot is
 * worth beside simply holding the starting mix, which AI proposals are waiting
 * for a yes, what is left of each limit today, which orders are resting on each
 * book, and whether trading is stopped. The products the new-bot form offers
 * come from the same answer (the engine's own list), never from this file.
 *
 * The one thing the page must never get wrong is the kill switch: it sits at the
 * top, it is always there, it asks for one confirmation and it never asks for a
 * code. "Resume trading" (which clears a halt) does ask for one, because it is
 * the button that lets real money move again.
 *
 * ## Why this file carries no relative imports
 *
 * A bundle's panel is loaded twice: from its own bundle directory in the
 * checkout, and as `<crow-home>/panels/coinbase.js`, a single-file copy beside
 * the gateway. A relative `import "./connect.js"` would resolve to
 * `<crow-home>/panels/connect.js` in the installed case, which is not there
 * (docs/developers/bundles.md), so the Connect steps are loaded BY PATH from the
 * bundle directory — this instance's installed copy first, then the app root's.
 * No app module is needed here at all, and no module is imported that could
 * reach the keychain, the identity or the engine.
 *
 * ## What the browser is allowed to see
 *
 * Only the last four characters of the key and of the portfolio name, never the
 * key name, the private key, the approval secret, the engine token or the
 * install token. Engine refusals arrive as `{ok:false, code, message}` and the
 * page shows the message, never the machine code. Nothing from a query string
 * is pasted into markup or into the script: the one value that comes from the
 * address (`?preview=<id>`) is escaped into an attribute here and read back by
 * the script with `getAttribute`.
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/** The bundle directory this panel's other files are loaded from. */
function bundleDir() {
  const home = process.env.CROW_HOME || join(homedir(), ".crow");
  const installed = join(home, "bundles", "coinbase");
  if (existsSync(join(installed, "panel", "connect.js"))) return installed;
  return join(process.env.CROW_APP_ROOT || join(homedir(), "crow"), "bundles", "coinbase");
}

/** Import a file of this bundle by its path inside it, from whichever copy has it. */
const bundleImport = (rel) => import(pathToFileURL(join(bundleDir(), rel)).href);

/** Escape a value for HTML text or a double-quoted attribute. */
function esc(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** The sentence the panel shows when two-factor sign-in is still off. */
const TWO_FACTOR_MESSAGE = "Turn on two-factor sign-in first (Settings \u2192 Security)";

/**
 * The words the page uses. One object, serialised into the script once, with
 * every `<` escaped so no string can close the element it sits in.
 */
const STRINGS = {
  // state
  notConnected: "Not connected yet. Connect your Coinbase key below.",
  needsReconnect: "Crow lost its link to the trading engine. Press Connect again.",
  disconnectUnfinished: "Disconnect didn't finish \u2014 press Disconnect again",
  engineDown: "Trading engine is not responding.",
  halted: "Stopped. Every Crow order is being cancelled and every bot is stopped. Press Resume trading when you are ready.",
  haltedBook: "Trading on this book is stopped until you press Resume trading.",
  pending: "Crow is waiting for the trading engine to confirm your key.",
  twoFactor: TWO_FACTOR_MESSAGE,
  // kill and resume
  kill: "KILL SWITCH",
  killArmed: "Press the kill switch again to confirm.",
  resume: "Resume trading",
  // connect
  connected: "Connected",
  code: "2FA code",
  noProjects: "No projects yet. Create one first.",
  portfolio: "Portfolio",
  key: "Key",
  // previews
  approve: "Approve",
  reject: "Not now",
  nothingWaiting: "Nothing is waiting for you.",
  timeLeft: "Time left",
  expired: "This proposal expired. Ask again.",
  // bots
  noBots: "No bots yet. Create one below.",
  noProducts: "No products are set up yet.",
  pause: "Pause",
  stop: "Stop",
  goLive: "Go live",
  backToPractice: "Back to practice",
  goLiveConfirm: "I understand this bot will trade with real money.",
  turnLive: "Turn on live trading",
  cancel: "Cancel",
  resumeBot: "Resume",
  needsAttention: "needs attention",
  worth: "Worth",
  ahead: "That is ahead of simply holding your starting mix by",
  behind: "That is behind simply holding your starting mix by",
  profit: "Profit taken so far",
  fees: "Fees paid",
  recenter: "Move the middle price",
  newCenter: "New middle price",
  rebalance: "Rebalance",
  grid: "Grid",
  statusRunning: "running",
  statusPaused: "paused",
  statusStopped: "stopped",
  startMoney: "Starting money (USDC)",
  startCoin: "Starting coin amount (optional)",
  startCoinHint: "Leave it blank to start with 0.",
  badCoin: "That starting coin amount is not a number Crow can use. Type an amount like 0.25, or leave it blank.",
  // open orders
  noOrders: "No open orders.",
  // alerts, fills, limits
  noAlerts: "No alerts.",
  noFills: "No fills yet.",
  when: "When",
  bot: "Bot",
  product: "Product",
  side: "Side",
  price: "Price",
  size: "Size",
  buy: "Buy",
  sell: "Sell",
  ceiling: "ceiling",
  usedToday: "used today",
  noLimits: "No limits were read from the engine.",
  otherLimit: "Another limit",
  drawdown: "Down from its best",
  nothingYet: "nothing yet",
  // settings
  ceilingOff: "Live trading is switched off on this computer in the add-on settings. Nothing here can turn it on.",
  done: "Saved.",
  // helpers
  failed: "Crow could not do that. Try again.",
};

/** The plain label of each cap the engine knows, by the variable that sets it. */
const CAP_LABELS = {
  CROW_COINBASE_DAILY_NOTIONAL_USD: "Most Crow may spend in a day",
  CROW_COINBASE_ORDERS_PER_HOUR: "Most orders an hour",
  CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT: "Stop trading after this much fall from the top",
  CROW_COINBASE_BOT_MAX_ORDER_USD: "Largest single order from a bot",
  CROW_COINBASE_MAX_BOT_CAPITAL_USD: "Most starting money for a new bot",
  CROW_COINBASE_AI_MAX_ORDER_USD: "Largest single order from the AI",
  CROW_COINBASE_AI_DAILY_NOTIONAL_USD: "Most the AI may spend in a day",
  CROW_COINBASE_AI_ORDERS_PER_HOUR: "Most AI orders an hour",
  CROW_COINBASE_AI_CAPITAL_USD: "Most money the AI may manage",
};

/** Which `used_today` field shows how much of a cap one book has spent. */
const CAP_USED = {
  CROW_COINBASE_DAILY_NOTIONAL_USD: "daily_notional_usd",
  CROW_COINBASE_ORDERS_PER_HOUR: "orders_last_hour",
  CROW_COINBASE_AI_DAILY_NOTIONAL_USD: "ai_daily_notional_usd",
  CROW_COINBASE_AI_ORDERS_PER_HOUR: "ai_orders_last_hour",
};

/** The page's own look. Scoped under `.cb` so nothing reaches the dashboard around it. */
const STYLES = `
  .cb { display: flex; flex-direction: column; gap: 14px; }
  .cb h2 { margin: 18px 0 0; font-size: 15px; }
  .cb p { margin: 0; }
  .cb-hint { font-size: 12px; line-height: 1.5; color: var(--crow-text-muted); }
  .cb-say {
    margin: 0; padding: 10px 12px; border-radius: 8px; font-size: 13px; line-height: 1.5;
    border: 1px solid var(--crow-border); background: var(--crow-bg-elevated);
  }
  .cb-say.cb-bad { border-color: var(--crow-error); }
  .cb-banner {
    margin: 0; padding: 10px 12px; border-radius: 8px; font-size: 13px; line-height: 1.5;
    border: 1px solid var(--crow-border); background: var(--crow-bg-elevated);
  }
  .cb-banner.cb-alarm { border-color: var(--crow-error); }
  .cb-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
  .cb-kill {
    min-height: 52px; padding: 0 22px; border-radius: 10px; border: 2px solid var(--crow-error);
    background: var(--crow-error); color: #fff; font: inherit; font-size: 15px; font-weight: 700;
    letter-spacing: 0.04em; cursor: pointer;
  }
  .cb-kill.cb-armed { background: transparent; color: var(--crow-error); }
  .cb-card {
    display: flex; flex-direction: column; gap: 8px; padding: 12px;
    border: 1px solid var(--crow-border); border-radius: 10px; background: var(--crow-bg-elevated);
  }
  .cb-card.cb-focus { box-shadow: inset 0 0 0 2px var(--crow-accent); }
  .cb-card-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .cb-badge {
    font-size: 11px; font-weight: 700; letter-spacing: 0.04em; padding: 2px 7px;
    border-radius: 6px; border: 1px solid var(--crow-border); color: var(--crow-text-secondary);
  }
  .cb-badge.cb-practice { border-color: var(--crow-border); }
  .cb-badge.cb-live { border-color: var(--crow-error); color: var(--crow-error); }
  .cb-bot { display: flex; flex-direction: column; gap: 6px; padding: 10px 12px;
    border: 1px solid var(--crow-border); border-radius: 10px; background: var(--crow-bg-elevated); }
  .cb-bot-note { font-size: 12px; line-height: 1.5; color: var(--crow-text-secondary); }
  .cb-bot-acts { display: flex; flex-wrap: wrap; gap: 8px; }
  .cb-bot-form { display: flex; flex-direction: column; gap: 6px; padding-top: 6px; }
  .cb-bot-form[hidden] { display: none; }
  .cb-orders { display: flex; flex-direction: column; gap: 10px; }
  .cb-summary { font-size: 14px; line-height: 1.5; }
  .cb-lines { margin: 0; padding-left: 18px; font-size: 12px; line-height: 1.5; color: var(--crow-text-secondary); }
  .cb-field { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; }
  .cb-field input, .cb input, .cb select {
    min-height: 40px; padding: 0 8px; border-radius: 8px; font: inherit; font-size: 13px;
    border: 1px solid var(--crow-border); background: var(--crow-bg-deep); color: var(--crow-text-primary);
  }
  .cb button {
    min-height: 40px; padding: 0 14px; border-radius: 8px; font: inherit; font-size: 13px;
    border: 1px solid var(--crow-border); background: var(--crow-bg-elevated); color: var(--crow-text-primary);
    cursor: pointer;
  }
  .cb button[hidden], .cb [hidden] { display: none; }
  .cb-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .cb-table th, .cb-table td { padding: 4px 8px; text-align: left; border-bottom: 1px solid var(--crow-border); }
  .cb-table th { color: var(--crow-text-muted); font-weight: 600; }
  .cb-list { margin: 0; padding-left: 18px; font-size: 13px; line-height: 1.6; }
  .cb-steps { font-size: 13px; line-height: 1.6; }
  .cb-note-readonly { font-size: 12px; line-height: 1.5; color: var(--crow-text-muted); }
`;

/** The page. Static markup plus the one escaped query value; the script fills the rest. */
function renderContent({ steps, focus, lang }) {
  return `
<section class="cb" id="cb-panel" data-lang="${esc(lang)}">
  <style>${STYLES}</style>
  <div id="cb-focus" data-preview="${esc(focus)}" hidden></div>

  <div class="cb-bar">
    <button type="button" id="cb-kill" class="cb-kill">KILL SWITCH</button>
    <p class="cb-hint">Stops every bot and asks Coinbase to cancel Crow's orders right away. No code needed.</p>
  </div>
  <div class="cb-bar" id="cb-resume" hidden>
    <label class="cb-field">2FA code <input id="cb-resume-code" inputmode="numeric" maxlength="6" autocomplete="off"></label>
    <button type="button" id="cb-resume-btn">Resume trading</button>
  </div>

  <p id="cb-say" class="cb-say" role="status" hidden></p>
  <div id="cb-banner"></div>

  <h2>Connect</h2>
  <div id="cb-connect" class="cb-card">
    <p class="cb-steps">${esc(steps)}</p>
    <p class="cb-hint">New bots always start in Practice: no real money.</p>
    <label class="cb-field">Project <select id="cb-project"></select></label>
    <label class="cb-field">Key name <input id="cb-key-name" type="password" autocomplete="off" spellcheck="false"></label>
    <label class="cb-field">Private key <input id="cb-key" type="password" autocomplete="off" spellcheck="false"></label>
    <label class="cb-field">2FA code <input id="cb-connect-code" inputmode="numeric" maxlength="6" autocomplete="off"></label>
    <div class="cb-bar">
      <button type="button" id="cb-test">Test connection</button>
      <button type="button" id="cb-connect-btn">Connect</button>
    </div>
  </div>
  <div id="cb-connected" class="cb-card" hidden>
    <p id="cb-connected-msg"></p>
    <p id="cb-key-line" class="cb-hint"></p>
    <label class="cb-field">2FA code <input id="cb-disconnect-code" inputmode="numeric" maxlength="6" autocomplete="off"></label>
    <div class="cb-bar"><button type="button" id="cb-disconnect">Disconnect</button></div>
  </div>

  <h2>Pending approvals</h2>
  <div id="cb-previews"></div>
  <h2 id="cb-recent-title" hidden>Recently answered</h2>
  <div id="cb-recent"></div>

  <h2>Bots</h2>
  <p class="cb-hint">Every bot wears a badge: <span class="cb-badge cb-practice">PRACTICE</span> means no real money,
    <span class="cb-badge cb-live">LIVE</span> means real money.</p>
  <div id="cb-bots"></div>
  <form id="cb-create" class="cb-card">
    <p><b>New bot</b></p>
    <label class="cb-field">What should it trade?
      <select id="cb-product"><option value="">No products are set up yet.</option></select>
    </label>
    <label class="cb-field">Starting money (USDC) <input id="cb-capital" inputmode="decimal" value="10.00"></label>
    <p class="cb-hint">Rebalance (recommended) keeps about half in the coin and the rest in USDC.</p>
    <details>
      <summary class="cb-hint">More options</summary>
      <label class="cb-field"><input type="checkbox" id="cb-grid"> Use a grid instead of rebalancing</label>
      <p class="cb-hint">No edge on average: it behaves like holding about half in the coin.</p>
      <label class="cb-field">Middle price <input id="cb-center" inputmode="decimal"></label>
      <label class="cb-field">Step (%) <input id="cb-step" inputmode="decimal" value="1"></label>
      <label class="cb-field">Steps below <input id="cb-below" type="number" min="1" max="10" value="3"></label>
      <label class="cb-field">Steps above <input id="cb-above" type="number" min="1" max="10" value="3"></label>
      <label class="cb-field">Money per buy (USDC) <input id="cb-per-buy" inputmode="decimal" value="5"></label>
      <label class="cb-field">Money to buy with
        <select id="cb-rebuy">
          <option value="proceeds">What it just sold</option>
          <option value="fixed">Fresh money</option>
        </select>
      </label>
    </details>
    <div class="cb-bar"><button type="submit">Create bot (Practice)</button></div>
  </form>

  <h2>Open orders</h2>
  <div id="cb-orders" class="cb-orders">
    <div class="cb-card" data-book="dry">
      <p class="cb-card-head"><span class="cb-badge cb-practice">PRACTICE</span><b>Practice</b></p>
      <div class="cb-orders-body"><p class="cb-hint">No open orders.</p></div>
    </div>
    <div class="cb-card" data-book="live">
      <p class="cb-card-head"><span class="cb-badge cb-live">LIVE</span><b>Live</b></p>
      <div class="cb-orders-body"><p class="cb-hint">No open orders.</p></div>
    </div>
  </div>

  <h2>Alerts</h2>
  <div id="cb-alerts"></div>

  <h2>Recent fills and profit/loss</h2>
  <div id="cb-fills"></div>
  <div id="cb-pnl"></div>

  <h2>Limits in force</h2>
  <ul class="cb-list" id="cb-limits"></ul>

  <h2>Settings</h2>
  <form id="cb-switches" class="cb-card">
    <label class="cb-field"><input type="checkbox" id="cb-sw-live"> Let bots trade with real money</label>
    <label class="cb-field"><input type="checkbox" id="cb-sw-ai"> Let the AI place real orders after I approve</label>
    <p class="cb-hint" id="cb-switches-note"></p>
    <label class="cb-field">2FA code <input id="cb-switches-code" inputmode="numeric" maxlength="6" autocomplete="off"></label>
    <div class="cb-bar"><button type="submit">Save</button></div>
  </form>
  <details class="cb-card">
    <summary class="cb-hint">More options</summary>
    <p><b>Limits Crow may not pass</b></p>
    <div id="cb-caps" class="cb-card"></div>
    <label class="cb-field">2FA code <input id="cb-caps-code" inputmode="numeric" maxlength="6" autocomplete="off"></label>
    <div class="cb-bar"><button type="button" id="cb-caps-save">Save limits</button></div>
    <p><b>Alert me after some days behind simply holding</b></p>
    <p class="cb-note-readonly">Crow rings the bell if a bot does worse than simply holding its starting mix for the
      number of days set in the add-on settings. There is nothing to set here.</p>
  </details>

  <template id="cb-preview-tpl">
    <div class="cb-card" data-left="0">
      <p class="cb-card-head"><span class="cb-badge"></span><span class="cb-left cb-hint"></span></p>
      <p class="cb-summary"></p>
      <ul class="cb-lines"></ul>
      <label class="cb-field">2FA code <input data-field="totp" inputmode="numeric" maxlength="6" autocomplete="off"></label>
      <div class="cb-bar">
        <button type="button" data-act="approve">Approve</button>
        <button type="button" data-act="reject">Not now</button>
      </div>
    </div>
  </template>
</section>`;
}

/**
 * The page's script: poll the panel's own state route every 8 seconds and draw
 * it. Every value the route hands over goes through `esc` before it becomes
 * markup, every action posts to /api/coinbase and shows the answer's sentence,
 * and a refusal's machine code is never shown. Under Turbo the whole script runs
 * again on a second visit into the panel, so both timers are cleared first and
 * every tick checks it still owns the page.
 */
function renderScript() {
  const strings = JSON.stringify(STRINGS).replace(/</g, "\\u003c");
  const capLabels = JSON.stringify(CAP_LABELS).replace(/</g, "\\u003c");
  const capUsed = JSON.stringify(CAP_USED).replace(/</g, "\\u003c");
  return `
(function () {
  var root = document.getElementById("cb-panel");
  if (!root) return;
  if (window.__crowCoinbasePoll) { clearInterval(window.__crowCoinbasePoll); window.__crowCoinbasePoll = null; }
  if (window.__crowCoinbaseTick) { clearInterval(window.__crowCoinbaseTick); window.__crowCoinbaseTick = null; }
  var owner = {};
  window.__crowCoinbasePollOwner = owner;
  var S = ${strings};
  var CAP_LABELS = ${capLabels};
  var CAP_USED = ${capUsed};
  var POLL_MS = 8000;
  var focusBox = document.getElementById("cb-focus");
  var focusId = focusBox ? String(focusBox.getAttribute("data-preview") || "") : "";
  var killArmed = false;
  var killTimer = null;
  var haltArmed = false;
  var lastPreviewKey = null;
  var lastBotKey = null;
  var lastSwitches = null;
  var productsBuilt = "";
  var capsBuilt = "";
  var projectsLoaded = false;
  var pollFails = 0;

  function esc(value) {
    return String(value === undefined || value === null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  function say(text, bad) {
    var el = document.getElementById("cb-say");
    if (!el) return;
    if (!text) { el.hidden = true; el.textContent = ""; return; }
    el.hidden = false;
    el.textContent = String(text);
    el.className = bad ? "cb-say cb-bad" : "cb-say";
  }

  function clearSay() {
    if (window.__crowCoinbasePollOwner !== owner) return;
    say("", false);
  }

  function api(method, path, body) {
    var init = { method: method, headers: {} };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch("/api/coinbase" + path, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) { try { data = JSON.parse(text); } catch (err) { data = null; } }
        if (!res.ok) {
          var failure = new Error((data && data.message) || S.failed);
          failure.status = res.status;
          failure.data = data || {};
          throw failure;
        }
        return data || {};
      });
    });
  }

  function fail(err) {
    var data = (err && err.data) || {};
    say(data.message || S.failed, true);
  }

  function stopPolling() {
    if (window.__crowCoinbasePoll) { clearInterval(window.__crowCoinbasePoll); window.__crowCoinbasePoll = null; }
    if (window.__crowCoinbaseTick) { clearInterval(window.__crowCoinbaseTick); window.__crowCoinbaseTick = null; }
  }

  function clock(seconds) {
    var s = Math.max(0, Math.floor(Number(seconds) || 0));
    var m = Math.floor(s / 60);
    var r = s % 60;
    return m + ":" + (r < 10 ? "0" : "") + r;
  }

  function when(stamp) {
    var n = Number(stamp);
    if (!isFinite(n) || n <= 0) return "";
    var ms = n > 1e12 ? n : n * 1000;
    try { return new Date(ms).toLocaleString(); } catch (err) { return ""; }
  }

  function bookName(book) { return book === "live" ? "Live" : "Practice"; }

  function badgeClass(badge) { return String(badge) === "LIVE" ? "cb-badge cb-live" : "cb-badge cb-practice"; }

  function statusWords(status) {
    if (status === "PAUSED") return S.statusPaused;
    if (status === "STOPPED") return S.statusStopped;
    return S.statusRunning;
  }

  function capUnit(name) {
    if (name === "CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT") return "%";
    if (name === "CROW_COINBASE_ORDERS_PER_HOUR" || name === "CROW_COINBASE_AI_ORDERS_PER_HOUR") return "";
    return " USDC";
  }

  function capLabel(name) {
    return Object.prototype.hasOwnProperty.call(CAP_LABELS, name) ? CAP_LABELS[name] : S.otherLimit;
  }

  // ---- the state banner ---------------------------------------------------------------------

  function renderBanner(state) {
    var box = document.getElementById("cb-banner");
    var connection = state.connection || {};
    var engine = state.engine || {};
    var lines = [];
    var alarm = false;
    if (!connection.connected) {
      lines.push(connection.message || S.notConnected);
    } else if (connection.disconnect_unfinished) {
      lines.push(connection.message || S.disconnectUnfinished);
    } else if (connection.needs_reconnect) {
      lines.push(connection.message || S.needsReconnect);
    }
    if (connection.pending) lines.push(S.pending);
    if (!engine.reachable) { lines.push(engine.note || S.engineDown); alarm = true; }
    if (engine.reachable && engine.halted) {
      lines.push(S.halted);
      alarm = true;
      var books = engine.halted_books || {};
      if (books.dry === true && books.live !== true) lines.push(bookName("dry") + ": " + S.haltedBook);
      if (books.live === true && books.dry !== true) lines.push(bookName("live") + ": " + S.haltedBook);
    } else if (engine.reachable && engine.note) {
      lines.push(engine.note);
    }
    if (state.two_factor === false) lines.push(S.twoFactor);
    box.innerHTML = lines.map(function (line) {
      return '<p class="cb-banner' + (alarm ? " cb-alarm" : "") + '">' + esc(line) + "</p>";
    }).join("");
    var resume = document.getElementById("cb-resume");
    if (resume) resume.hidden = !(engine.reachable && engine.halted);
  }

  // ---- Connect ------------------------------------------------------------------------------

  function loadProjects() {
    if (projectsLoaded) return;
    projectsLoaded = true;
    api("GET", "/projects").then(function (answer) {
      var select = document.getElementById("cb-project");
      if (!select) return;
      var projects = (answer && answer.projects) || [];
      select.innerHTML = "";
      if (!projects.length) {
        var none = document.createElement("option");
        none.value = "";
        none.textContent = S.noProjects;
        select.appendChild(none);
        return;
      }
      projects.forEach(function (project) {
        var option = document.createElement("option");
        option.value = String(project.id);
        option.textContent = String(project.name);
        select.appendChild(option);
      });
    }).catch(function () { projectsLoaded = false; });
  }

  function renderConnect(state) {
    var connection = state.connection || {};
    var showConnect = !connection.connected || connection.needs_reconnect === true || connection.disconnect_unfinished === true;
    var block = document.getElementById("cb-connect");
    var done = document.getElementById("cb-connected");
    if (block) block.hidden = !showConnect;
    if (done) done.hidden = showConnect;
    if (showConnect) loadProjects();
    if (showConnect) return;
    var message = document.getElementById("cb-connected-msg");
    if (message) message.textContent = String(connection.message || S.connected);
    var keyLine = document.getElementById("cb-key-line");
    if (keyLine) {
      var bits = [];
      if (connection.portfolio_last4) bits.push(S.portfolio + " \\u2026" + String(connection.portfolio_last4));
      if (connection.key_last4) bits.push(S.key + " \\u2026" + String(connection.key_last4));
      keyLine.textContent = bits.join("  \\u00b7  ");
    }
  }

  // ---- pending approvals --------------------------------------------------------------------

  function previewKeyOf(previews) {
    return (previews || []).map(function (row) {
      return [row.preview_id, row.hash, row.state, row.badge].join("|");
    }).join(",");
  }

  // Why the countdown is not in the key: a fresh "seconds_left" every poll would
  // rebuild the cards and wipe a code the owner is typing. It is refreshed here instead.
  function syncCountdowns(box, previews) {
    var cards = box.querySelectorAll(".cb-card[data-preview]");
    for (var i = 0; i < cards.length; i += 1) {
      var id = String(cards[i].getAttribute("data-preview"));
      for (var j = 0; j < previews.length; j += 1) {
        if (String(previews[j].preview_id) !== id) continue;
        var seconds = Number(previews[j].seconds_left);
        if (isFinite(seconds)) {
          cards[i].setAttribute("data-left", String(Math.max(0, Math.floor(seconds))));
        }
        break;
      }
    }
  }

  function renderPreviews(state) {
    var previews = state.previews || [];
    var box = document.getElementById("cb-previews");
    var key = previewKeyOf(previews);
    if (key === lastPreviewKey) { syncCountdowns(box, previews); return; }
    lastPreviewKey = key;
    box.innerHTML = "";
    if (!previews.length) {
      box.innerHTML = '<p class="cb-hint">' + esc(S.nothingWaiting) + "</p>";
      return;
    }
    var template = document.getElementById("cb-preview-tpl");
    previews.forEach(function (preview) {
      var card = template.content.firstElementChild.cloneNode(true);
      var badge = card.querySelector(".cb-badge");
      badge.className = badgeClass(preview.badge);
      badge.textContent = String(preview.badge || "");
      var left = Number(preview.seconds_left);
      card.setAttribute("data-left", String(isFinite(left) ? Math.max(0, Math.floor(left)) : 0));
      card.querySelector(".cb-left").textContent = isFinite(left) && left > 0
        ? S.timeLeft + " " + clock(left)
        : S.expired;
      card.querySelector(".cb-summary").textContent = String(preview.summary || "");
      var lines = card.querySelector(".cb-lines");
      (preview.lines || []).forEach(function (line) {
        var item = document.createElement("li");
        item.textContent = String(line);
        lines.appendChild(item);
      });
      if (focusId && String(preview.preview_id) === focusId) card.className += " cb-focus";
      card.setAttribute("data-preview", String(preview.preview_id));
      card.addEventListener("click", function (event) {
        var button = event.target && event.target.closest ? event.target.closest("button[data-act]") : null;
        if (!button) return;
        var act = button.getAttribute("data-act");
        var id = String(preview.preview_id);
        if (act === "reject") {
          api("POST", "/previews/" + encodeURIComponent(id) + "/reject", {}).then(function (answer) {
            say((answer && answer.message) || S.reject, false);
            load();
          }).catch(fail);
          return;
        }
        var field = card.querySelector('[data-field="totp"]');
        var code = field ? String(field.value || "").trim() : "";
        var body = { hash: String(preview.hash || "") };
        if (code) body.totp = code;
        api("POST", "/previews/" + encodeURIComponent(id) + "/approve", body).then(function (answer) {
          if (field) field.value = "";
          say((answer && answer.message) || S.approve, false);
          load();
        }).catch(fail);
      });
      box.appendChild(card);
    });
  }

  /** The proposals already answered, one plain sentence each (at most five). */
  function renderRecent(state) {
    var recentBox = document.getElementById("cb-recent");
    var recentTitle = document.getElementById("cb-recent-title");
    var recent = state.recent_previews || [];
    if (recentTitle) recentTitle.hidden = !recent.length;
    if (recentBox) {
      recentBox.innerHTML = recent.map(function (row) {
        return '<p class="cb-hint">' + esc(row.summary) + "</p>";
      }).join("");
    }
  }

  // ---- bots ---------------------------------------------------------------------------------

  function botKeyOf(bots) {
    return (bots || []).map(function (bot) {
      return [bot.id, bot.status, bot.mode, bot.strategy, bot.value, bot.vs_hold, bot.realized, bot.fees, bot.note].join("|");
    }).join(",");
  }

  function botMoney(bot) {
    var bits = [];
    if (bot.value !== undefined && bot.value !== null && bot.value !== "") {
      bits.push(S.worth + " " + String(bot.value) + " USDC.");
    }
    var vs = bot.vs_hold === undefined || bot.vs_hold === null ? "" : String(bot.vs_hold);
    if (vs !== "") {
      var behind = vs.charAt(0) === "-";
      var amount = behind ? vs.slice(1) : vs;
      bits.push((behind ? S.behind : S.ahead) + " " + amount + " USDC.");
    }
    if (bot.realized !== undefined && bot.realized !== null && bot.realized !== "") {
      bits.push(S.profit + " " + String(bot.realized) + " USDC.");
    }
    if (bot.fees !== undefined && bot.fees !== null && bot.fees !== "") {
      bits.push(S.fees + " " + String(bot.fees) + " USDC.");
    }
    return bits.join(" ");
  }

  function botCard(bot) {
    var note = bot.note ? String(bot.note) : (bot.status === "PAUSED" ? S.needsAttention : "");
    var isLive = String(bot.badge) === "LIVE";
    var strategyWords = bot.strategy === "grid" ? S.grid : S.rebalance;
    var recenter = bot.strategy === "grid"
      ? '<div class="cb-bot-form" data-form="recenter" hidden>' +
        '<label class="cb-field">' + esc(S.newCenter) +
        ' <input data-field="center" inputmode="decimal"></label>' +
        '<label class="cb-field">' + esc(S.code) +
        ' <input data-field="recenter_totp" inputmode="numeric" maxlength="6" autocomplete="off"></label>' +
        '<div class="cb-bar"><button type="button" data-act="recenter">' + esc(S.recenter) + "</button></div></div>"
      : "";
    return '<div class="cb-bot" data-bot="' + esc(bot.id) + '">' +
      '<p class="cb-card-head"><span class="' + badgeClass(bot.badge) + '">' + esc(bot.badge) + "</span>" +
      "<b>" + esc(bot.product) + "</b> \\u2014 " + esc(strategyWords) + " (" + esc(statusWords(bot.status)) + ")</p>" +
      (note ? '<p class="cb-bot-note">' + esc(note) + "</p>" : "") +
      '<p class="cb-hint">' + esc(botMoney(bot)) + "</p>" +
      '<div class="cb-bot-acts">' +
      '<button type="button" data-act="pause">' + esc(S.pause) + "</button>" +
      '<button type="button" data-act="stop">' + esc(S.stop) + "</button>" +
      '<button type="button" data-act="resume-open">' + esc(S.resumeBot) + "</button>" +
      (isLive
        ? '<button type="button" data-act="practice">' + esc(S.backToPractice) + "</button>"
        : '<button type="button" data-act="live-open">' + esc(S.goLive) + "</button>") +
      "</div>" +
      '<div class="cb-bot-form" data-form="resume" hidden>' +
      '<label class="cb-field">' + esc(S.code) +
      ' <input data-field="totp" inputmode="numeric" maxlength="6" autocomplete="off"></label>' +
      '<div class="cb-bar"><button type="button" data-act="resume">' + esc(S.resumeBot) + "</button>" +
      '<button type="button" data-act="close">' + esc(S.cancel) + "</button></div></div>" +
      '<div class="cb-bot-form" data-form="live" hidden>' +
      '<label class="cb-field"><input type="checkbox" data-field="ack"> ' + esc(S.goLiveConfirm) + "</label>" +
      '<label class="cb-field">' + esc(S.startMoney) +
      ' <input data-field="capital_quote" inputmode="decimal" value="' + esc(bot.capital_quote || "") + '"></label>' +
      '<label class="cb-field">' + esc(S.startCoin) +
      ' <input data-field="capital_base" inputmode="decimal" placeholder="' + esc(S.startCoinHint) + '"></label>' +
      '<label class="cb-field">' + esc(S.code) +
      ' <input data-field="live_totp" inputmode="numeric" maxlength="6" autocomplete="off"></label>' +
      '<div class="cb-bar"><button type="button" data-act="live">' + esc(S.turnLive) + "</button>" +
      '<button type="button" data-act="close">' + esc(S.cancel) + "</button></div></div>" +
      recenter +
      "</div>";
  }

  function renderBots(state) {
    var bots = state.bots || [];
    var box = document.getElementById("cb-bots");
    var key = botKeyOf(bots);
    if (key === lastBotKey) return;
    lastBotKey = key;
    if (!bots.length) {
      box.innerHTML = '<p class="cb-hint">' + esc(S.noBots) + "</p>";
      return;
    }
    box.innerHTML = bots.map(botCard).join("");
  }

  function fieldOf(card, name) {
    var field = card.querySelector('[data-field="' + name + '"]');
    return field ? field : null;
  }

  function botAction(button) {
    var card = button.closest(".cb-bot");
    if (!card) return;
    var id = String(card.getAttribute("data-bot") || "");
    var act = button.getAttribute("data-act");
    var base = "/bots/" + encodeURIComponent(id);
    var field;
    if (act === "pause") { api("POST", base + "/pause", {}).then(function (answer) { say((answer && answer.message) || S.done, false); load(); }).catch(fail); return; }
    if (act === "stop") { api("POST", base + "/stop", {}).then(function (answer) { say((answer && answer.message) || S.done, false); load(); }).catch(fail); return; }
    if (act === "practice") {
      // A move back to practice needs no code and names no money: the engine takes the practice
      // book's capital from the live book's own value and cancels what was resting there.
      api("POST", base + "/mode", { mode: "dry" }).then(function (answer) {
        say((answer && answer.message) || S.done, false);
        load();
      }).catch(fail);
      return;
    }
    if (act === "resume-open" || act === "live-open") {
      var name = act === "resume-open" ? "resume" : "live";
      var form = card.querySelector('[data-form="' + name + '"]');
      if (form) form.hidden = !form.hidden;
      return;
    }
    if (act === "close") {
      var panel = button.closest(".cb-bot-form");
      if (panel) panel.hidden = true;
      return;
    }
    if (act === "resume") {
      field = fieldOf(card, "totp");
      var code = field ? String(field.value || "").trim() : "";
      var resumeBody = { acknowledge_rebase: true };
      if (code) resumeBody.totp = code;
      api("POST", base + "/resume", resumeBody).then(function (answer) {
        if (field) field.value = "";
        say((answer && answer.message) || S.done, false);
        load();
      }).catch(fail);
      return;
    }
    if (act === "live") {
      var ack = fieldOf(card, "ack");
      if (!ack || ack.checked !== true) { say(S.goLiveConfirm, true); return; }
      var money = fieldOf(card, "capital_quote");
      var coinField = fieldOf(card, "capital_base");
      // The base side of the starting mix: blank means none of the coin, which the engine reads
      // as "0". A value that is not a plain non-negative decimal is refused here, so nothing is
      // posted and the owner is told in one plain sentence.
      var coin = coinField ? String(coinField.value || "").trim() : "";
      if (coin !== "" && !/^\\d+(\\.\\d+)?$/.test(coin)) { say(S.badCoin, true); return; }
      var liveCode = fieldOf(card, "live_totp");
      var liveBody = {
        mode: "live",
        acknowledge_live: true,
        capital_quote: money ? String(money.value || "").trim() : "",
        capital_base: coin === "" ? "0" : coin,
      };
      if (liveCode && String(liveCode.value || "").trim() !== "") liveBody.totp = String(liveCode.value).trim();
      api("POST", base + "/mode", liveBody).then(function (answer) {
        if (liveCode) liveCode.value = "";
        say((answer && answer.message) || S.done, false);
        load();
      }).catch(fail);
      return;
    }
    if (act === "recenter") {
      var center = fieldOf(card, "center");
      var centerCode = fieldOf(card, "recenter_totp");
      var centerBody = { center: center ? String(center.value || "").trim() : "" };
      if (centerCode && String(centerCode.value || "").trim() !== "") centerBody.totp = String(centerCode.value).trim();
      api("POST", base + "/recenter", centerBody).then(function (answer) {
        if (centerCode) centerCode.value = "";
        say((answer && answer.message) || S.done, false);
        load();
      }).catch(fail);
    }
  }

  // ---- the open orders of each book ----------------------------------------------------------

  // One box per book, filled from GET /panel's open_orders (the engine's own /orders read).
  // The rows carry no client order id: the page only ever shows what the owner needs to see.
  function renderOrders(state) {
    var box = document.getElementById("cb-orders");
    if (!box) return;
    var orders = state.open_orders || {};
    ["dry", "live"].forEach(function (book) {
      var card = box.querySelector('[data-book="' + book + '"]');
      if (!card) return;
      var body = card.querySelector(".cb-orders-body");
      if (!body) return;
      var rows = orders[book];
      if (!Array.isArray(rows) || !rows.length) {
        body.innerHTML = '<p class="cb-hint">' + esc(S.noOrders) + "</p>";
        return;
      }
      var head = "<tr><th>" + esc(S.bot) + "</th><th>" + esc(S.product) + "</th><th>" + esc(S.side) +
        "</th><th>" + esc(S.size) + "</th><th>" + esc(S.price) + "</th><th>" + esc(S.when) + "</th></tr>";
      var lines = rows.map(function (row) {
        var side = String(row.side || "").toUpperCase() === "SELL" ? S.sell : S.buy;
        return "<tr><td>" + esc(row.bot) + "</td><td>" + esc(row.product) + "</td><td>" + esc(side) +
          "</td><td>" + esc(row.size) + "</td><td>" + esc(row.price) + "</td><td>" +
          esc(when(row.created_at)) + "</td></tr>";
      }).join("");
      body.innerHTML = '<div class="table-scroll"><table class="cb-table">' + head + lines + "</table></div>";
    });
  }

  // ---- alerts, fills, profit and loss -------------------------------------------------------

  function renderAlerts(state) {
    var box = document.getElementById("cb-alerts");
    var alerts = state.alerts || [];
    if (!alerts.length) {
      box.innerHTML = '<p class="cb-hint">' + esc(S.noAlerts) + "</p>";
      return;
    }
    box.innerHTML = '<ul class="cb-list">' + alerts.map(function (alert) {
      var at = when(alert.ts);
      return "<li>" + (at ? esc(at) + " \\u2014 " : "") + esc(alert.message) + "</li>";
    }).join("") + "</ul>";
  }

  function renderFills(state) {
    var box = document.getElementById("cb-fills");
    var fills = state.fills || [];
    if (!fills.length) {
      box.innerHTML = '<p class="cb-hint">' + esc(S.noFills) + "</p>";
    } else {
      var head = "<tr><th>" + esc(S.when) + "</th><th>" + esc(S.bot) + "</th><th>" + esc(S.product) +
        "</th><th>" + esc(S.side) + "</th><th>" + esc(S.price) + "</th><th>" + esc(S.size) + "</th></tr>";
      var rows = fills.map(function (fill) {
        var side = String(fill.side || "").toUpperCase() === "SELL" ? S.sell : S.buy;
        return "<tr><td>" + esc(when(fill.time)) + "</td><td>" + esc(fill.bot_id) + "</td><td>" +
          esc(fill.product) + "</td><td>" + esc(side) + "</td><td>" + esc(fill.price) + "</td><td>" +
          esc(fill.size) + "</td></tr>";
      }).join("");
      box.innerHTML = '<div class="table-scroll"><table class="cb-table">' + head + rows + "</table></div>";
    }
    var pnl = document.getElementById("cb-pnl");
    var bots = state.bots || [];
    pnl.innerHTML = bots.filter(function (bot) {
      return (bot.realized !== undefined && bot.realized !== null && bot.realized !== "") ||
        (bot.fees !== undefined && bot.fees !== null && bot.fees !== "");
    }).map(function (bot) {
      var bits = [];
      if (bot.realized !== undefined && bot.realized !== null && bot.realized !== "") {
        bits.push(S.profit + " " + String(bot.realized) + " USDC");
      }
      if (bot.fees !== undefined && bot.fees !== null && bot.fees !== "") {
        bits.push(S.fees + " " + String(bot.fees) + " USDC");
      }
      return '<p class="cb-hint">' + esc(bot.id) + " \\u2014 " + esc(bits.join(", ")) + "</p>";
    }).join("");
  }

  function renderLimits(state) {
    var box = document.getElementById("cb-limits");
    var limits = state.limits || {};
    var caps = limits.caps || {};
    var ceilings = limits.ceilings || {};
    var used = limits.used_today || {};
    var names = Object.keys(caps);
    var drawdown = state.drawdown || {};
    if (!names.length) {
      box.innerHTML = '<li class="cb-hint">' + esc(S.noLimits) + "</li>";
      return;
    }
    var items = [];
    names.forEach(function (name) {
      var unit = capUnit(name);
      var bits = [esc(capLabel(name)) + ": " + esc(String(caps[name])) + esc(unit)];
      if (ceilings[name] !== undefined && ceilings[name] !== null) {
        bits.push(esc(S.ceiling) + " " + esc(String(ceilings[name])) + esc(unit));
      }
      var usedField = Object.prototype.hasOwnProperty.call(CAP_USED, name) ? CAP_USED[name] : "";
      if (usedField) {
        var parts = [];
        ["dry", "live"].forEach(function (book) {
          var row = used[book] || {};
          if (row[usedField] === undefined || row[usedField] === null) return;
          parts.push(bookName(book) + " " + String(row[usedField]));
        });
        if (parts.length) bits.push(esc(S.usedToday) + " " + esc(parts.join(" \\u00b7 ")));
      }
      items.push("<li>" + bits.join(" \\u00b7 ") + "</li>");
    });
    var dd = drawdown.dry === undefined || drawdown.dry === null ? S.nothingYet : String(drawdown.dry) + "%";
    var ddLive = drawdown.live === undefined || drawdown.live === null ? S.nothingYet : String(drawdown.live) + "%";
    if (dd !== S.nothingYet || ddLive !== S.nothingYet) {
      items.push("<li>" + esc(S.drawdown) + " \\u2014 " + esc(bookName("dry")) + " " + esc(dd) +
        ", " + esc(bookName("live")) + " " + esc(ddLive) + "</li>");
    }
    box.innerHTML = items.join("");
  }

  // ---- settings -----------------------------------------------------------------------------

  // The products the engine offers, from GET /panel's products (its own /status read). There is
  // no list in this file: an engine with none leaves the form saying so.
  function renderProducts(state) {
    if (!Array.isArray(state.products)) return;
    var select = document.getElementById("cb-product");
    if (!select) return;
    var names = state.products.map(function (name) { return String(name); });
    var key = names.join(",");
    if (key === productsBuilt) return;
    var keep = String(select.value || "");
    productsBuilt = key;
    select.innerHTML = "";
    if (!names.length) {
      var none = document.createElement("option");
      none.value = "";
      none.textContent = S.noProducts;
      select.appendChild(none);
      return;
    }
    names.forEach(function (name) {
      var option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      select.appendChild(option);
    });
    if (keep && names.indexOf(keep) !== -1) select.value = keep;
  }

  function buildCaps(state) {
    var limits = state.limits || {};
    var caps = limits.caps || {};
    var ceilings = limits.ceilings || {};
    var names = Object.keys(caps);
    var key = names.join(",");
    if (!names.length || key === capsBuilt) return;
    capsBuilt = key;
    var box = document.getElementById("cb-caps");
    box.innerHTML = names.map(function (name) {
      var isCount = typeof caps[name] === "number" || typeof ceilings[name] === "number";
      var ceiling = ceilings[name] === undefined || ceilings[name] === null
        ? ""
        : ' <span class="cb-hint">' + esc(S.ceiling) + " " + esc(String(ceilings[name])) + esc(capUnit(name)) + "</span>";
      return '<label class="cb-field">' + esc(capLabel(name)) +
        ' <input data-cap="' + esc(name) + '" type="' + (isCount ? "number" : "text") +
        '" inputmode="' + (isCount ? "numeric" : "decimal") + '" value="' + esc(String(caps[name])) + '">' +
        ceiling + "</label>";
    }).join("");
  }

  function renderSettings(state) {
    var switches = state.switches || {};
    // The state the poll last returned: the Save button compares against this and sends only
    // the switches that really changed.
    lastSwitches = {
      live_enabled: switches.live_enabled === true,
      ai_live_enabled: switches.ai_live_enabled === true,
    };
    var form = document.getElementById("cb-switches");
    if (form && !form.contains(document.activeElement)) {
      document.getElementById("cb-sw-live").checked = lastSwitches.live_enabled;
      document.getElementById("cb-sw-ai").checked = lastSwitches.ai_live_enabled;
    }
    var note = document.getElementById("cb-switches-note");
    if (note) note.textContent = switches.ceiling === false ? S.ceilingOff : "";
    buildCaps(state);
  }

  function render(state) {
    renderBanner(state);
    renderConnect(state);
    renderPreviews(state);
    renderRecent(state);
    renderBots(state);
    renderOrders(state);
    renderProducts(state);
    renderAlerts(state);
    renderFills(state);
    renderLimits(state);
    renderSettings(state);
  }

  // ---- the poll -----------------------------------------------------------------------------

  function load() {
    return api("GET", "/panel").then(function (state) {
      if (window.__crowCoinbasePollOwner !== owner) return;
      pollFails = 0;
      render(state || {});
    }).catch(function (err) {
      if (window.__crowCoinbasePollOwner !== owner) return;
      pollFails += 1;
      var status = err && err.status;
      if (status === 403 || status === 401) {
        stopPolling();
        say((err.data && err.data.message) || S.failed, true);
        return;
      }
      if (pollFails >= 3) say(S.engineDown, true);
    });
  }

  function startTicks() {
    window.__crowCoinbaseTick = setInterval(function () {
      if (window.__crowCoinbasePollOwner !== owner) return;
      var cards = root.querySelectorAll("[data-left]");
      for (var i = 0; i < cards.length; i += 1) {
        var left = Number(cards[i].getAttribute("data-left")) - 1;
        if (!(left > 0)) left = 0;
        cards[i].setAttribute("data-left", String(left));
        var label = cards[i].querySelector(".cb-left");
        if (label) label.textContent = left > 0 ? S.timeLeft + " " + clock(left) : S.expired;
      }
    }, 1000);
  }

  // ---- the buttons --------------------------------------------------------------------------

  function armKill() {
    var button = document.getElementById("cb-kill");
    killArmed = true;
    if (button) { button.className = "cb-kill cb-armed"; button.textContent = S.killArmed; }
    say(S.killArmed, false);
    if (killTimer) clearTimeout(killTimer);
    killTimer = setTimeout(function () {
      killArmed = false;
      killTimer = null;
      if (button) { button.className = "cb-kill"; button.textContent = S.kill; }
      clearSay();
    }, 12000);
  }

  function disarmKill() {
    killArmed = false;
    if (killTimer) { clearTimeout(killTimer); killTimer = null; }
    var button = document.getElementById("cb-kill");
    if (button) { button.className = "cb-kill"; button.textContent = S.kill; }
  }

  document.getElementById("cb-kill").addEventListener("click", function () {
    if (!killArmed) { armKill(); return; }
    disarmKill();
    api("POST", "/kill", { confirm: true }).then(function (answer) {
      say((answer && answer.message) || S.halted, false);
      load();
    }).catch(fail);
  });

  document.getElementById("cb-resume-btn").addEventListener("click", function () {
    var field = document.getElementById("cb-resume-code");
    var code = field ? String(field.value || "").trim() : "";
    var body = { acknowledge_rebase: true };
    if (code) body.totp = code;
    api("POST", "/halt/clear", body).then(function (answer) {
      if (field) field.value = "";
      say((answer && answer.message) || S.resume, false);
      load();
    }).catch(fail);
  });

  function pastedKey() {
    var name = document.getElementById("cb-key-name");
    var key = document.getElementById("cb-key");
    return {
      key_name: name ? String(name.value || "").trim() : "",
      private_key: key ? String(key.value || "") : "",
    };
  }

  function clearKeyFields() {
    var name = document.getElementById("cb-key-name");
    var key = document.getElementById("cb-key");
    if (name) name.value = "";
    if (key) key.value = "";
  }

  document.getElementById("cb-test").addEventListener("click", function () {
    var pasted = pastedKey();
    var codeField = document.getElementById("cb-connect-code");
    var body = { key_name: pasted.key_name, private_key: pasted.private_key };
    if (codeField && String(codeField.value || "").trim() !== "") body.totp = String(codeField.value).trim();
    api("POST", "/connect/test", body).then(function (answer) {
      clearKeyFields();
      say((answer && answer.message) || S.connected, false);
    }).catch(fail);
  });

  document.getElementById("cb-connect-btn").addEventListener("click", function () {
    var pasted = pastedKey();
    var codeField = document.getElementById("cb-connect-code");
    var project = document.getElementById("cb-project");
    var body = { key_name: pasted.key_name, private_key: pasted.private_key };
    if (project && String(project.value || "").trim() !== "") body.project_id = String(project.value).trim();
    if (codeField && String(codeField.value || "").trim() !== "") body.totp = String(codeField.value).trim();
    api("POST", "/connect", body).then(function (answer) {
      clearKeyFields();
      if (codeField) codeField.value = "";
      say((answer && answer.message) || S.connected, false);
      load();
    }).catch(fail);
  });

  document.getElementById("cb-disconnect").addEventListener("click", function () {
    var codeField = document.getElementById("cb-disconnect-code");
    var body = {};
    if (codeField && String(codeField.value || "").trim() !== "") body.totp = String(codeField.value).trim();
    api("POST", "/disconnect", body).then(function (answer) {
      if (codeField) codeField.value = "";
      say((answer && answer.message) || S.done, false);
      load();
    }).catch(fail);
  });

  document.getElementById("cb-bots").addEventListener("click", function (event) {
    var button = event.target && event.target.closest ? event.target.closest("button[data-act]") : null;
    if (button) botAction(button);
  });

  document.getElementById("cb-create").addEventListener("submit", function (event) {
    event.preventDefault();
    var product = document.getElementById("cb-product");
    var capital = document.getElementById("cb-capital");
    var grid = document.getElementById("cb-grid");
    var body = {
      product: product ? String(product.value || "") : "",
      strategy: grid && grid.checked === true ? "grid" : "rebalance",
      capital_quote: capital ? String(capital.value || "").trim() : "",
    };
    if (!body.product) { say(S.noProducts, true); return; }
    if (body.strategy === "grid") {
      var center = document.getElementById("cb-center");
      var step = document.getElementById("cb-step");
      var below = document.getElementById("cb-below");
      var above = document.getElementById("cb-above");
      var perBuy = document.getElementById("cb-per-buy");
      var rebuy = document.getElementById("cb-rebuy");
      body.params = {
        center: center ? String(center.value || "").trim() : "",
        step_pct: step ? String(step.value || "").trim() : "",
        levels_below: below ? Number(below.value) : 3,
        levels_above: above ? Number(above.value) : 3,
        quote_per_buy: perBuy ? String(perBuy.value || "").trim() : "",
        rebuy_sizing: rebuy ? String(rebuy.value || "proceeds") : "proceeds",
      };
    } else {
      body.params = { target_base_pct: 50 };
    }
    api("POST", "/bots", body).then(function (answer) {
      say((answer && answer.message) || S.done, false);
      load();
    }).catch(fail);
  });

  document.getElementById("cb-switches").addEventListener("submit", function (event) {
    event.preventDefault();
    var codeField = document.getElementById("cb-switches-code");
    // Every unchecked box is sent as OFF, so Save can always turn a switch off \u2014 even before
    // the first poll has answered and there is nothing to compare against. A checked box is sent
    // as ON only when it differs from the state the poll last showed (or when there is no such
    // state yet): a switch left where the engine put it is not a change, and asking for it again
    // would only ask for a code nobody needed.
    var boxes = [
      ["live_enabled", document.getElementById("cb-sw-live")],
      ["ai_live_enabled", document.getElementById("cb-sw-ai")],
    ];
    var body = {};
    for (var i = 0; i < boxes.length; i += 1) {
      var name = boxes[i][0];
      var box = boxes[i][1];
      if (!box || box.checked !== true) { body[name] = false; continue; }
      if (!lastSwitches || lastSwitches[name] !== true) body[name] = true;
    }
    if (!Object.keys(body).length) {
      if (codeField) codeField.value = "";
      say(S.done, false);
      return;
    }
    if (codeField && String(codeField.value || "").trim() !== "") body.totp = String(codeField.value).trim();
    api("POST", "/switches", body).then(function (answer) {
      if (codeField) codeField.value = "";
      // The engine's own sentence for what changed, never a generic "Saved."
      say((answer && answer.message) || S.done, false);
      load();
    }).catch(fail);
  });

  document.getElementById("cb-caps-save").addEventListener("click", function () {
    var inputs = document.querySelectorAll("#cb-caps input[data-cap]");
    var caps = {};
    for (var i = 0; i < inputs.length; i += 1) {
      var name = String(inputs[i].getAttribute("data-cap") || "");
      var raw = String(inputs[i].value || "").trim();
      if (!name || raw === "") continue;
      // Money travels as a decimal string, counts as whole numbers: the panel
      // must never hand the engine a float it rounded itself.
      caps[name] = inputs[i].type === "number" ? Math.trunc(Number(raw)) : raw;
    }
    var codeField = document.getElementById("cb-caps-code");
    var body = { caps: caps };
    if (haltArmed) body.confirm_halt = true;
    if (codeField && String(codeField.value || "").trim() !== "") body.totp = String(codeField.value).trim();
    api("POST", "/caps", body).then(function (answer) {
      haltArmed = false;
      if (codeField) codeField.value = "";
      say(S.done, false);
      load();
    }).catch(function (err) {
      var data = (err && err.data) || {};
      if (data.code === "would_halt") {
        // The owner is warned, and pressing Save again confirms it.
        haltArmed = true;
        say(data.message || S.failed, true);
        return;
      }
      fail(err);
    });
  });

  startTicks();
  load();
  window.__crowCoinbasePoll = setInterval(load, POLL_MS);
})();`;
}

export default {
  id: "coinbase",
  name: "Trading",
  icon: "dollar",
  route: "/dashboard/coinbase",
  navOrder: 70,
  category: "finance",
  async handler(req, res, { layout, lang }) {
    const query = (req && req.query) || {};
    // The one value from the address: an id the page highlights. Escaped into a
    // data attribute, never concatenated into markup or script.
    const focus = typeof query.preview === "string" ? query.preview : "";
    const langCode = lang === "es" ? "es" : "en";

    let steps = "";
    try {
      const connect = await bundleImport("panel/connect.js");
      steps = typeof connect.COPY_STEPS === "string" ? connect.COPY_STEPS : "";
    } catch {
      // The Connect copy is the only thing this handler loads; without it the
      // rest of the page still renders and says what to do in its own words.
      steps = "";
    }

    return layout({
      title: "Trading",
      content: renderContent({ steps, focus, lang: langCode }),
      scripts: renderScript(),
    });
  },
};