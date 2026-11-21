// On a GATE relay the exit cleanup still does its NORMAL work for the pair, and only the
// CRASH is withheld.
//
// The browser sits behind the Crow relay's gate (`cdp-relay.mjs --attach`). When the
// relay accepted this connection's `Crow.guardReady` (`{ok: true}` from
// `sendGuardReady`), the RELAY finishes the cleanup when the connection ends: it closes
// every page, leaves one empty page and ends in IDLE. But it only does that when NO
// other intent client is connected, so skipping this connection's cleanup entirely would
// leave its pages running JS and sockets until the other client left — with no time
// bound — and the approved behaviour is that a turn's pages are closed when the turn
// ends.
//
// So a relay-owned pair gets the same treatment as any other: the browser session is
// opened, a survivor is made where the normal path makes one, the bot's pages are
// blanked, their commit observed and their closes issued, and the operator's pages stay
// untouched. What it NEVER does is send `Browser.crash`: that browser is the relay's to
// keep for the next connection. Every place the cleanup would crash — a survivor that
// cannot be made, a blank that never commits, a budget that expires with pages armed —
// instead abandons the rest of the cleanup: no crash, no further page work, one
// `console.error` line saying the relay will finish, and the promise resolves so the
// process exits and its connection closes.
//
// The seam is `opts.relayOwnsCleanup`, a per-pair function asked once per run, before the
// cleanup's first await. A run may only withhold the crash when EVERY pair answers exactly
// `true`; a MIXED set, or every other answer — no function, `false`, `"yes"`, `1`,
// `undefined`, a throw, or a connection that is already gone — keeps the blank-and-crash
// path, which is the fail-safe for a relay with no gate, an older relay that refused the
// declaration, and a browser that died before the exit.
//
// server.js cannot be imported here (it imports Playwright, which the test tree does
// not install), so the per-connection decision is tested through the two helpers it
// uses — `relayGuardReadyAccepted` and `relayOwnsExitCleanup` in private-address.js —
// plus static assertions on server.js: the flag is reset at the start of every
// (re)connect, set from `sendGuardReady`'s answer and from nothing else, and handed to
// `blankPagesOnExit` as the seam.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";

import { createPageOwnership } from "../bundles/browser/server/page-ownership.js";
import { blankPagesOnExit } from "../bundles/browser/server/private-address.js";
// Namespace import on purpose: the two helpers this task adds must make THEIR tests red
// (a missing export read as a property is `undefined`) instead of failing the file's
// import, which would take the cleanup cases down with them.
import * as privateAddress from "../bundles/browser/server/private-address.js";

const SERVER_JS = new URL("../bundles/browser/server/server.js", import.meta.url);
const SERVER = readFileSync(SERVER_JS, "utf8");

// ---------------------------------------------------------------------------
// fakes (Playwright is not installed for the test suite)
// ---------------------------------------------------------------------------

/** A fake page. Every call a caller can make on it is counted, so "untouched" is a number. */
function fakePage(world, name, opts = {}) {
  const page = {
    name,
    targetId: opts.targetId || `target-${++world.targetSeq}`,
    closed: false,
    calls: { goto: [], close: 0, isClosed: 0, newCDPSession: 0, opener: 0 },
  };
  page.urlValue = opts.url || `http://127.0.0.1:9/${name}`;
  page.url = () => page.urlValue;
  page.isClosed = () => {
    page.calls.isClosed += 1;
    return page.closed;
  };
  page.goto = async (target) => {
    page.calls.goto.push(target);
    if (opts.gotoNeverAnswers) return new Promise(() => {});
    await new Promise((r) => setTimeout(r, 0));
    // A goto that resolves without the about:blank commit ever showing is the fail-closed
    // case the cleanup must never close a page for.
    if (opts.gotoCommits !== false) page.urlValue = target;
  };
  page.close = async () => {
    page.calls.close += 1;
    page.closed = true;
  };
  page.opener = async () => {
    page.calls.opener += 1;
    return null;
  };
  // `attachDenyAllSession` goes through `page.context().newCDPSession(page)`; the
  // ownership's own target-id lookup does too. Both are counted on the page they name.
  page.context = () => ({
    async newCDPSession(target) {
      const counted = target && target.calls ? target : page;
      counted.calls.newCDPSession += 1;
      return {
        on() {},
        async send(method) {
          if (method === "Target.getTargetInfo") return { targetInfo: { targetId: counted.targetId } };
          return {};
        },
        async detach() {},
      };
    },
  });
  return page;
}

/**
 * A fake BrowserContext (an EventEmitter, like Playwright's) whose calls are counted, and
 * a world-level counter for the browser session and the crash.
 */
function makeWorld(opts = {}) {
  const world = {
    targetSeq: 0,
    pages: [],
    counters: { getter: 0, pages: 0, browser: 0, browserSessions: 0, newPage: 0, crashSends: [] },
  };
  const context = new EventEmitter();
  world.context = context;
  world.addPage = (name, pageOpts = {}) => {
    const page = fakePage(world, name, pageOpts);
    world.pages.push(page);
    return page;
  };
  context.pages = () => {
    world.counters.pages += 1;
    return world.pages.slice();
  };
  context.newPage = async () => {
    world.counters.newPage += 1;
    if (opts.failNewPage) throw new Error("no new page: the browser is going");
    return world.addPage(`survivor-${world.counters.newPage}`, { url: "about:blank" });
  };
  context.newCDPSession = async (page) => {
    if (page && page.calls) page.calls.newCDPSession += 1;
    return {
      async send(method) {
        if (method === "Target.getTargetInfo") return { targetInfo: { targetId: page ? page.targetId : null } };
        return {};
      },
      async detach() {},
    };
  };
  context.browser = () => {
    world.counters.browser += 1;
    return {
      async newBrowserCDPSession() {
        world.counters.browserSessions += 1;
        return {
          async send(method) {
            world.counters.crashSends.push(method);
          },
          async detach() {},
        };
      },
    };
  };
  return world;
}

/** The getter a registration gets: it counts, so "the context was never asked" is a number. */
const countingGetter = (world) => () => {
  world.counters.getter += 1;
  return world.context;
};

/** Every count back to zero, taken after the setup (a mark's own target lookup) has settled. */
function resetCounters(world) {
  world.counters.getter = 0;
  world.counters.pages = 0;
  world.counters.browser = 0;
  world.counters.browserSessions = 0;
  world.counters.newPage = 0;
  world.counters.crashSends.length = 0;
  for (const page of world.pages) {
    page.calls.goto.length = 0;
    page.calls.close = 0;
    page.calls.isClosed = 0;
    page.calls.newCDPSession = 0;
    page.calls.opener = 0;
  }
}

/** The cleanup left the whole world alone: no context read, no session, no page touch, no crash. */
function assertUntouched(world, label) {
  assert.equal(world.counters.getter, 0, `${label}: the cleanup never even asked for the context`);
  assert.equal(world.counters.pages, 0, `${label}: the context's page list was never read`);
  assert.equal(world.counters.browser, 0, `${label}: the browser was never asked for a session`);
  assert.equal(world.counters.browserSessions, 0, `${label}: no browser-level CDP session was opened`);
  assert.equal(world.counters.newPage, 0, `${label}: no survivor page was made`);
  assert.deepEqual(world.counters.crashSends, [], `${label}: no Browser.crash was sent`);
  for (const page of world.pages) {
    assert.deepEqual(page.calls.goto, [], `${label}: page ${page.name} was never navigated`);
    assert.equal(page.calls.close, 0, `${label}: page ${page.name} was never closed`);
    assert.equal(page.calls.isClosed, 0, `${label}: page ${page.name} was never probed`);
    assert.equal(page.calls.newCDPSession, 0, `${label}: page ${page.name} was never given a CDP session`);
    assert.equal(page.calls.opener, 0, `${label}: page ${page.name}'s opener was never read`);
  }
}

/** The page saw nothing at all: the operator's tab, and a survivor the cleanup made. */
function assertPageUntouched(page, label) {
  assert.deepEqual(page.calls.goto, [], `${label}: page ${page.name} was never navigated`);
  assert.equal(page.calls.close, 0, `${label}: page ${page.name} was never closed`);
  assert.equal(page.calls.isClosed, 0, `${label}: page ${page.name} was never probed`);
  assert.equal(page.calls.newCDPSession, 0, `${label}: page ${page.name} was never given a CDP session`);
  assert.equal(page.calls.opener, 0, `${label}: page ${page.name}'s opener was never read`);
}

/**
 * One registration on its own fake proc, run the way the exit runs it: stdin closes. The
 * option is only passed when the caller names it, so "no relayOwnsCleanup at all" is a case.
 */
async function runExitCleanup(world, options = {}) {
  const proc = new EventEmitter();
  proc.stdin = new EventEmitter();
  const settings = { proc, budgetMs: 2000 };
  if (options.budgetMs !== undefined) settings.budgetMs = options.budgetMs;
  if (options.ownership) settings.ownership = options.ownership;
  if (options.relayOwnsCleanup !== undefined) settings.relayOwnsCleanup = options.relayOwnsCleanup;
  const run = blankPagesOnExit(countingGetter(world), settings);
  proc.stdin.emit("close");
  return run();
}

/** Collect every `console.error` line written while `work` runs. */
async function captureErrorLines(work) {
  const lines = [];
  const original = console.error;
  console.error = (...args) => {
    lines.push(args.map((arg) => (typeof arg === "string" ? arg : String(arg))).join(" "));
  };
  try {
    await work();
  } finally {
    console.error = original;
  }
  return lines;
}

/** An ownership whose context is attached and whose named page is the bot's. */
async function ownershipWithBotPage(world, botPage) {
  const ownership = createPageOwnership();
  await ownership.attachContext(world.context);
  ownership.markOpened(botPage);
  // The mark's target-id lookup is asynchronous: let it land before the counters are reset.
  await new Promise((r) => setTimeout(r, 20));
  return ownership;
}

// ---------------------------------------------------------------------------
// 1. the relay owns the cleanup: the normal work still happens, the crash does not
// ---------------------------------------------------------------------------

test("relayOwnsCleanup true: the bot's page is blanked, committed and closed; the operator's page is left alone; no crash", async () => {
  const world = makeWorld();
  const operator = world.addPage("operator");
  const bot = world.addPage("bot");
  const ownership = await ownershipWithBotPage(world, bot);
  resetCounters(world);

  let asked = 0;
  const lines = await captureErrorLines(() => runExitCleanup(world, {
    ownership,
    relayOwnsCleanup: () => {
      asked += 1;
      return true;
    },
  }));

  assert.equal(asked, 1, "the seam is asked once for the pair, before anything is touched");
  assert.deepEqual(bot.calls.goto, ["about:blank"], "the bot's page is still blanked: the relay only finishes the job when this connection ENDS");
  assert.equal(bot.calls.close, 1, "and closed once its blank had committed");
  assert.deepEqual(world.counters.crashSends, [], "a relay-owned run never sends Browser.crash");
  assert.equal(world.counters.newPage, 0, "an operator page keeps the browser alive, so the normal path makes no survivor");
  assertPageUntouched(operator, "relay-owned pair");
  assert.deepEqual(lines, [], "the ordinary path needs no explanation line");
});

test("relayOwnsCleanup true and only the bot's page: the normal path runs (survivor, blank, close), still no crash", async () => {
  const world = makeWorld();
  const bot = world.addPage("bot");
  const ownership = await ownershipWithBotPage(world, bot);
  resetCounters(world);

  await runExitCleanup(world, { ownership, relayOwnsCleanup: () => true });

  assert.equal(world.counters.newPage, 1, "every live page is the bot's, so the normal path makes ONE survivor");
  const survivor = world.pages.find((page) => page.name.startsWith("survivor-"));
  assert.ok(survivor, "the survivor page was made");
  assertPageUntouched(survivor, "relay-owned pair");
  assert.deepEqual(bot.calls.goto, ["about:blank"], "the bot's page is blanked");
  assert.equal(bot.calls.close, 1, "and closed after its grace");
  assert.deepEqual(world.counters.crashSends, [], "a relay-owned run never sends Browser.crash");
});

test("relayOwnsCleanup true and context.newPage() rejects: no crash, no page touched, one line, and the cleanup resolves", async () => {
  const world = makeWorld({ failNewPage: true });
  const bot = world.addPage("bot");
  const ownership = await ownershipWithBotPage(world, bot);
  resetCounters(world);

  let resolved = false;
  const lines = await captureErrorLines(async () => {
    await runExitCleanup(world, { ownership, relayOwnsCleanup: () => true });
    resolved = true;
  });

  assert.equal(resolved, true, "the cleanup promise resolves: the process exits and its connection closes");
  assert.deepEqual(world.counters.crashSends, [], "no Browser.crash is ever sent for a relay-owned run");
  assert.equal(world.counters.newPage, 1, "the survivor WAS attempted: that is the step that failed");
  assert.deepEqual(bot.calls.goto, [], "the abandoned cleanup does no further page work");
  assert.equal(bot.calls.close, 0, "and closes no page");
  assert.equal(lines.length, 1, `exactly one log line (got ${JSON.stringify(lines)})`);
  assert.match(lines[0], /the relay owns the cleanup: leaving the rest to it/);
});

test("relayOwnsCleanup true and a blank does not commit: no crash, that page is not closed, the cleanup resolves", async () => {
  const world = makeWorld();
  const bot = world.addPage("bot", { gotoCommits: false, url: "http://127.0.0.1:9/bot" });
  const ownership = await ownershipWithBotPage(world, bot);
  resetCounters(world);

  let resolved = false;
  const lines = await captureErrorLines(async () => {
    await runExitCleanup(world, { ownership, relayOwnsCleanup: () => true });
    resolved = true;
  });

  assert.equal(resolved, true, "the cleanup promise resolves");
  assert.deepEqual(bot.calls.goto, ["about:blank"], "the blank was attempted");
  assert.equal(bot.calls.close, 0, "a page whose blank never committed is NEVER closed");
  assert.deepEqual(world.counters.crashSends, [], "and the browser is not crashed either");
  const survivor = world.pages.find((page) => page.name.startsWith("survivor-"));
  assert.ok(survivor, "the normal path made its survivor before the blank");
  assertPageUntouched(survivor, "relay-owned pair");
  assert.equal(lines.length, 1, `exactly one log line (got ${JSON.stringify(lines)})`);
  assert.match(lines[0], /the relay owns the cleanup: leaving the rest to it/);
});

test("relayOwnsCleanup true and the budget expires with pages armed: no crash, the cleanup resolves", async () => {
  const world = makeWorld();
  const bot = world.addPage("bot", { gotoNeverAnswers: true });
  const ownership = await ownershipWithBotPage(world, bot);
  resetCounters(world);

  let resolved = false;
  const started = Date.now();
  const lines = await captureErrorLines(async () => {
    await runExitCleanup(world, { ownership, budgetMs: 50, relayOwnsCleanup: () => true });
    resolved = true;
  });
  const took = Date.now() - started;

  assert.equal(resolved, true, "the cleanup promise resolves");
  assert.deepEqual(world.counters.crashSends, [], "a budget that expires on a relay-owned run does not crash the browser");
  assert.equal(bot.calls.close, 0, "the page behind the stuck blank is never closed");
  assert.ok(took < 1000, `the abandoned cleanup let the budget end it (took ${took} ms)`);
  assert.equal(lines.length, 1, `exactly one log line (got ${JSON.stringify(lines)})`);
  assert.match(lines[0], /the relay owns the cleanup: leaving the rest to it/);
});

// ---------------------------------------------------------------------------
// 2. the fail-safe: every other answer keeps the old blank-and-crash behaviour
// ---------------------------------------------------------------------------

test("no relayOwnsCleanup option: a bot page is still blanked and closed (the fallback stays)", async () => {
  const world = makeWorld();
  const operator = world.addPage("operator");
  const ownership = createPageOwnership();
  await ownership.attachContext(world.context);
  const bot = world.addPage("bot");
  ownership.markOpened(bot);
  await new Promise((r) => setTimeout(r, 20));
  resetCounters(world);

  await runExitCleanup(world, { ownership });

  assert.deepEqual(bot.calls.goto, ["about:blank"], "without the seam the bot page is blanked, exactly as before");
  assert.equal(bot.calls.close, 1, "and closed after its grace");
  assert.equal(operator.calls.goto.length, 0, "the operator's tab is still never navigated");
  assert.equal(operator.calls.close, 0, "and never closed");
  assert.deepEqual(world.counters.crashSends, [], "the blank committed: no crash");
});

test("every fail-safe answer (false, yes, 1, undefined, throws, missing) still fails closed with the crash", async () => {
  const variants = [
    ["returns false", () => false],
    ["returns \"yes\"", () => "yes"],
    ["returns 1", () => 1],
    ["returns undefined", () => undefined],
    ["throws", () => { throw new Error("the relay seam is broken"); }],
    ["missing", undefined],
  ];

  for (const [label, seam] of variants) {
    // No survivor can be made, so the old path has to end in Browser.crash.
    const world = makeWorld({ failNewPage: true });
    const bot = world.addPage("bot");
    const ownership = await ownershipWithBotPage(world, bot);
    resetCounters(world);

    const options = { ownership };
    if (seam !== undefined) options.relayOwnsCleanup = seam;
    await runExitCleanup(world, options);

    assert.deepEqual(
      world.counters.crashSends,
      ["Browser.crash"],
      `${label}: the old fail-closed path has to run (a survivor that cannot be made means the crash)`,
    );
    assert.equal(bot.calls.close, 0, `${label}: a page is never closed on that path`);
  }
});

test("a MIXED set of pairs (one relay-owned, one not) keeps the crash: one non-relay pair is enough", async () => {
  // The relay-owned pair does its normal work and would never crash; the other pair's
  // failing survivor still has to, because its connection is not the relay's.
  const relayWorld = makeWorld();
  relayWorld.addPage("operator");
  const relayBot = relayWorld.addPage("bot");
  const relayOwnership = await ownershipWithBotPage(relayWorld, relayBot);
  resetCounters(relayWorld);

  const otherWorld = makeWorld({ failNewPage: true });
  const otherBot = otherWorld.addPage("bot");
  const otherOwnership = await ownershipWithBotPage(otherWorld, otherBot);
  resetCounters(otherWorld);

  const proc = new EventEmitter();
  proc.stdin = new EventEmitter();
  const run = blankPagesOnExit(countingGetter(relayWorld), {
    proc,
    budgetMs: 2000,
    ownership: relayOwnership,
    relayOwnsCleanup: () => true,
  });
  blankPagesOnExit(countingGetter(otherWorld), { proc, budgetMs: 2000, ownership: otherOwnership });
  proc.stdin.emit("close");
  await run();

  assert.deepEqual(
    otherWorld.counters.crashSends,
    ["Browser.crash"],
    "the pair without a relay still fails closed with the crash",
  );
  assert.deepEqual(relayWorld.counters.crashSends, [], "the relay-owned pair never sends one itself");
  assert.deepEqual(relayBot.calls.goto, ["about:blank"], "and it still did its normal work");
  assert.equal(relayBot.calls.close, 1, "including the close of the bot's page");
});

// ---------------------------------------------------------------------------
// 3. a re-registration (a reconnect) replaces the seam on the pair it already has
// ---------------------------------------------------------------------------

test("re-registering the same server replaces the seam, so a reconnect's answer is the one used", async () => {
  const world = makeWorld({ failNewPage: true });
  const bot = world.addPage("bot");
  const ownership = await ownershipWithBotPage(world, bot);
  resetCounters(world);

  const proc = new EventEmitter();
  proc.stdin = new EventEmitter();
  // The first connection: the declaration was refused, so the cleanup is this process's
  // (its failing survivor would crash the browser).
  const run = blankPagesOnExit(countingGetter(world), {
    proc,
    budgetMs: 2000,
    ownership,
    relayOwnsCleanup: () => false,
  });
  // The reconnect: the relay accepted the declaration on THIS connection.
  blankPagesOnExit(countingGetter(world), {
    proc,
    budgetMs: 2000,
    ownership,
    relayOwnsCleanup: () => true,
  });
  resetCounters(world);

  const lines = await captureErrorLines(async () => {
    proc.stdin.emit("close");
    await run();
  });

  assert.deepEqual(world.counters.crashSends, [], "the reconnect's answer (true) is the one used: no crash");
  assert.equal(world.counters.newPage, 1, "the normal path ran up to the survivor it could not make");
  assert.equal(bot.calls.close, 0, "no page is closed");
  assert.equal(lines.length, 1, `exactly one log line (got ${JSON.stringify(lines)})`);
  assert.match(lines[0], /the relay owns the cleanup: leaving the rest to it/);
});

// ---------------------------------------------------------------------------
// 4. server.js's per-connection decision
// ---------------------------------------------------------------------------

test("only sendGuardReady's {ok: true} makes the relay the owner; {ok: false} answers do not", () => {
  const accepted = privateAddress.relayGuardReadyAccepted;
  assert.equal(typeof accepted, "function", "private-address.js exports the decision server.js uses");

  assert.equal(accepted({ ok: true }), true, "{ok: true}: the relay took the declaration");
  assert.equal(accepted({ ok: false, unsupported: true }), false, "a relay older than the gate: not the owner");
  assert.equal(accepted({ ok: false }), false, "no session, or a send that failed: not the owner");
  assert.equal(accepted(undefined), false, "no answer at all: not the owner");
  assert.equal(accepted(null), false);
  assert.equal(accepted({ ok: "true" }), false, "only the boolean true counts");
});

test("a browser that is already gone (or a probe that throws) is never relay-owned at exit time", () => {
  const owns = privateAddress.relayOwnsExitCleanup;
  assert.equal(typeof owns, "function", "private-address.js exports the exit-time decision server.js's closure uses");

  const live = { isConnected: () => true };
  assert.equal(owns(true, live), true, "the connection's declaration was accepted and it is still up");
  assert.equal(owns(false, live), false, "this connection's declaration was not accepted");
  assert.equal(owns(true, { isConnected: () => false }), false, "the connection is gone: the old path runs");
  assert.equal(owns(true, null), false, "no browser: nothing for the relay to clean up");
  assert.equal(owns(true, undefined), false);
  assert.equal(
    owns(true, { isConnected() { throw new Error("the connection is gone"); } }),
    false,
    "a probe that throws proves nothing: the cleanup is this process's",
  );
  assert.equal(owns(true, { isConnected: true }), false, "a non-function probe cannot answer yes");
});

test("server.js: the flag is reset at every (re)connect, set only from sendGuardReady's answer, and handed to the cleanup", () => {
  assert.match(
    SERVER,
    /relayGuardReadyAccepted,\s*\n\s*relayOwnsExitCleanup,\s*\n\} from "\.\/private-address\.js";/,
    "server.js imports both helpers from private-address.js (one decision, one implementation)",
  );

  const start = SERVER.indexOf("async function ensureConnected()");
  assert.ok(start > -1, "ensureConnected is where a connection is made");
  const end = SERVER.indexOf("\n  }\n", start);
  const body = SERVER.slice(start, end > start ? end + 4 : undefined);

  const reset = body.indexOf("relayOwnsCleanupHere = false;");
  const connect = body.indexOf("chromium.connectOverCDP(");
  const send = body.indexOf("sendGuardReady(");
  const set = body.indexOf("relayOwnsCleanupHere = relayGuardReadyAccepted(");
  assert.ok(reset > -1, "the per-connection flag is reset in ensureConnected");
  assert.ok(connect > -1 && reset < connect, "and it is reset at the START of every (re)connect, before the connection is made");
  assert.ok(send > -1, "ensureConnected still sends the declaration");
  assert.ok(set > -1 && set > send, "the flag is set AFTER sendGuardReady resolved");

  assert.ok(
    body.includes("relayOwnsExitCleanup(relayOwnsCleanupHere, browser)"),
    "the cleanup's seam reads the live flag AND whether the connection is still up",
  );
  assert.match(body, /relayOwnsCleanup:\s*\(\)\s*=>\s*\{/, "the seam is a function on blankPagesOnExit's opts");
  assert.ok(
    body.includes("return false;"),
    "the seam returns false when the probe throws (a probe that throws proves nothing)",
  );

  // "Nothing else may set it": the declaration (false), the reset at every (re)connect, and
  // sendGuardReady's answer — three writes, and nothing here reads a gate status, a header,
  // a page or an env var into it.
  assert.equal(
    [...SERVER.matchAll(/relayOwnsCleanupHere = false;/g)].length,
    2,
    "the flag is declared false and reset to false at every (re)connect",
  );
  assert.equal(
    [...SERVER.matchAll(/relayOwnsCleanupHere = relayGuardReadyAccepted\(/g)].length,
    1,
    "its one true-valued write is sendGuardReady's answer",
  );
  assert.equal(
    [...SERVER.matchAll(/relayOwnsCleanupHere\s*=(?!=)/g)].length,
    3,
    "nothing else may set the flag: the declaration, the reset and the sendGuardReady answer, and no other write",
  );
});