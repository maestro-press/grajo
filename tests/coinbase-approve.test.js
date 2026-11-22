/**
 * The Trading panel's AI-order previews: the card that shows exactly what will be placed, the
 * approval that places it once, and the "Not now" that places nothing.
 *
 * Everything runs through the real express app the harness builds (the real JSON body parser, the
 * real auth seam, the real CSRF middleware), against one scratch Crow home and one fake trading
 * engine on loopback. The fake keeps the pin, logs every request with the key its MAC was signed
 * with (`record.mac`: "owner", "install" or "none"), and can be scripted to answer a route from a
 * test. The step-up gate is the real one with its two seams injected, so its own replay guard and
 * its own lockout are what the routes meet: a code accepted once is refused the second time.
 *
 * The approve route is privileged (local password session + 2FA on + a fresh code); the reject
 * route is local session only. Every seeded preview, hash and amount below is a test figure, and
 * the scratch directories are removed in `after()`.
 *
 * The two unit tests at the bottom exercise `bundles/coinbase/panel/approve.js` directly, with a
 * stub client, so a refusal that never reaches the engine is checked without an engine at all.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";

import {
  scaffold,
  cleanupScratch,
  createFakeEngine,
  fakePreview,
  renderPanelPage,
  waitFor,
  ENGINE_TOKEN,
  LOCAL_LOGIN_CODE,
  LOCAL_LOGIN_MESSAGE,
  TWO_FACTOR_MESSAGE,
  TOTP_REQUIRED_MESSAGE,
} from "./helpers/coinbase-panel-harness.mjs";
import { createEngineClient } from "../bundles/coinbase/server/engine-client.js";

// The copy the panel owes the owner, in one place.
const APPROVE_MESSAGE = "Approved. Placing your order now.";
const REJECT_MESSAGE = "Okay, not now.";
const GONE_MESSAGE = "That proposal is gone. Ask again.";
const NOT_PENDING_MESSAGE = "That proposal is no longer waiting for you.";
const EXPIRED_MESSAGE = "This proposal expired. Ask again.";
const CHANGED_MESSAGE = "This proposal changed. Look at it again before approving.";
const LIVE_LINE = "Live: real money";
const PRACTICE_LINE = "Practice: no real money";
const RESTING_LINE = "It rests on the order book and fills only at that price or better.";

// The clock the route tests inject. `createPanelRoutes` takes a millisecond clock; approve.js
// dates a preview against epoch seconds.
const NOW_MS = 1_700_003_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);

// `approve.js` does not exist yet: loading it inside the tests that need it keeps every other
// test able to run (and to fail on its own).
let approveModule = null;
async function approveApi() {
  if (!approveModule) approveModule = await import("../bundles/coinbase/panel/approve.js");
  return approveModule;
}

function approvePath(id) {
  return `/api/coinbase/previews/${encodeURIComponent(id)}/approve`;
}

function rejectPath(id) {
  return `/api/coinbase/previews/${encodeURIComponent(id)}/reject`;
}

/** Every request the engine answered with a POST to one preview's approve route. */
function engineApproveCalls(h) {
  return h.fake.state.requests.filter(
    (record) => record.method === "POST" && /^\/ai\/previews\/[^/]+\/approve$/.test(String(record.path)),
  );
}

/** Every request the engine answered with a POST to one preview's reject route. */
function engineRejectCalls(h) {
  return h.fake.state.requests.filter(
    (record) => record.method === "POST" && /^\/ai\/previews\/[^/]+\/reject$/.test(String(record.path)),
  );
}

/** The engine requests recorded after `mark`, POSTs only. */
function postsAfter(h, mark) {
  return h.fake.state.requests.slice(mark).filter((record) => record.method === "POST");
}

/** A panel install with one connection standing, so the owner's secret can sign a call. */
async function connected(options = {}) {
  const h = await scaffold(options);
  const answer = await h.connect();
  assert.equal(answer.status, 200, `the scaffold could not connect: ${answer.text}`);
  assert.equal(h.fake.state.credentials, "ready");
  return h;
}

after(() => {
  cleanupScratch();
});

// ---- the gates ---------------------------------------------------------------------------------

test("test_approve_requires_step_up_and_local_session", async () => {
  const h = await connected();
  try {
    const row = fakePreview({ preview_id: "pv-gate", hash: "1".repeat(64) });
    h.fake.state.previews = [row];
    const path = approvePath(row.preview_id);

    // A peer sign-in is not enough, whatever else the request carries.
    h.flags.isLocal = false;
    const peer = await h.post(path, { hash: row.hash, totp: h.freshCode() });
    assert.equal(peer.status, 403);
    assert.equal(peer.json?.code, LOCAL_LOGIN_CODE);
    assert.equal(peer.json?.message, LOCAL_LOGIN_MESSAGE);

    // A local session, but two-factor sign-in is off: refused before any code is looked at.
    h.flags.isLocal = true;
    h.flags.twoFactor = false;
    const noTwoFactor = await h.post(path, { hash: row.hash, totp: h.freshCode() });
    assert.equal(noTwoFactor.status, 403);
    assert.equal(noTwoFactor.json?.code, "two_factor_required");
    assert.equal(noTwoFactor.json?.message, TWO_FACTOR_MESSAGE);

    // Two-factor on, no code in the body: refused.
    h.flags.twoFactor = true;
    const noCode = await h.post(path, { hash: row.hash });
    assert.equal(noCode.status, 403);
    assert.equal(noCode.json?.code, "totp_required");
    assert.equal(noCode.json?.message, TOTP_REQUIRED_MESSAGE);

    // A code that matches no time step: refused too.
    const wrongCode = await h.post(path, { hash: row.hash, totp: "000000" });
    assert.equal(wrongCode.status, 403);
    assert.equal(wrongCode.json?.code, "totp_required");
    assert.equal(wrongCode.json?.message, TOTP_REQUIRED_MESSAGE);

    // None of that reached the engine, and the preview is still waiting.
    assert.equal(engineApproveCalls(h).length, 0);
    assert.equal(row.state, "pending");
  } finally {
    await h.close();
  }
});

// ---- one approval, one order --------------------------------------------------------------------

test("test_approve_with_fresh_code_places_once", async () => {
  const h = await connected();
  try {
    const first = fakePreview({ preview_id: "pv-one", hash: "2".repeat(64) });
    const second = fakePreview({ preview_id: "pv-two", hash: "3".repeat(64) });
    h.fake.state.previews = [first, second];

    const mark = h.fake.state.requests.length;
    const code = h.freshCode();
    const answer = await h.post(approvePath(first.preview_id), { hash: first.hash, totp: code });

    assert.equal(answer.status, 200);
    assert.equal(answer.json?.ok, true);
    assert.equal(answer.json?.message, APPROVE_MESSAGE);

    const posts = postsAfter(h, mark);
    assert.equal(posts.length, 1, "an approval sends one request to the engine and nothing else");
    assert.equal(posts[0].path, `/ai/previews/${first.preview_id}/approve`);
    assert.equal(posts[0].mac, "owner", "the approval is signed with the sealed owner secret");
    assert.deepEqual(JSON.parse(posts[0].body), { hash: first.hash });
    assert.equal(first.state, "placed");

    // The same code, a second approval: the gate refuses the replay and the engine hears nothing.
    const beforeReplay = h.fake.state.requests.length;
    const replay = await h.post(approvePath(second.preview_id), { hash: second.hash, totp: code });
    assert.equal(replay.status, 403);
    assert.equal(replay.json?.ok, false);
    assert.equal(replay.json?.code, "totp_required");
    assert.equal(postsAfter(h, beforeReplay).length, 0);
    assert.equal(second.state, "pending");
  } finally {
    await h.close();
  }
});

// ---- what the card says, and that the approval approves exactly that ----------------------------

test("test_approve_shows_exactly_what_will_be_placed", async () => {
  const h = await connected({ seams: { now: () => NOW_MS } });
  try {
    const row = fakePreview({
      preview_id: "pv-shown",
      hash: "4".repeat(64),
      book: "live",
      side: "BUY",
      product: "BTC-USDC",
      size: "0.00100000",
      limit_price: "60000.00",
      requested_limit_price: "60000.00",
      notional: "60.00",
      limits: [{ name: "ai_max_order_usd", limit: "25.00", used_after: "60.00" }],
      created_at: NOW_S - 10,
      expires_at: NOW_S + 120,
    });
    h.fake.state.previews = [row];

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200);
    const shown = (panel.json?.previews || []).find((entry) => entry.preview_id === row.preview_id);
    assert.ok(shown, "the pending preview is on the panel");

    const summary = String(shown.summary ?? "");
    const lines = Array.isArray(shown.lines) ? shown.lines.map(String) : [];
    assert.match(summary, /buy/i, "the sentence says which side");
    assert.ok(summary.includes("0.0010"), `the size keeps its digits: ${summary}`);
    assert.ok(summary.includes("BTC-USDC"), "the sentence names the product");
    assert.ok(summary.includes("60000.00"), "the sentence carries the limit price");
    assert.ok(summary.includes("60.00"), "the sentence carries the notional");

    assert.equal(shown.book, "live");
    assert.equal(shown.badge, "LIVE");
    assert.ok(lines.includes(LIVE_LINE), "a live order says it is real money");
    assert.ok(!lines.includes(PRACTICE_LINE));
    assert.ok(lines.includes(RESTING_LINE), "the card says how the order fills");
    assert.ok(lines.join(" | ").includes("25.00"), "the engine's own limit is on the card");

    // The countdown is measured against the injected clock, not the wall clock.
    assert.equal(shown.seconds_left, 120);
    assert.equal(shown.hash, row.hash);
    assert.equal(shown.can_approve, true);

    // The sentence described the numbers the approval is for.
    const mark = h.fake.state.requests.length;
    const answer = await h.post(approvePath(row.preview_id), { hash: shown.hash, totp: h.freshCode() });
    assert.equal(answer.status, 200);
    const posts = postsAfter(h, mark);
    assert.equal(posts.length, 1);
    assert.deepEqual(JSON.parse(posts[0].body), { hash: shown.hash });
    assert.equal(shown.hash, row.hash);
    assert.equal(row.limit_price, "60000.00", "the panel never rewrote the price it showed");
    assert.equal(row.size, "0.00100000");
  } finally {
    await h.close();
  }
});

// ---- refusals that never reach the engine ------------------------------------------------------

test("test_approve_after_expiry_refused", async () => {
  const h = await connected({ seams: { now: () => NOW_MS } });
  try {
    const row = fakePreview({
      preview_id: "pv-late",
      hash: "5".repeat(64),
      created_at: NOW_S - 900,
      expires_at: NOW_S - 300,
    });
    h.fake.state.previews = [row];

    const answer = await h.post(approvePath(row.preview_id), { hash: row.hash, totp: h.freshCode() });
    assert.equal(answer.status, 409);
    assert.equal(answer.json?.ok, false);
    assert.equal(answer.json?.code, "expired");
    assert.equal(answer.json?.message, EXPIRED_MESSAGE);
    assert.equal(engineApproveCalls(h).length, 0, "an expired proposal places nothing");
    assert.equal(row.state, "pending");
  } finally {
    await h.close();
  }
});

test("test_approve_hash_changed_refused", async () => {
  const h = await connected();
  try {
    const row = fakePreview({ preview_id: "pv-moved", hash: "6".repeat(64) });
    h.fake.state.previews = [row];
    const staleHash = "7".repeat(64);

    const answer = await h.post(approvePath(row.preview_id), { hash: staleHash, totp: h.freshCode() });
    assert.equal(answer.status, 409);
    assert.equal(answer.json?.ok, false);
    assert.equal(answer.json?.code, "changed");
    assert.equal(answer.json?.message, CHANGED_MESSAGE);

    // The stale hash is never forwarded, and the price the owner no longer saw is never placed.
    assert.equal(engineApproveCalls(h).length, 0);
    assert.equal(row.state, "pending");
  } finally {
    await h.close();
  }
});

test("test_approve_not_pending_refused", async () => {
  const h = await connected();
  try {
    const placed = fakePreview({ preview_id: "pv-placed", hash: "8".repeat(64), state: "placed" });
    const rejected = fakePreview({ preview_id: "pv-rejected", hash: "9".repeat(64), state: "rejected" });
    const expired = fakePreview({ preview_id: "pv-expired", hash: "a".repeat(64), state: "expired" });
    h.fake.state.previews = [placed, rejected, expired];

    for (const row of [placed, rejected, expired]) {
      const answer = await h.post(approvePath(row.preview_id), { hash: row.hash, totp: h.freshCode() });
      assert.equal(answer.status, 409, `a ${row.state} proposal answers a conflict`);
      assert.equal(answer.json?.ok, false);
      assert.equal(answer.json?.code, "not_pending");
      assert.equal(answer.json?.message, NOT_PENDING_MESSAGE);
    }

    const gone = await h.post(approvePath("pv-nobody"), { hash: "b".repeat(64), totp: h.freshCode() });
    assert.equal(gone.status, 404);
    assert.equal(gone.json?.ok, false);
    assert.equal(gone.json?.code, "not_found");
    assert.equal(gone.json?.message, GONE_MESSAGE);

    assert.equal(engineApproveCalls(h).length, 0);
  } finally {
    await h.close();
  }
});

test("test_approve_engine_refusal_passes_plain_message", async () => {
  const h = await connected();
  try {
    const row = fakePreview({ preview_id: "pv-book", hash: "c".repeat(64) });
    h.fake.state.previews = [row];
    const engineMessage = "The book for AI orders changed; ask again.";
    h.fake.next("POST", `/ai/previews/${row.preview_id}/approve`, {
      status: 409,
      body: { code: "BOOK_CHANGED", message: engineMessage },
    });

    const answer = await h.post(approvePath(row.preview_id), { hash: row.hash, totp: h.freshCode() });
    assert.equal(answer.status, 409);
    assert.equal(answer.json?.ok, false);
    assert.equal(answer.json?.message, engineMessage, "the engine's sentence reaches the owner unchanged");
    assert.equal(answer.json?.code, "BOOK_CHANGED", "the machine code stays in its own field");
    assert.ok(
      !String(answer.json?.message ?? "").includes("BOOK_CHANGED"),
      "the raw code is not pasted into the sentence",
    );
    assert.equal(row.state, "pending");
  } finally {
    await h.close();
  }
});

// ---- the panel never reprices ------------------------------------------------------------------

/**
 * The engine client as the panel sees it, with the money fields of every listed preview pinned
 * read-only: a panel that tries to rewrite `limit_price`, `size` or `notional` throws instead of
 * showing a number the approval would not carry. `seen` keeps every row handed to the panel, so a
 * test can show what went into the description.
 */
function previewDescribingSpy(real, seen) {
  return {
    ...real,
    async aiPreviews(params) {
      const result = await real.aiPreviews(params);
      if (result && result.ok && Array.isArray(result.data)) {
        for (const row of result.data) {
          if (!row || typeof row !== "object") continue;
          seen.push(row);
          for (const field of ["limit_price", "size", "notional"]) {
            if (!Object.hasOwn(row, field)) continue;
            Object.defineProperty(row, field, {
              value: row[field],
              writable: false,
              enumerable: true,
              configurable: false,
            });
          }
        }
      }
      return result;
    },
  };
}

test("test_approve_never_reprices", async () => {
  const fake = await createFakeEngine();
  const seen = [];
  const h = await scaffold({
    fake,
    engineClientFactory: ({ secretProvider }) => previewDescribingSpy(
      createEngineClient({ baseUrl: fake.baseUrl, token: ENGINE_TOKEN, secretProvider }),
      seen,
    ),
  });
  try {
    assert.equal((await h.connect()).status, 200);
    const row = fakePreview({
      preview_id: "pv-price",
      hash: "d".repeat(64),
      size: "0.00100000",
      limit_price: "60000.00",
      requested_limit_price: "60000.00",
      notional: "60.00",
    });
    fake.state.previews = [row];

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200);
    const shown = (panel.json?.previews || [])[0];
    assert.ok(shown);
    assert.ok(String(shown.summary).includes("60000.00"));

    const mark = fake.state.requests.length;
    const answer = await h.post(approvePath(row.preview_id), { hash: shown.hash, totp: h.freshCode() });
    assert.equal(answer.status, 200);

    const posts = postsAfter(h, mark);
    assert.equal(posts.length, 1);
    const body = JSON.parse(posts[0].body);
    assert.deepEqual(Object.keys(body), ["hash"], "the approval carries the hash and no money at all");
    for (const field of ["price", "limit_price", "size", "notional", "requested_limit_price"]) {
      assert.equal(Object.hasOwn(body, field), false, `the approval body carries no ${field}`);
    }

    // What was described is what the engine listed: no price or size was edited on the way.
    assert.ok(seen.length > 0, "the panel read the listing before describing it");
    for (const listed of seen) {
      assert.equal(listed.limit_price, row.limit_price);
      assert.equal(listed.size, row.size);
      assert.equal(listed.notional, row.notional);
    }
  } finally {
    await h.close();
  }
});

// ---- two taps, one order -----------------------------------------------------------------------

test("test_double_tap_approve_one_order", async () => {
  const h = await connected();
  try {
    const row = fakePreview({ preview_id: "pv-tap", hash: "e".repeat(64) });
    h.fake.state.previews = [row];

    const codeA = h.freshCode();
    const codeB = h.freshCode();
    // Whatever order the two taps arrive in, only one of them can be accepted: the engine answers
    // the other with its own not-pending refusal.
    h.fake.next("POST", `/ai/previews/${row.preview_id}/approve`, {
      status: 409,
      body: { code: "NOT_PENDING", message: NOT_PENDING_MESSAGE },
    });
    // Hold the first approval at the engine so the second tap starts after it has its code in.
    const held = h.fake.holdNext("POST", `/ai/previews/${row.preview_id}/approve`);
    const first = h.post(approvePath(row.preview_id), { hash: row.hash, totp: codeA });
    const reached = await waitFor(() => h.fake.state.requests.some(
      (record) => record.method === "POST" && record.path === `/ai/previews/${row.preview_id}/approve`,
    ));
    held.release();
    assert.ok(reached, "the first tap reached the engine");
    const second = h.post(approvePath(row.preview_id), { hash: row.hash, totp: codeB });

    const [a, b] = await Promise.all([first, second]);
    const answers = [a, b];
    const successes = answers.filter((answer) => answer.status === 200 && answer.json?.ok === true);
    const refusals = answers.filter((answer) => answer.status === 409 && answer.json?.ok === false);

    assert.equal(successes.length, 1, "one tap places the order");
    assert.equal(successes[0].json?.message, APPROVE_MESSAGE);
    assert.equal(refusals.length, 1, "the other tap is refused");
    assert.equal(refusals[0].json?.message, NOT_PENDING_MESSAGE);
    assert.equal(row.state, "placed", "one order, not two");
    assert.ok(engineApproveCalls(h).length <= 2);
  } finally {
    await h.close();
  }
});

// ---- rejecting needs no code -------------------------------------------------------------------

test("test_reject_needs_only_local_session", async () => {
  const h = await scaffold({ twoFactor: false });
  try {
    const first = fakePreview({ preview_id: "pv-no-now", hash: "f".repeat(64) });
    const second = fakePreview({ preview_id: "pv-no-now-2", hash: "1a".repeat(32) });
    h.fake.state.previews = [first, second];

    // Two-factor sign-in is off and no code is sent: the "Not now" still works.
    const answer = await h.post(rejectPath(first.preview_id), {});
    assert.equal(answer.status, 200);
    assert.equal(answer.json?.ok, true);
    assert.equal(answer.json?.message, REJECT_MESSAGE);

    const rejects = engineRejectCalls(h);
    assert.equal(rejects.length, 1);
    assert.equal(rejects[0].path, `/ai/previews/${first.preview_id}/reject`);
    assert.equal(rejects[0].headers.authorization, `Bearer ${ENGINE_TOKEN}`);
    assert.equal(rejects[0].mac, "none", "a reject needs no approval signature");
    assert.equal(first.state, "rejected");

    // A peer sign-in is refused, and nothing reaches the engine.
    h.flags.isLocal = false;
    const peer = await h.post(rejectPath(second.preview_id), {});
    assert.equal(peer.status, 403);
    assert.equal(peer.json?.code, LOCAL_LOGIN_CODE);
    assert.equal(peer.json?.message, LOCAL_LOGIN_MESSAGE);
    assert.equal(engineRejectCalls(h).length, 1);
    assert.equal(second.state, "pending");
  } finally {
    await h.close();
  }
});

// ---- the page ----------------------------------------------------------------------------------

test("test_preview_deep_link_focus", async () => {
  const safe = await renderPanelPage({ query: { preview: "pv-focus-1" } });
  const safeText = `${safe.content}\n${safe.scripts}`;
  assert.ok(safeText.includes("pv-focus-1"), "the asked-for preview reaches the page's own script");

  const hostile = '"><script>alert(1)</script>';
  const escaped = await renderPanelPage({ query: { preview: hostile } });
  const escapedText = `${escaped.content}\n${escaped.scripts}`;
  assert.ok(!escapedText.includes("<script>alert(1)"), "the id is never injected raw");
  assert.ok(
    /&quot;|&lt;|\\u003c/.test(escapedText),
    "the id is escaped before it reaches the markup or the script",
  );
});

test("test_pending_previews_only_in_cards_and_recent_list", async () => {
  const h = await connected();
  try {
    const waiting = [
      fakePreview({ preview_id: "pv-wait-1", hash: "2a".repeat(32) }),
      fakePreview({ preview_id: "pv-wait-2", hash: "3b".repeat(32), book: "live", side: "SELL" }),
    ];
    const settled = ["placed", "placed", "rejected", "expired", "rejected", "expired"].map((state, index) =>
      fakePreview({
        preview_id: `pv-done-${index + 1}`,
        hash: String(index + 1).padStart(2, "0").repeat(32),
        state,
      }),
    );
    h.fake.state.previews = [...waiting, ...settled];

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200);
    const previews = panel.json?.previews || [];
    const recent = panel.json?.recent_previews || [];

    assert.deepEqual(
      previews.map((entry) => entry.preview_id).sort(),
      ["pv-wait-1", "pv-wait-2"],
      "only the proposals still waiting are cards",
    );
    for (const entry of previews) {
      assert.equal(entry.state, "pending");
      assert.equal(typeof entry.summary, "string");
      assert.ok(entry.summary.length > 0);
      assert.ok(Array.isArray(entry.lines) && entry.lines.length > 0);
      const text = `${entry.summary} ${entry.lines.join(" ")}`;
      assert.ok(!/NaN|Infinity/.test(text));
      assert.ok(!/\de[+-]?\d/i.test(text), "money is written out, never in exponent notation");
    }

    assert.equal(recent.length, 5, "at most five answered proposals are listed");
    const settledIds = new Set(settled.map((row) => row.preview_id));
    for (const entry of recent) {
      assert.ok(settledIds.has(entry.preview_id), "a card is never repeated in the recent list");
      assert.notEqual(entry.state, "pending");
      assert.equal(typeof entry.summary, "string");
      assert.ok(entry.summary.length > 0);
      assert.ok(!/NaN|Infinity/.test(entry.summary));
      assert.ok(!/\de[+-]?\d/i.test(entry.summary));
      assert.equal(entry.preview_id, String(entry.preview_id));
    }
  } finally {
    await h.close();
  }
});

// ---- the audit trail ---------------------------------------------------------------------------

test("test_approve_audited_without_secrets", async () => {
  const h = await connected();
  try {
    const approved = fakePreview({ preview_id: "pv-audit-ok", hash: "4c".repeat(32) });
    h.fake.state.previews = [approved];
    const goodCode = h.freshCode();
    const okAnswer = await h.post(approvePath(approved.preview_id), { hash: approved.hash, totp: goodCode });
    assert.equal(okAnswer.status, 200);

    const refused = fakePreview({ preview_id: "pv-audit-bad", hash: "5d".repeat(32) });
    h.fake.state.previews.push(refused);
    const staleCode = h.freshCode();
    const staleHash = "6e".repeat(32);
    const badAnswer = await h.post(approvePath(refused.preview_id), { hash: staleHash, totp: staleCode });
    assert.equal(badAnswer.status, 409);

    const rows = (await h.audit()).filter((row) => String(row.action) === "coinbase.previews_approve");
    const parsed = rows.map((row) => {
      let payload = null;
      try { payload = JSON.parse(String(row.payload ?? "null")); } catch { payload = null; }
      return { row, payload };
    });

    const okRow = parsed.find((entry) => entry.payload && entry.payload.ok === true);
    const refusedRow = parsed.find((entry) => entry.payload && entry.payload.ok === false);
    assert.ok(okRow, "the approval is filed");
    assert.ok(refusedRow, "the refusal is filed");
    assert.equal(typeof refusedRow.payload.code, "string");
    assert.equal(refusedRow.payload.code, "changed");

    // The preview each row is about is named, in the payload or as the row's target.
    assert.ok(`${okRow.row.target ?? ""} ${String(okRow.row.payload ?? "")}`.includes(approved.preview_id));
    assert.ok(`${refusedRow.row.target ?? ""} ${String(refusedRow.row.payload ?? "")}`.includes(refused.preview_id));

    // No secret, no hash, no code value in any of them.
    for (const entry of parsed) {
      const text = String(entry.row.payload ?? "");
      for (const value of [approved.hash, refused.hash, staleHash, goodCode, staleCode, ENGINE_TOKEN]) {
        assert.ok(!text.includes(value), "an audit payload carries no secret and no hash");
      }
    }
  } finally {
    await h.close();
  }
});

// ---- approve.js on its own ---------------------------------------------------------------------

test("test_describe_preview_keeps_money_digits", async () => {
  const { describePreview } = await approveApi();
  const now = NOW_S; // epoch seconds, the unit approve.js dates a preview against

  const shown = describePreview(
    fakePreview({
      product: "BTC-USDC",
      side: "BUY",
      size: "0.00100000",
      limit_price: "60000.00",
      notional: "60.00",
      book: "dry",
      expires_at: now + 900,
      limits: [{ name: "ai_max_order_usd", limit: "25.00", used_after: "60.00" }],
    }),
    { now },
  );
  assert.equal(shown.expired, false);
  assert.equal(shown.seconds_left, 900);
  assert.equal(shown.badge, "PRACTICE");
  assert.ok(shown.lines.includes(PRACTICE_LINE));

  const text = `${shown.summary} ${shown.lines.join(" ")}`;
  assert.ok(!/NaN|Infinity/.test(text));
  assert.ok(!/\de[+-]?\d/i.test(text), "money is written out, never in exponent notation");
  assert.ok(shown.summary.includes("0.0010"), `the size keeps its digits: ${shown.summary}`);
  assert.ok(shown.summary.includes("60000.00"), `the price keeps its digits: ${shown.summary}`);
  assert.ok(shown.summary.includes("BTC-USDC"));

  // An amount the browser would print as 1.2e-7 is still written out in full.
  const tiny = describePreview(
    fakePreview({
      size: "0.00000012",
      limit_price: "60000.00",
      notional: "0.0072",
      expires_at: now + 60,
    }),
    { now },
  );
  const tinyText = `${tiny.summary} ${tiny.lines.join(" ")}`;
  assert.ok(!/\de[+-]?\d/i.test(tinyText), `no exponent notation: ${tinyText}`);
  assert.ok(tiny.summary.includes("0.00000012"));

  // A live preview says so, in the book's own words.
  const live = describePreview(
    fakePreview({ book: "live", size: "0.00100000", limit_price: "60000.00", expires_at: now + 60 }),
    { now },
  );
  assert.equal(live.badge, "LIVE");
  assert.ok(live.lines.includes(LIVE_LINE));

  // Past the window: nothing left to approve.
  const gone = describePreview(fakePreview({ expires_at: now - 5 }), { now });
  assert.equal(gone.expired, true);
  assert.equal(gone.seconds_left, 0);
});

/** A client stand-in: it answers the listing a test seeds and records what it was asked. */
function stubClient(options = {}) {
  const calls = { previews: 0, params: undefined, approve: [], reject: [] };
  const client = {
    async aiPreviews(params) {
      calls.previews += 1;
      calls.params = params;
      if (options.previewsResult) return options.previewsResult;
      return { ok: true, data: options.rows || [] };
    },
    async approve(id, hash) {
      calls.approve.push({ id, hash });
      return options.approveResult || {
        ok: true,
        data: { preview_id: id, state: "placed", cid: "cid-test-1", book: "dry" },
      };
    },
    async aiReject(id) {
      calls.reject.push({ id });
      return options.rejectResult || { ok: true, data: { preview_id: id, state: "rejected" } };
    },
  };
  return { client, calls };
}

test("test_approve_preview_and_reject_preview_with_stub_client", async () => {
  const { approvePreview, rejectPreview } = await approveApi();
  const now = NOW_S;
  const row = fakePreview({
    preview_id: "pv-stub",
    hash: "7f".repeat(32),
    created_at: now - 5,
    expires_at: now + 60,
  });

  // The listed hash is the hash that is approved, once.
  {
    const stub = stubClient({ rows: [row] });
    const answer = await approvePreview({ client: stub.client, previewId: row.preview_id, hash: row.hash, now });
    assert.equal(answer.ok, true);
    assert.equal(answer.message, APPROVE_MESSAGE);
    assert.equal(stub.calls.previews, 1);
    assert.deepEqual(stub.calls.approve, [{ id: row.preview_id, hash: row.hash }]);
  }

  // An id nobody holds.
  {
    const stub = stubClient({ rows: [] });
    const answer = await approvePreview({ client: stub.client, previewId: "pv-nobody", hash: row.hash, now });
    assert.equal(answer.ok, false);
    assert.equal(answer.status, 404);
    assert.equal(answer.code, "not_found");
    assert.equal(answer.message, GONE_MESSAGE);
    assert.equal(stub.calls.approve.length, 0);
  }

  // Nothing waiting any more.
  {
    const stub = stubClient({ rows: [{ ...row, state: "placed" }] });
    const answer = await approvePreview({ client: stub.client, previewId: row.preview_id, hash: row.hash, now });
    assert.equal(answer.ok, false);
    assert.equal(answer.status, 409);
    assert.equal(answer.code, "not_pending");
    assert.equal(answer.message, NOT_PENDING_MESSAGE);
    assert.equal(stub.calls.approve.length, 0);
  }

  // Past the window.
  {
    const stub = stubClient({ rows: [{ ...row, expires_at: now - 1 }] });
    const answer = await approvePreview({ client: stub.client, previewId: row.preview_id, hash: row.hash, now });
    assert.equal(answer.ok, false);
    assert.equal(answer.status, 409);
    assert.equal(answer.code, "expired");
    assert.equal(answer.message, EXPIRED_MESSAGE);
    assert.equal(stub.calls.approve.length, 0);
  }

  // A hash that is not the one on the row: refused, and never sent.
  {
    const stub = stubClient({ rows: [row] });
    const answer = await approvePreview({ client: stub.client, previewId: row.preview_id, hash: "00".repeat(32), now });
    assert.equal(answer.ok, false);
    assert.equal(answer.status, 409);
    assert.equal(answer.code, "changed");
    assert.equal(answer.message, CHANGED_MESSAGE);
    assert.equal(stub.calls.approve.length, 0);
  }

  // The engine's own refusal passes through in its own words and its own code field.
  {
    const engineMessage = "The book for AI orders changed; ask again.";
    const stub = stubClient({
      rows: [row],
      approveResult: { ok: false, status: 409, code: "BOOK_CHANGED", message: engineMessage },
    });
    const answer = await approvePreview({ client: stub.client, previewId: row.preview_id, hash: row.hash, now });
    assert.equal(answer.ok, false);
    assert.equal(answer.status, 409);
    assert.equal(answer.code, "BOOK_CHANGED");
    assert.equal(answer.message, engineMessage);
  }

  // Rejecting is one call to the engine and one plain answer.
  {
    const stub = stubClient({ rows: [row] });
    const answer = await rejectPreview({ client: stub.client, previewId: row.preview_id });
    assert.equal(answer.ok, true);
    assert.equal(answer.message, REJECT_MESSAGE);
    assert.deepEqual(stub.calls.reject, [{ id: row.preview_id }]);
  }

  // A reject the engine refuses reads back as the engine said it.
  {
    const stub = stubClient({
      rows: [row],
      rejectResult: { ok: false, status: 404, code: "NOT_FOUND", message: "There is no such preview." },
    });
    const answer = await rejectPreview({ client: stub.client, previewId: "pv-nobody" });
    assert.equal(answer.ok, false);
    assert.equal(answer.status, 404);
    assert.equal(answer.code, "NOT_FOUND");
    assert.equal(answer.message, "There is no such preview.");
  }
});