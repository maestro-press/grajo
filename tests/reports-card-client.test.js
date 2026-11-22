/**
 * The report card in the Perch chat: perch-hub/report-card.js, spliced into the hub client.
 *
 * Built on the vm harness (tests/fixtures/perch-hub-vm.mjs): the WHOLE emitted Perch client runs in
 * a fresh vm context against a fake DOM and a fake fetch, with the report routes answered per test.
 * No browser, no server, and no database — the card talks only to the shapes the server half owns.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mountHub, openChatSession, findByClass, stdFetch, makeResponse } from "./fixtures/perch-hub-vm.mjs";
import { perchReportCardJs } from "../servers/gateway/dashboard/perch-hub/report-card.js";

const SID = "perchlive-aaaaaaaa";
const SECOND = "perchlive-bbbbbbbb";
const RID = "rpt-0123456789abcdef";
const OTHER = "rpt-fedcba9876543210";
const CSRF_TOKEN = "page-csrf-token";
const HASH = "a".repeat(64);
const HASH_NEW = "b".repeat(64);

/** Two live sessions on one roost: a switch has somewhere to switch to. */
const TWO_SESSIONS = {
  birds: [{
    id: "r4",
    name: "R4 Assistant",
    perch_attached: true,
    state: "working",
    sessions: [
      { sessionId: SID, state: "awake", cardId: null, pendingUi: false, projectId: 7 },
      { sessionId: SECOND, state: "awake", cardId: null, pendingUi: false, projectId: 7 },
    ],
  }],
};

const report = (over = {}) => ({
  id: RID,
  title: "Weekly numbers",
  status: "draft",
  live: false,
  pauseReason: null,
  recipeRev: 2,
  liveRev: 0,
  pendingFreeChange: false,
  deliveryMode: "email",
  ...over,
});

const card = (over = {}) => {
  const out = {
    report: report(over.report),
    headRev: over.headRev === undefined ? 5 : over.headRev,
    changesHash: over.changesHash || HASH,
    changesTruncated: !!over.changesTruncated,
    sender: over.sender === undefined ? null : over.sender,
    schedule: over.schedule || null,
    scheduleProposal: over.scheduleProposal || null,
    preview: over.preview === undefined ? null : over.preview,
    changes: over.changes || [],
    sources: over.sources || [],
    recipients: over.recipients || [],
    steps: over.steps || [],
    hosts: over.hosts || [],
    credentials: over.credentials || [],
  };
  if (over.changesUnreadable) out.changesUnreadable = true;
  return out;
};

const preview = (over = {}) => ({ runId: "run-1", status: "done", recipeRev: 2, current: true, ...over });

/**
 * Mount the real client with a scripted report surface. `state.cards` maps a report id to the answer
 * its card read returns (a function is called per read); `state.list` is the chat's ids, or a
 * function of the sid; `state.reply` answers the next POST. Every call is recorded in `calls`.
 */
async function mount(state = {}) {
  const calls = [];
  const impl = (method, path, opts) => {
    const body = opts && opts.body ? JSON.parse(opts.body) : undefined;
    calls.push({ method, path, body, headers: (opts && opts.headers) || {} });
    if (path === "/roost" && state.roost) return makeResponse(200, state.roost);
    const listed = /^\/interactive\/(perchlive-[0-9a-f]{8})\/reports$/.exec(path);
    if (listed && method === "GET") {
      const given = typeof state.list === "function" ? state.list(listed[1]) : state.list;
      const ids = given === undefined ? Object.keys(state.cards || {}) : given;
      return makeResponse(200, { reports: ids.map((id) => ({ id })) });
    }
    const m = /^\/dashboard\/api\/reports\/(rpt-[0-9a-f]{16})(?:\/(.*))?$/.exec(path);
    if (m) {
      const id = m[1];
      if (method === "GET" && m[2] === "card") {
        const answer = (state.cards || {})[id] || card();
        return makeResponse(200, { card: typeof answer === "function" ? answer() : answer });
      }
      const reply = typeof state.reply === "function" ? state.reply(id, m[2], body) : state.reply;
      return makeResponse(reply ? reply.status : 202, reply ? reply.json : { ok: true });
    }
    return stdFetch()(method, path);
  };
  const hub = await mountHub({ fetchImpl: impl, lang: state.lang || "en" });
  /* The hub's CSRF reader is a call into the page's own runtime (window.crowCsrf). */
  hub.win.crowCsrf = () => CSRF_TOKEN;
  return { hub, calls };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle(times = 6) { for (let i = 0; i < times; i += 1) await tick(); }

async function open(hub, sid = SID) {
  await openChatSession(hub, sid);
  await settle();
}

function all(hub, cls) {
  const out = [];
  const walk = (n) => {
    if (String(n.className || "").split(" ").includes(cls)) out.push(n);
    for (const c of n.children || []) walk(c);
  };
  walk(hub.els["perch-transcript"]);
  return out;
}
const text = (hub, cls) => (all(hub, cls)[0] || {}).textContent || "";
const found = (hub, cls) => findByClass(hub.els["perch-transcript"], cls);
const posts = (calls) => calls.filter((c) => c.method === "POST");
const settingsShown = (hub) => all(hub, "rcard-setting").map((n) => n.textContent);

function click(hub, cls) {
  const node = found(hub, cls);
  assert.ok(node, `a ${cls} button is on the card`);
  node.onclick();
}

/** Every element tag under the transcript, so a test can prove no markup was parsed. */
function tags(hub) {
  const out = [];
  const walk = (n) => { out.push(String(n.tagName || "").toUpperCase()); (n.children || []).forEach(walk); };
  walk(hub.els["perch-transcript"]);
  return out;
}

/* -------------------------------------------------------------------- tests */

test("card approve buttons call owner routes with CSRF", async () => {
  const { hub, calls } = await mount({
    cards: {
      [RID]: card({
        sender: { accountId: "acc-1", address: "reports@example.test", kind: "google_reports" },
        preview: preview(),
        report: { pendingFreeChange: true },
        changes: [{ blockId: "block-1", type: "chart", kind: "free", change: "changed",
          before: { limit: 10 }, after: { limit: 20 } }],
        sources: [{ blockId: "block-1", type: "csv", settingsHash: "sh-1",
          settings: { url: "https://example.test/data.csv" } }],
        recipients: [{ id: "rc-1", address: "sam@example.test", displayName: "Sam",
          commentTier: "colleague", state: "proposed", proposedBy: "bot" }],
        steps: [{ stepKey: "step-1", rev: 3, language: "python", entry: "main.py",
          bundleHash: "bh-1", proposedBy: "bot", files: [] }],
        hosts: [{ host: "api.example.test", notice: "Crow will read this site." }],
        credentials: [{ host: "api.example.test", connectionUuid: "conn-1", injectHash: "ih-1",
          inject: { header: "X-Api-Key", pathPrefixes: ["/v1"], methods: ["GET"] } }],
      }),
    },
  });
  await open(hub);

  for (const cls of ["rcard-preview", "rcard-golive", "rcard-apply", "rcard-source-approve",
    "rcard-rcpt-approve", "rcard-step-approve", "rcard-host-approve", "rcard-cred-approve"]) {
    click(hub, cls);
    await settle();
  }

  const sent = posts(calls);
  assert.deepEqual(sent.map((c) => c.path), [
    "/dashboard/api/reports/" + RID + "/preview",
    "/dashboard/api/reports/" + RID + "/go-live",
    "/dashboard/api/reports/" + RID + "/apply",
    "/dashboard/api/reports/" + RID + "/sources/block-1/approve",
    "/dashboard/api/reports/" + RID + "/recipients/rc-1/approve",
    "/dashboard/api/reports/" + RID + "/steps/step-1/3/approve",
    "/dashboard/api/reports/" + RID + "/hosts/" + encodeURIComponent("api.example.test") + "/approve",
    "/dashboard/api/reports/" + RID + "/credentials/conn-1/approve",
  ]);
  for (const c of sent) {
    assert.equal(c.headers["X-Crow-Csrf"], CSRF_TOKEN, `${c.path} carries the page's CSRF token`);
    assert.equal(/mail|send/i.test(c.path), false, `${c.path} is not a mail or send path`);
  }
  assert.deepEqual(sent.map((c) => c.body), [
    undefined,
    { previewRunId: "run-1", expectedSenderAccountId: "acc-1" },
    { expectedRev: 5, changesHash: HASH },
    { settingsHash: "sh-1" },
    undefined,
    { bundleHash: "bh-1" },
    undefined,
    { injectHash: "ih-1" },
  ]);
  /* Nothing above is a GET that could have run or sent anything on its own. */
  assert.equal(calls.filter((c) => c.method !== "GET" && c.method !== "POST").length, 0);
});

test("go-live card names the sender account", async () => {
  const google = await mount({
    cards: { [RID]: card({ preview: preview(),
      sender: { accountId: "acc-1", address: "reports@example.test", kind: "google_reports" } }) },
  });
  await open(google.hub);
  assert.equal(text(google.hub, "rcard-from"),
    "Send from: reports@example.test (reports-only Google account)");

  const crow = await mount({
    cards: { [RID]: card({ preview: preview(),
      sender: { accountId: "ma-1", address: "alex@example.test", kind: "crow_mail" } }) },
  });
  await open(crow.hub);
  assert.equal(text(crow.hub, "rcard-from"),
    "Send from: alex@example.test (your Crow Mail account)");

  const none = await mount({ cards: { [RID]: card({ preview: preview(), sender: null }) } });
  await open(none.hub);
  assert.equal(found(none.hub, "rcard-from"), null, "no sender, no line");
});

test("card renders a pending step diff", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        steps: [{
          stepKey: "step-1", rev: 3, language: "python", entry: "main.py", bundleHash: "bh-1",
          proposedBy: "bot",
          files: [{
            path: "reports/weekly.py", status: "modified", added: 2, removed: 1,
            lines: [
              { op: "+", text: "x = 1" },
              { op: "-", text: "y = 2" },
              { op: " ", text: "# note" },
              { op: "+", text: "<b>x</b>" },
            ],
          }],
        }],
      }),
    },
  });
  await open(hub);

  assert.equal(text(hub, "rcard-step-key"), "step-1");
  assert.equal(text(hub, "rcard-step-meta"), "Revision 3 \u00b7 python");
  assert.equal(text(hub, "rcard-step-entry"), "main.py");
  assert.equal(text(hub, "rcard-step-path"), "reports/weekly.py");
  assert.equal(text(hub, "rcard-step-counts"), "2 lines added, 1 removed");
  assert.deepEqual(all(hub, "rcard-diff-line").map((n) => n.textContent),
    ["+x = 1", "-y = 2", " # note", "+<b>x</b>"]);
  /* A diff line is text: the markup in it never became an element. */
  assert.equal(tags(hub).includes("B"), false);
});

test("apply shows every changed block's full settings", async () => {
  const long = "L".repeat(400);
  const { hub } = await mount({
    cards: {
      [RID]: card({
        report: { pendingFreeChange: true },
        changes: [{
          blockId: "block-1", type: "chart", kind: "free", change: "changed",
          before: { limit: 10, nested: { a: [1, 2] } },
          after: { limit: 200, nested: { a: [1, 2, 3] }, note: long },
        }],
      }),
    },
  });
  await open(hub);

  assert.equal(text(hub, "rcard-block"), "block-1");
  assert.equal(text(hub, "rcard-change-word"), "Changed");
  const shown = settingsShown(hub);
  assert.deepEqual(shown.slice(0, 2), ["limit: 10", 'nested: {"a":[1,2]}'], "the before settings, whole");
  assert.ok(shown.includes("limit: 200"), shown.join(" | "));
  assert.ok(shown.includes('nested: {"a":[1,2,3]}'), "a nested value is shown as its JSON");
  assert.ok(shown.includes("note: " + long), "a long value is shown in full");
  assert.equal(shown.some((s) => s.includes("...") || s.includes("\u2026")), false, "nothing is elided");
  assert.ok(found(hub, "rcard-apply"), "Apply is offered for a free change");
});

test("a recipe-level change entry renders its full values", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        report: { pendingFreeChange: true },
        changes: [
          { blockId: null, type: "recipe", kind: "free", change: "changed",
            before: { emptyText: "Nothing new this time." },
            after: { emptyText: "Nothing new this week." } },
        ],
      }),
    },
  });
  await open(hub);

  /* A recipe entry names no block: the card says what it is about, and the raw type is not printed. */
  assert.equal(all(hub, "rcard-change").length, 1);
  assert.deepEqual(all(hub, "rcard-block").map((n) => n.textContent), ["Whole report"],
    "a recipe entry is labelled, not left blank");
  assert.deepEqual(all(hub, "rcard-type").map((n) => n.textContent), [],
    "the raw recipe type is not printed beside the label");
  const shown = settingsShown(hub);
  assert.ok(shown.includes("emptyText: Nothing new this time."), shown.join(" | "));
  assert.ok(shown.includes("emptyText: Nothing new this week."), "the whole new value, not a summary");
  assert.ok(found(hub, "rcard-apply"), "a recipe-level change is free, so Apply is still offered");
});

test("an order change entry is labelled Block order", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        report: { pendingFreeChange: true },
        changes: [
          { blockId: null, type: "order", kind: "free", change: "changed",
            before: { order: ["b1", "b2"] }, after: { order: ["b2", "b1"] } },
        ],
      }),
    },
  });
  await open(hub);

  assert.deepEqual(all(hub, "rcard-block").map((n) => n.textContent), ["Block order"],
    "an order entry is labelled, not left blank");
  assert.deepEqual(all(hub, "rcard-type").map((n) => n.textContent), [],
    "the raw order type is not printed beside the label");
  const shown = settingsShown(hub);
  assert.ok(shown.includes('order: ["b1","b2"]'), shown.join(" | "));
  assert.ok(shown.includes('order: ["b2","b1"]'), "the whole new order, not a summary");
  assert.ok(found(hub, "rcard-apply"), "a reorder is free, so Apply is still offered");
});

test("apply is not offered for a source or custom change", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        report: { pendingFreeChange: true },
        changes: [
          { blockId: "block-1", type: "csv", kind: "source", change: "changed",
            before: { url: "https://example.test/a.csv" }, after: { url: "https://example.test/b.csv" } },
          { blockId: "block-2", type: "custom", kind: "custom", change: "added",
            before: null, after: { code: "print(1)" } },
        ],
      }),
    },
  });
  await open(hub);

  assert.equal(found(hub, "rcard-apply"), null, "a source or custom change is not one tap");
  assert.deepEqual(all(hub, "rcard-change-word").map((n) => n.textContent), ["Changed", "Added"]);
  assert.ok(settingsShown(hub).includes("code: print(1)"), "the entries are still shown whole");
});

test("apply is not offered when changes are unreadable", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        changesUnreadable: true,
        report: { pendingFreeChange: true },
        changes: [{ blockId: "block-1", type: "chart", kind: "free", change: "changed",
          before: { limit: 10 }, after: { limit: 20 } }],
      }),
    },
  });
  await open(hub);
  assert.equal(found(hub, "rcard-apply"), null, "a change list the server cannot show is not approvable");
});

test("approve source shows the full settings and posts the settingsHash", async () => {
  const { hub, calls } = await mount({
    cards: {
      [RID]: card({
        sources: [{
          blockId: "block-1", type: "csv", settingsHash: "sh-1",
          settings: { url: "https://example.test/data.csv", limit: 5, opts: { deep: true } },
        }],
      }),
    },
  });
  await open(hub);

  assert.equal(text(hub, "rcard-type"), "csv");
  const shown = settingsShown(hub);
  assert.ok(shown.includes("url: https://example.test/data.csv"), shown.join(" | "));
  assert.ok(shown.includes("limit: 5"));
  assert.ok(shown.includes('opts: {"deep":true}'));

  click(hub, "rcard-source-approve");
  await settle();
  assert.equal(posts(calls)[0].path, "/dashboard/api/reports/" + RID + "/sources/block-1/approve");
  assert.deepEqual(posts(calls)[0].body, { settingsHash: "sh-1" });
  assert.equal(posts(calls)[0].headers["X-Crow-Csrf"], CSRF_TOKEN);
});

test("a truncated source has no approve button", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        sources: [{ blockId: "block-1", type: "csv", settingsHash: "sh-1", settings: {}, truncated: true }],
      }),
    },
  });
  await open(hub);
  assert.equal(found(hub, "rcard-source-approve"), null);
  assert.equal(text(hub, "rcard-truncated"), "Too large to show.");
  assert.equal(text(hub, "rcard-block"), "block-1", "the source is still named");
});

test("card never renders a server string as markup", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        report: { title: "<b>Weekly</b>", pauseReason: "<u>paused</u>", status: "paused" },
        sender: { accountId: "acc-1", address: "<i>r@example.test</i>", kind: "google_reports" },
        recipients: [{ id: "rc-1", address: "sam@example.test", displayName: "<script>x</script>",
          commentTier: "colleague", state: "proposed", proposedBy: "bot" }],
        hosts: [{ host: "<img src=x>", notice: "<em>reads</em>" }],
      }),
    },
  });
  await open(hub);

  assert.equal(text(hub, "rcard-title"), "<b>Weekly</b>");
  assert.equal(text(hub, "rcard-pause"), "<u>paused</u>");
  assert.equal(text(hub, "rcard-from"), "Send from: <i>r@example.test</i> (reports-only Google account)");
  assert.equal(text(hub, "rcard-name"), "<script>x</script>");
  assert.equal(text(hub, "rcard-host-line"), "<img src=x>");
  assert.equal(text(hub, "rcard-notice"), "<em>reads</em>");
  for (const tag of ["B", "I", "U", "EM", "IMG", "SCRIPT"]) {
    assert.equal(tags(hub).includes(tag), false, `no ${tag} element was parsed out of a server string`);
  }
});

test("a session switch clears the cards and stops the polls", async () => {
  const { hub, calls } = await mount({
    roost: TWO_SESSIONS,
    list: (sid) => (sid === SID ? [RID, OTHER] : []),
    cards: {
      [RID]: card({ preview: preview({ status: "queued", current: false }) }),
      [OTHER]: card({ report: { id: OTHER, title: "Second report" } }),
    },
  });
  await open(hub);

  assert.equal(all(hub, "rcard-card").length, 2, "both reports are on screen");
  const delays = [...hub.timerDelays.values()];
  assert.ok(delays.filter((d) => d === 3000).length >= 1, "the preview in flight has its own poll");
  assert.ok(delays.filter((d) => d === 8000).length >= 1, "the id list has its own beat");

  await openChatSession(hub, SECOND);
  await settle();

  assert.equal(all(hub, "rcard-card").length, 0, "the transcript's report cards went with it");

  /* Firing whatever is left on the preview rhythm asks for nothing: the poll went with its chat. */
  const readsOfCard = () => calls.filter((c) => c.path === "/dashboard/api/reports/" + RID + "/card").length;
  const readsBefore = readsOfCard();
  for (const [id, delay] of [...hub.timerDelays]) {
    if (delay !== 3000) continue;
    const fn = hub.timers.get(id);
    if (fn) fn();
  }
  await settle();
  assert.equal(readsOfCard(), readsBefore, "no preview poll outlived the chat it belonged to");

  /* The new chat's own beat asks about the new chat, and never about the one left behind. */
  const askedOfOld = calls.filter((c) => c.path.indexOf(SID) >= 0).length;
  for (const [id, delay] of [...hub.timerDelays]) {
    if (delay !== 8000) continue;
    const fn = hub.timers.get(id);
    if (fn) fn();
  }
  await settle();
  assert.equal(calls.filter((c) => c.path.indexOf(SID) >= 0).length, askedOfOld,
    "the id list poll stopped asking about the session that was left");
});

test("go-live is offered only with a current preview", async () => {
  const noPreview = await mount({ cards: { [RID]: card({ preview: null }) } });
  await open(noPreview.hub);
  assert.equal(found(noPreview.hub, "rcard-golive"), null);
  assert.equal(text(noPreview.hub, "rcard-status"), "Preview first to check this report.");

  const stale = await mount({ cards: { [RID]: card({ preview: preview({ current: false }) }) } });
  await open(stale.hub);
  assert.equal(found(stale.hub, "rcard-golive"), null, "a preview that is not current publishes nothing");
  assert.equal(text(stale.hub, "rcard-status"), "Preview first to check this report.");

  const fresh = await mount({ cards: { [RID]: card({ preview: preview() }) } });
  await open(fresh.hub);
  assert.ok(found(fresh.hub, "rcard-golive"), "a current preview offers go-live");
  assert.equal(found(fresh.hub, "rcard-preview-line"), null, "a settled preview has no running line");

  const running = await mount({ cards: { [RID]: card({ preview: preview({ status: "running", current: false }) }) } });
  await open(running.hub);
  assert.equal(text(running.hub, "rcard-preview-line"), "Preview running.");

  const already = await mount({
    cards: { [RID]: card({ report: { live: true, liveRev: 2 }, preview: preview() }) },
  });
  await open(already.hub);
  assert.equal(found(already.hub, "rcard-golive"), null, "a report already live at that revision has nothing to publish");
});

test("a refused tap shows the server's sentence, and a lost socket shows the offline line", async () => {
  const refused = await mount({
    cards: { [RID]: card({ preview: preview() }) },
    reply: { status: 409, json: { error: "preview_stale", message: "This preview is out of date. Preview again." } },
  });
  await open(refused.hub);
  click(refused.hub, "rcard-golive");
  await settle();
  assert.equal(text(refused.hub, "rcard-status"), "This preview is out of date. Preview again.");

  const offline = await mount({
    cards: { [RID]: card({ preview: preview() }) },
    reply: { status: 0, json: null },
  });
  await open(offline.hub);
  click(offline.hub, "rcard-preview");
  await settle();
  assert.equal(text(offline.hub, "rcard-status"), "No connection.");
});

test("apply echoes the head rev and the diff hash the card showed", async () => {
  /* The card's own answer changes between reads, so a fresh read before the tap would show up in the
     body: the POST has to echo the revision the displayed changes came from. */
  const first = card({
    headRev: 7,
    changesHash: HASH,
    report: { pendingFreeChange: true },
    changes: [{ blockId: "block-1", type: "chart", kind: "free", change: "changed",
      before: { limit: 10 }, after: { limit: 20 } }],
  });
  const later = card({
    headRev: 8,
    changesHash: HASH_NEW,
    report: { pendingFreeChange: true },
    changes: [{ blockId: "block-1", type: "chart", kind: "free", change: "changed",
      before: { limit: 10 }, after: { limit: 30 } }],
  });
  let reads = 0;
  const { hub, calls } = await mount({ cards: { [RID]: () => (reads++ === 0 ? first : later) } });
  await open(hub);

  assert.ok(settingsShown(hub).includes("limit: 20"), "the displayed card is the first answer");
  click(hub, "rcard-apply");
  await settle();

  const sent = posts(calls);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].path, "/dashboard/api/reports/" + RID + "/apply");
  assert.deepEqual(sent[0].body, { expectedRev: 7, changesHash: HASH });
});

test("a truncated diff shows a message and no Apply button", async () => {
  const { hub } = await mount({
    cards: {
      [RID]: card({
        changesTruncated: true,
        report: { pendingFreeChange: true },
        changes: [{ blockId: "block-1", type: "chart", kind: "free", change: "changed",
          before: { limit: 10 }, after: { limit: 20 } }],
      }),
    },
  });
  await open(hub);

  assert.equal(found(hub, "rcard-apply"), null, "a shortened change list is not one tap");
  assert.equal(text(hub, "rcard-changes-truncated"),
    "Too many changes to show here. Open the report page to review them.");
  assert.equal(text(hub, "rcard-block"), "block-1", "the entries the card has are listed");
  assert.ok(settingsShown(hub).includes("limit: 20"), "their settings are still shown whole");
});

test("go-live echoes the sender account the card showed", async () => {
  const withSender = await mount({
    cards: { [RID]: card({ preview: preview(),
      sender: { accountId: "acc-1", address: "reports@example.test", kind: "google_reports" } }) },
  });
  await open(withSender.hub);
  click(withSender.hub, "rcard-golive");
  await settle();
  assert.deepEqual(posts(withSender.calls)[0].body,
    { previewRunId: "run-1", expectedSenderAccountId: "acc-1" });

  const noSender = await mount({ cards: { [RID]: card({ preview: preview(), sender: null }) } });
  await open(noSender.hub);
  click(noSender.hub, "rcard-golive");
  await settle();
  assert.deepEqual(posts(noSender.calls)[0].body,
    { previewRunId: "run-1", expectedSenderAccountId: "" });
});

test("a conflict answer re-reads the card", async () => {
  const MESSAGE = "This report changed while you were looking at it. Nothing was applied.";
  const first = card({
    headRev: 3,
    report: { pendingFreeChange: true, title: "Weekly numbers" },
    changes: [{ blockId: "block-1", type: "chart", kind: "free", change: "changed",
      before: { limit: 10 }, after: { limit: 20 } }],
  });
  const later = card({
    headRev: 4,
    report: { pendingFreeChange: true, title: "Weekly numbers, revised" },
    changes: [{ blockId: "block-1", type: "chart", kind: "free", change: "changed",
      before: { limit: 10 }, after: { limit: 30 } }],
  });
  let reads = 0;
  const { hub, calls } = await mount({
    cards: { [RID]: () => (reads++ === 0 ? first : later) },
    reply: (id, path) => (path === "apply"
      ? { status: 409, json: { error: "conflict", message: MESSAGE } }
      : null),
  });
  await open(hub);
  const readsOfCard = () =>
    calls.filter((c) => c.path === "/dashboard/api/reports/" + RID + "/card").length;
  const before = readsOfCard();

  click(hub, "rcard-apply");
  await settle();

  assert.equal(readsOfCard(), before + 1, "the refused tap read the card again");
  assert.equal(all(hub, "rcard-card").length, 1, "one card, the new one");
  assert.equal(text(hub, "rcard-title"), "Weekly numbers, revised", "the new answer is on screen");
  assert.equal(text(hub, "rcard-status"), MESSAGE, "the server's sentence is on the new card");

  /* The same refusal from a section's approve lands the same way. */
  const second = await mount({
    cards: { [RID]: card({ sources: [{ blockId: "block-1", type: "csv", settingsHash: "sh-1",
      settings: { url: "https://example.test/data.csv" } }] }) },
    reply: (id, path) => (path === "sources/block-1/approve"
      ? { status: 409, json: { error: "conflict", message: MESSAGE } }
      : null),
  });
  await open(second.hub);
  click(second.hub, "rcard-source-approve");
  await settle();
  assert.equal(text(second.hub, "rcard-status"), MESSAGE,
    "a conflict from a section approve says why on the card that replaces it");
});

test("approve source posts the settings hash the card showed", async () => {
  const first = card({ sources: [{ blockId: "block-1", type: "csv", settingsHash: "sh-first",
    settings: { url: "https://example.test/data.csv" } }] });
  const later = card({ sources: [{ blockId: "block-1", type: "csv", settingsHash: "sh-second",
    settings: { url: "https://example.test/other.csv" } }] });
  let reads = 0;
  const { hub, calls } = await mount({ cards: { [RID]: () => (reads++ === 0 ? first : later) } });
  await open(hub);

  assert.ok(settingsShown(hub).includes("url: https://example.test/data.csv"));
  click(hub, "rcard-source-approve");
  await settle();

  assert.deepEqual(posts(calls)[0].body, { settingsHash: "sh-first" });
});

test("the module output carries no backtick and no dollar-brace", async () => {
  const vm = await import("node:vm");
  const { perchHubJs } = await import("../servers/gateway/dashboard/perch-hub/client.js");
  for (const lang of ["en", "es"]) {
    const js = perchReportCardJs(lang);
    assert.equal(js.includes("`"), false, `${lang}: no backtick`);
    assert.equal(js.includes("${"), false, `${lang}: no dollar-brace`);
    /* The whole client the splice lands in compiles — one stray backtick would break every script
       the hub serves. */
    assert.doesNotThrow(() => new vm.Script(perchHubJs(lang)), `${lang}: the emitted client compiles`);
  }
});