/**
 * The trading engine's event feed, turned into the notifications the owner sees.
 *
 * The engine writes one short sentence per event (a fill, a halt, a refused
 * order) and keeps them behind a cursor.  Crow reads that feed through the
 * lease, so one gateway polls at a time and moves the engine's cursor forward as
 * it goes; a handover to another gateway continues where the last one stopped
 * instead of repeating a page.
 *
 * Three things keep the bell readable:
 *
 * - most kinds map to nothing at all (`mapEvent`), so the feed's own bookkeeping
 *   never reaches the owner;
 * - each kind is limited to `hourlyLimit` notifications in any rolling hour, and
 *   what the limit suppresses is folded into one summary note rather than
 *   dropped silently; the one frequent high kind, `ai_preview`, has a looser
 *   `highHourlyLimit`, and what that holds back is counted and folded into one
 *   summary note an hour.  Every other high kind -- `live_switch` (the owner is
 *   told live trading was turned on, every time), a halt, a watchdog, an alert,
 *   a credentials fault -- is not bound by any limit and is not counted by it,
 *   so a quiet storm never buries the one note that matters;
 * - a feed that cannot be reached, and an engine whose own heartbeat reads
 *   stale, are one notice per episode and one more when the engine comes back,
 *   instead of a notification per failed poll.
 *
 * The episode itself is reachability, not the feed: a caller that watches the
 * engine's health reports what it saw through `noteReachability`, and the feed's
 * own failed reads count into the same episode.
 *
 * A notification's body is the engine's own event message plus a few fixed
 * sentences.  An event's `data` is never copied into a title, a body or a
 * notification's metadata; the one exception is the preview id an `ai_preview`
 * notification links to.
 */

const HOUR_MS = 60 * 60 * 1000;

const UNREACHABLE = "ENGINE_UNREACHABLE";
const LEASE_NOT_HELD = "LEASE_NOT_HELD";
const CURSOR_AHEAD = "CURSOR_AHEAD";

const DEFAULT_HOURLY_LIMIT = 6;
// The `ai_preview` window: a proposed order is frequent by nature, so the owner
// is owed a bounded number of them an hour and one summary for the rest.  No
// other kind is counted here.
const DEFAULT_HIGH_HOURLY_LIMIT = 20;
const DEFAULT_FAILURE_THRESHOLD = 3;
const DEFAULT_PAGE_LIMIT = 100;

// The one high kind the window holds.
const CAPPED_URGENT_KINDS = new Set(["ai_preview"]);

const NOT_RESPONDING_TITLE = "Trading engine not responding";
const NOT_RESPONDING_BODY = "The trading engine is not responding";
const BACK_TITLE = "Trading engine is back";
const BACK_BODY = "The trading engine is answering again";
const RESET_TITLE = "Trading engine history was reset";
const RESET_BODY = "Trading engine history was reset; some earlier events cannot be shown";

const PREVIEW_LINK = "/dashboard/coinbase?preview=";
const TRADING_PANEL_URL = "/dashboard/coinbase";
const PREVIEW_SUMMARY = "more AI order proposals waiting";

/** The engine's message for an event, as text, never anything from `data`. */
function messageOf(event) {
  const message = event && event.message;
  if (typeof message === "string") return message;
  return message === undefined || message === null ? "" : String(message);
}

/** The level of an event, lowercased, or an empty string. */
function levelOf(event) {
  const level = event && event.level;
  return typeof level === "string" ? level.toLowerCase() : "";
}

/**
 * The notification one engine event earns, or null when it earns none.
 *
 * The titles are fixed sentences rather than the engine's own wording, so the
 * bell reads the same whatever an event's message says; the body is the
 * engine's message.  A `credentials` event is only worth a high notification
 * when its level says something is wrong: the engine also writes informational
 * ones, and those stay in the feed.
 */
export function mapEvent(event) {
  if (!event || typeof event !== "object") return null;
  const kind = event.kind;
  const body = messageOf(event);

  switch (kind) {
    case "halt":
      return { priority: "high", title: "Trading halted", body, kind };
    case "watchdog":
      return { priority: "high", title: "Trading engine watchdog", body, kind };
    case "credentials": {
      const level = levelOf(event);
      if (level !== "warn" && level !== "error" && level !== "high") return null;
      return { priority: "high", title: "Coinbase connection needs attention", body, kind };
    }
    case "live_switch":
      return { priority: "high", title: "Live trading switch changed", body, kind };
    case "ai_preview": {
      const note = { priority: "high", title: "The AI proposed an order", body, kind };
      const previewId = event.data && typeof event.data === "object" ? event.data.preview_id : null;
      if (previewId !== undefined && previewId !== null && previewId !== "") {
        note.action_url = PREVIEW_LINK + encodeURIComponent(String(previewId));
      }
      return note;
    }
    case "alert":
      return { priority: "high", title: "Trading alert", body, kind };
    case "fill":
      return { priority: "normal", title: "Order filled", body, kind };
    case "trailing_hold":
      return { priority: "normal", title: "Bot is behind simply holding", body, kind };
    case "bot_paused": {
      // The owner's own Pause is not news: the owner just pressed it, so it earns no
      // note. Every other bot_paused (a drawdown, a strategy) still notifies.
      const reason = event.data && typeof event.data === "object" ? event.data.reason : null;
      if (reason === "owner") return null;
      // Not every bot_paused event takes a bot out of service, so the title says
      // only that something wants a look; the engine's sentence says the rest.
      return { priority: "normal", title: "A bot needs attention", body, kind };
    }
    default:
      return null;
  }
}

/** The notification writer over an instance's own notifications table. */
export function makeNotify(db, createNotification) {
  return async ({ title, body, priority, action_url, kind }) =>
    createNotification(db, {
      title,
      body,
      type: "system",
      source: "coinbase",
      priority,
      action_url,
      metadata: kind ? { kind } : null,
    });
}

/** A stored counter as a whole number, or null when it is not one. */
function wholeNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.trunc(parsed);
  }
  return null;
}

/**
 * The notifier: one poll of the feed, the cursor it keeps, and the notifications
 * it sends on the way.
 *
 * `client` is the engine client, `notify` the writer a mapped event is handed to,
 * and `holder` the lease holder this poller acts as.  `onEvents` sees every page
 * before anything is notified (the audit trail rides on it).  `now` answers epoch
 * milliseconds and dates the rate limit; `hourlyLimit`, `failureThreshold` and
 * `pageLimit` are the three bounds above.
 *
 * `keyKind` names the key the cursor post is signed with: "owner" (the default)
 * or "install" for an engine that has no pin yet.  A function is asked for it on
 * every post, which is how the caller follows an engine from the install token to
 * the owner's key.
 */
export function createNotifier(options = {}) {
  const config = options || {};
  const client = config.client;
  const notify = typeof config.notify === "function" ? config.notify : async () => null;
  const holder = config.holder;
  const now = typeof config.now === "function" ? config.now : Date.now;
  const onEvents = typeof config.onEvents === "function" ? config.onEvents : null;
  const hourlyLimit = Number.isFinite(config.hourlyLimit)
    ? Math.max(0, Math.trunc(config.hourlyLimit))
    : DEFAULT_HOURLY_LIMIT;
  const highHourlyLimit = Number.isFinite(config.highHourlyLimit)
    ? Math.max(0, Math.trunc(config.highHourlyLimit))
    : DEFAULT_HIGH_HOURLY_LIMIT;
  const failureThreshold = Number.isFinite(config.failureThreshold)
    ? Math.max(1, Math.trunc(config.failureThreshold))
    : DEFAULT_FAILURE_THRESHOLD;
  const pageLimit = Number.isFinite(config.pageLimit)
    ? Math.max(1, Math.trunc(config.pageLimit))
    : DEFAULT_PAGE_LIMIT;
  const keyKindOption = config.keyKind === undefined ? "owner" : config.keyKind;

  let cursor = 0;
  let holding = false;
  // Consecutive reads that never reached the engine, and the open episode: null,
  // "unreachable" (counted, alerted at the threshold) or "stale" (a heartbeat
  // the engine itself reports as stale, alerted at once).
  let failures = 0;
  let episode = null;

  // Per kind: the moments notifications went out, what the limit suppressed, and
  // when a summary last went for that kind.
  const sentTimes = new Map();
  const suppressed = new Map();
  const summaryAt = new Map();

  // The moments the capped high kind (`ai_preview`) went out, one count of what
  // its window held back, and the moment the last preview summary went; the
  // summary itself is not part of the window.
  const highSentTimes = [];
  let previewsSuppressed = 0;
  let previewSummaryAt = null;

  function resolveKeyKind() {
    const raw = typeof keyKindOption === "function" ? keyKindOption() : keyKindOption;
    return raw === "install" ? "install" : "owner";
  }

  /** The moments of the last hour kept for one kind, oldest dropped. */
  function recentTimes(kind, at) {
    const kept = (sentTimes.get(kind) || []).filter((stamp) => at - stamp < HOUR_MS);
    sentTimes.set(kind, kept);
    return kept;
  }

  function underLimit(kind, at) {
    return recentTimes(kind, at).length < hourlyLimit;
  }

  function countSend(kind, at) {
    const kept = recentTimes(kind, at);
    kept.push(at);
    sentTimes.set(kind, kept);
  }

  /** The capped high notifications (`ai_preview`) of the last hour, newest last. */
  function recentHighTimes(at) {
    const kept = highSentTimes.filter((stamp) => at - stamp < HOUR_MS);
    highSentTimes.length = 0;
    for (const stamp of kept) highSentTimes.push(stamp);
    return highSentTimes;
  }

  function underHighLimit(at) {
    return recentHighTimes(at).length < highHourlyLimit;
  }

  function countHighSend(at) {
    recentHighTimes(at).push(at);
  }

  /** Hand one notification to the writer; a writer that throws is swallowed. */
  async function send(note) {
    try {
      await notify(note);
      return true;
    } catch {
      return false;
    }
  }

  /** Open an episode: one high note, the first time the engine is really gone. */
  async function startEpisode(reason) {
    if (episode !== null) return false;
    episode = reason;
    return send({ priority: "high", title: NOT_RESPONDING_TITLE, body: NOT_RESPONDING_BODY });
  }

  /**
   * One failed reach of the engine.  It counts, and the count only alerts once:
   * an episode already open is never announced twice.
   */
  async function noteUnreachable() {
    failures += 1;
    if (episode !== null) return false;
    if (failures < failureThreshold) return false;
    return startEpisode("unreachable");
  }

  /** The engine says its own heartbeat is stale: that is an episode at once. */
  async function noteStale() {
    return startEpisode("stale");
  }

  /** The engine answers again: close the episode with one note. */
  async function noteUp() {
    failures = 0;
    if (episode === null) return false;
    episode = null;
    return send({ priority: "normal", title: BACK_TITLE, body: BACK_BODY });
  }

  /** One summary per kind per hour, for what the limit held back. */
  async function flushSummaries(at) {
    let count = 0;
    for (const [kind, pending] of [...suppressed.entries()]) {
      if (!pending) continue;
      const last = summaryAt.get(kind);
      if (last !== undefined && at - last < HOUR_MS) continue;
      const title = `${pending} more ${kind} updates`;
      await send({
        priority: "normal",
        title,
        body: `${pending} more ${kind} updates were not shown one by one.`,
      });
      summaryAt.set(kind, at);
      suppressed.set(kind, 0);
      count += 1;
    }
    return count;
  }

  /**
   * One summary an hour for the previews the window held back: the count keeps
   * growing across polls until a summary carries it, and the summary itself
   * counts toward no limit.
   */
  async function flushPreviewSummary(at) {
    if (!previewsSuppressed) return 0;
    if (previewSummaryAt !== null && at - previewSummaryAt < HOUR_MS) return 0;
    const pending = previewsSuppressed;
    previewsSuppressed = 0;
    previewSummaryAt = at;
    const headline = `${pending} ${PREVIEW_SUMMARY}`;
    const delivered = await send({
      priority: "high",
      title: headline,
      body: `${headline} - open the Trading panel`,
      action_url: TRADING_PANEL_URL,
    });
    return delivered ? 1 : 0;
  }

  /** Move the engine's cursor forward, and follow a lost lease. */
  async function postCursor() {
    if (!client || typeof client.leaseCursor !== "function" || holder === undefined || holder === null) {
      return null;
    }
    let result;
    try {
      result = await client.leaseCursor(holder, cursor, { keyKind: resolveKeyKind() });
    } catch {
      return null;
    }
    if (!result || result.ok) return result || null;
    if (result.code === LEASE_NOT_HELD) {
      holding = false;
    }
    // CURSOR_AHEAD needs no handling: the feed answers the next poll with its
    // reset page, which adopts the newest id there is.
    return result;
  }

  async function pollOnce() {
    if (!holding) return { skipped: "not_holding" };

    let result;
    try {
      result = await client.events({ after: cursor, limit: pageLimit });
    } catch {
      result = { ok: false, code: UNREACHABLE };
    }
    if (!result || !result.ok) {
      const code = result && result.code ? result.code : UNREACHABLE;
      if (code !== UNREACHABLE) return { sent: 0, cursor, error: code };
      await noteUnreachable();
      return { sent: 0, cursor, error: code };
    }

    failures = 0;
    let sent = 0;
    // A page that reads ends the episode the failed reads opened.  A stale
    // heartbeat is the engine's own report, so only health can say it is over:
    // a feed that still answers says nothing about the watchdog.
    if (episode === "unreachable" && (await noteUp())) sent += 1;

    const data = result.data && typeof result.data === "object" ? result.data : {};

    if (data.reset) {
      const newest = wholeNumber(data.last_id);
      cursor = newest === null ? cursor : Math.max(0, newest);
      if (await send({ priority: "normal", title: RESET_TITLE, body: RESET_BODY })) sent += 1;
      await postCursor();
      return { sent, cursor };
    }

    const events = Array.isArray(data.events) ? data.events : [];
    if (onEvents) {
      try {
        await onEvents(events);
      } catch {
        // The audit trail is best effort; the feed is read either way.
      }
    }

    const at = now();
    for (const event of events) {
      const note = mapEvent(event);
      if (!note) continue;
      if (note.priority === "high") {
        // Only a preview belongs to the window; a live switch, a halt, a
        // watchdog, an alert or a credentials fault is sent whatever the window
        // holds, and never counts toward it.
        if (!CAPPED_URGENT_KINDS.has(note.kind)) {
          if (await send(note)) sent += 1;
          continue;
        }
        if (!underHighLimit(at)) {
          previewsSuppressed += 1;
          continue;
        }
        countHighSend(at);
        if (await send(note)) sent += 1;
        continue;
      }
      if (!underLimit(note.kind, at)) {
        suppressed.set(note.kind, (suppressed.get(note.kind) || 0) + 1);
        continue;
      }
      countSend(note.kind, at);
      if (await send(note)) sent += 1;
    }
    sent += await flushSummaries(at);
    sent += await flushPreviewSummary(at);

    const newest = wholeNumber(data.last_id);
    if (newest !== null) cursor = Math.max(0, newest);
    await postCursor();
    return { sent, cursor };
  }

  return {
    pollOnce,
    /** Report what a health read saw: "up", "unreachable" or "stale". */
    noteReachability(kind) {
      if (kind === "stale") return noteStale();
      if (kind === "up") return noteUp();
      return noteUnreachable();
    },
    setCursor(value) {
      const next = wholeNumber(value);
      if (next !== null) cursor = Math.max(0, next);
    },
    getCursor() {
      return cursor;
    },
    setHolding(value) {
      holding = Boolean(value);
    },
    isHolding() {
      return holding;
    },
    state() {
      return {
        cursor,
        holding,
        failures,
        alerted: episode !== null,
        episode,
        suppressed: Object.fromEntries(suppressed.entries()),
        previewsSuppressed,
      };
    },
  };
}