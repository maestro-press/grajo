/**
 * The three loops the Coinbase bundle runs from gateway boot.
 *
 * A panel is a view; these loops are not.  They are started when the bundle's
 * server module loads (gateway boot), so the lease is renewed, the sealed
 * credentials are re-pushed after an engine restart, and the event feed is read
 * whether or not anybody has the Trading page open.
 *
 * The loops are the client's only readers, and each of them is quiet about the
 * states that are not news:
 *
 * - a pinned engine with no key in memory, a disconnected owner, and an engine
 *   that refused the lease all read as "not connected"; nothing is notified and
 *   nothing is retried in a storm;
 * - an engine that was reset (no pin where the connection remembers an install)
 *   stops the credential push and asks the panel for a reconnect, once; a
 *   connection whose Disconnect has not finished (the store reports
 *   `disconnecting`) has no pin because the owner asked for that, so it is
 *   left alone instead — until a health read shows the pin is still there,
 *   which clears the stale flag so it cannot hide a later real reset;
 * - a rate-limited credential push waits as long as the engine asked; a push the
 *   engine could not take (it did not answer, or answered 5xx), and one it
 *   answered KEY_INVALID to (a passing Coinbase fault), is retried on a growing,
 *   capped wait, while any other refusal the engine answered is one high alert
 *   per episode and a five minute wait; a KEY_INVALID run only reaches the owner
 *   once it has persisted, and a push that succeeds, or health that shows the
 *   engine's credentials ready, ends the episode;
 * - an engine that stops answering its health route is one "not responding"
 *   alert per episode, counting from the health reads themselves so it arrives
 *   whether or not this gateway holds the lease.
 *
 * Audit entries ride on the notify poll: events the engine tagged as written by
 * an MCP call are appended to the project timeline of the project the caller
 * names, once per event, keyed by the event's own id and timestamp.
 */
import { createHash } from "node:crypto";

import { appImport } from "./app-root.js";
import { createNotifier } from "./notifier.js";

const AUDIT_ACTION = "coinbase.mcp_event";
const AUDIT_ACTOR = "coinbase-mcp";
const AUDIT_ACTOR_TYPE = "system";
const EVENT_TARGET_PREFIX = "engine-event:";

const HOLDER_PREFIX = "gw-";
const HOLDER_HEX_CHARS = 24;

const TRADING_PANEL_URL = "/dashboard/coinbase";

const DEFAULT_INTERVALS = Object.freeze({ lease: 20000, repush: 30000, notify: 15000 });
const DEFAULT_RATE_LIMITED_RETRY_S = 60;
const OTHER_FAILURE_RETRY_MS = 5 * 60 * 1000;
// The waits a re-push the engine could not take grows through, in seconds; the
// last one is where it stays.
const TRANSIENT_REPUSH_BACKOFF_S = Object.freeze([30, 60, 120, 300]);
const SECRET_MISMATCH = "SECRET_MISMATCH";
// The one key refusal the engine answers to a passing Coinbase fault: it backs
// off like a transient failure and is only told to the owner once the run of
// them is long enough to be news.
const KEY_INVALID = "KEY_INVALID";
const KEY_INVALID_ALERT_COUNT = 3;
const KEY_INVALID_ALERT_AFTER_MS = 5 * 60 * 1000;

const RESET_TITLE = "Trading engine was reset";
const RESET_BODY = "Trading engine was reset; reconnect in the Trading panel";
const ATTENTION_TITLE = "Coinbase connection needs attention";
const ATTENTION_BODY = "Crow could not install the Coinbase key the engine needs; reconnect in the Trading panel";
// A run of KEY_INVALID refusals is not a key the owner has to replace: the
// engine is failing to reach Coinbase while Crow keeps trying the same key.
const ATTENTION_RETRYING_BODY = "Coinbase isn't answering; Crow keeps retrying.";

/**
 * The lease holder id for one Crow home: "gw-" and 24 hex of its sha256.
 *
 * The engine takes a holder of 1 to 128 characters of `[A-Za-z0-9._:-]`, so this
 * shape is always a legal holder, and two gateways over two homes never read as
 * one holder.
 */
export function holderId(crowHome) {
  const text = typeof crowHome === "string" ? crowHome : String(crowHome === undefined || crowHome === null ? "" : crowHome);
  const digest = createHash("sha256").update(text, "utf8").digest("hex");
  return HOLDER_PREFIX + digest.slice(0, HOLDER_HEX_CHARS);
}

/** Whether an existence answer means "already there": a row list, or a boolean. */
function saysExists(answer) {
  if (Array.isArray(answer)) return answer.length > 0;
  return Boolean(answer);
}

/** The event's own timestamp as text, or an empty string. */
function eventTimestamp(event) {
  const ts = event && event.ts;
  return ts === undefined || ts === null ? "" : String(ts);
}

/**
 * Whether a refused re-push is worth another attempt soon: the engine never
 * answered, or answered that it could not act.
 */
function isTransientRepushFailure(code, status) {
  if (code === "ENGINE_UNREACHABLE") return true;
  if (status === 0) return true;
  return status >= 500;
}


/** The audit-existence question over one instance's database. */
export function auditExistsFor(db) {
  return async (target) => {
    const result = await db.execute({
      sql: "SELECT 1 FROM project_audit_log WHERE action='coinbase.mcp_event' AND target=? LIMIT 1",
      args: [target],
    });
    return result && Array.isArray(result.rows) ? result.rows : [];
  };
}

/**
 * The app pieces the loops need, loaded at run time from the Crow app root.
 *
 * The bundle is installed under a Crow home, so it reaches the app it belongs to
 * through `appImport` rather than importing a sibling path that does not exist
 * in an installed copy.  The paths are literals so the bundle's package graph
 * stays statically readable.
 */
export async function defaultWiring() {
  const notifications = await appImport("servers/shared/notifications.js");
  const acl = await appImport("servers/shared/project-acl.js");
  const crowHome = await appImport("servers/shared/crow-home.js");
  return {
    createNotification: notifications.createNotification,
    appendAudit: acl.appendAudit,
    resolveCrowHome: crowHome.resolveCrowHome,
  };
}

/**
 * Start the loops.
 *
 * `connection` is the panel's connection store: it knows which project this
 * install is bound to, which engine epoch the sealed credentials belong to,
 * whether a reconnect is already being asked for, and whether a Disconnect is
 * still in flight.  `repush()` pushes the sealed
 * credentials and answers a client result; `clearDisconnecting()`, when the
 * store offers it, drops a halfway flag a health read has just disproved.  No
 * secret reaches this module.
 *
 * The three timers are registered at call time, and the lease and repush ticks
 * each run once immediately, so a gateway that just booted has a lease within a
 * request rather than within one interval.  A tick never throws, and a tick that
 * is still running makes the next one of its own kind skip instead of queueing.
 */
export function startLoops(options = {}) {
  const config = options || {};
  const client = config.client;
  const notify = typeof config.notify === "function" ? config.notify : async () => null;
  const connection = config.connection;
  const db = config.db;
  const holder = config.holder;
  const getProjectId = typeof config.getProjectId === "function" ? config.getProjectId : () => null;
  const appendAudit = typeof config.appendAudit === "function" ? config.appendAudit : null;
  const auditExists = typeof config.auditExists === "function" ? config.auditExists : null;
  const now = typeof config.now === "function" ? config.now : Date.now;
  const timers = config.timers && typeof config.timers === "object" ? config.timers : {};
  const setIntervalImpl = typeof timers.setInterval === "function" ? timers.setInterval : setInterval;
  const clearIntervalImpl = typeof timers.clearInterval === "function" ? timers.clearInterval : clearInterval;
  const createNotifierImpl = typeof config.createNotifierImpl === "function" ? config.createNotifierImpl : createNotifier;

  const intervalConfig = config.intervalsMs && typeof config.intervalsMs === "object" ? config.intervalsMs : {};
  const intervals = {
    lease: Number.isFinite(intervalConfig.lease) ? intervalConfig.lease : DEFAULT_INTERVALS.lease,
    repush: Number.isFinite(intervalConfig.repush) ? intervalConfig.repush : DEFAULT_INTERVALS.repush,
    notify: Number.isFinite(intervalConfig.notify) ? intervalConfig.notify : DEFAULT_INTERVALS.notify,
  };

  const state = {
    engine: "unknown",
    mode: "unknown",
    holding: false,
    lastError: null,
    repushNotBefore: 0,
  };

  // The key kind the lease was last taken with: an engine with no pin takes the
  // install token, a pinned one the owner's key.
  let leaseKeyKind = "owner";
  // The reset notice is sent once per episode: the connection's own flag is the
  // guard when marking it works, and this one covers a marking that fails.
  const resetEpisode = { notified: false };
  // A refused key is told to the owner once per episode; a re-push the engine
  // could not take backs off instead, through these steps.  The KEY_INVALID run
  // counts its own failures and dates its first one, because that refusal is
  // only news once it has persisted.
  const repushEpisode = { alerted: false };
  const keyInvalidRun = { failures: 0, firstAt: null };
  let repushBackoffStep = 0;
  const running = { lease: false, repush: false, notify: false };
  const handles = [];

  async function readConnection() {
    if (!connection || typeof connection.get !== "function") return null;
    const found = await connection.get();
    return found && typeof found === "object" ? found : null;
  }

  /**
   * A health read that shows the pin still there says no Disconnect was in flight after all.
   *
   * The halfway flag a crashed Disconnect leaves behind would otherwise hide the next real
   * reset — an unpinned engine read as "the owner asked for that" — so it goes on the first
   * read that finds the engine still pinned. A store without the method (an older injected
   * one) is simply not asked, and no failure here changes what a tick decides.
   */
  async function clearStaleDisconnecting(pinned, conn) {
    if (pinned === false) return;
    if (!conn || conn.disconnecting !== true) return;
    if (!connection || typeof connection.clearDisconnecting !== "function") return;
    try {
      await connection.clearDisconnecting();
    } catch {
      // A store that cannot write changes nothing here: the next read asks again.
    }
  }

  /** A re-push that ended the episode arms both guards for the next one. */
  function closeRepushEpisode() {
    repushEpisode.alerted = false;
    keyInvalidRun.failures = 0;
    keyInvalidRun.firstAt = null;
    repushBackoffStep = 0;
  }

  /**
   * The owner was told once this episode; a writer that fails changes nothing.
   * `body` is the sentence this refusal earns: the reconnect one by default,
   * the retrying one for a KEY_INVALID run.
   */
  async function alertAttention(body = ATTENTION_BODY) {
    if (repushEpisode.alerted) return;
    repushEpisode.alerted = true;
    try {
      await notify({
        priority: "high",
        title: ATTENTION_TITLE,
        body,
        action_url: TRADING_PANEL_URL,
      });
    } catch {
      // A notification writer that fails changes nothing about the refusal.
    }
  }

  /** Report a health read to the notifier, when it can take one. */
  async function reportReachability(kind) {
    if (!notifier || typeof notifier.noteReachability !== "function") return;
    await notifier.noteReachability(kind);
  }

  /** Append the audit rows for the MCP-tagged events of one page. */
  async function auditEvents(events) {
    if (!appendAudit || !db || !Array.isArray(events) || events.length === 0) return;
    let projectId;
    try {
      projectId = await getProjectId();
    } catch {
      return;
    }
    if (projectId === undefined || projectId === null || projectId === "") return;
    for (const event of events) {
      try {
        if (!event || typeof event !== "object") continue;
        const data = event.data;
        if (!data || typeof data !== "object" || data.source !== "mcp") continue;
        const target = `${EVENT_TARGET_PREFIX}${eventTimestamp(event)}:${event.id}`;
        if (auditExists) {
          const found = await auditExists(target);
          if (saysExists(found)) continue;
        }
        await appendAudit(db, {
          project_id: projectId,
          actor_type: AUDIT_ACTOR_TYPE,
          actor_id: AUDIT_ACTOR,
          action: AUDIT_ACTION,
          target,
          payload: {
            id: event.id,
            ts: event.ts,
            level: event.level,
            kind: event.kind,
            owner: event.owner,
            message: event.message,
          },
        });
      } catch {
        // One event that cannot be audited never stops the page.
      }
    }
  }

  const notifier = createNotifierImpl({
    client,
    notify,
    holder,
    now,
    onEvents: auditEvents,
    keyKind: () => leaseKeyKind,
  });

  async function leaseTick() {
    const health = await client.health();
    if (!health || !health.ok) {
      if (health && health.code === "ENGINE_UNREACHABLE") {
        state.engine = "unreachable";
        // Counted from here rather than from the feed: an engine that never
        // answers is news whether or not this gateway ever holds the lease.
        await reportReachability("unreachable");
        return;
      }
      state.engine = "error";
      state.lastError = health && health.code ? health.code : "ENGINE_UNREACHABLE";
      return;
    }
    state.engine = "up";
    const data = health.data && typeof health.data === "object" ? health.data : {};
    // A health body whose own `ok` is false is the engine reporting a stale
    // heartbeat: it is answering, so it still leases, and it is one alert.
    await reportReachability(data.ok === false ? "stale" : "up");
    const conn = await readConnection();
    await clearStaleDisconnecting(data.pinned, conn);

    let keyKind;
    if (data.pinned === false) {
      keyKind = "install";
    } else if (data.credentials === "ready" && conn && !conn.needsReconnect) {
      keyKind = "owner";
    } else {
      state.mode = "not_connected";
      state.holding = false;
      notifier.setHolding(false);
      return;
    }
    leaseKeyKind = keyKind;

    const lease = await client.lease(holder, { keyKind });
    if (lease && lease.ok) {
      const wasHolding = notifier.isHolding();
      const held = Boolean(lease.data && lease.data.held);
      notifier.setHolding(held);
      state.holding = held;
      state.mode = held ? "holding" : "waiting";
      if (!wasHolding && held) {
        notifier.setCursor(lease.data ? lease.data.cursor : 0);
      }
      return;
    }

    const code = lease && lease.code ? lease.code : "ENGINE_UNREACHABLE";
    if (code === "APPROVAL_INVALID" || code === "NOT_CONNECTED") {
      state.mode = "not_connected";
      state.holding = false;
      notifier.setHolding(false);
      return;
    }
    state.holding = false;
    notifier.setHolding(false);
    state.lastError = code;
  }

  async function repushTick() {
    const health = await client.health();
    if (!health || !health.ok) {
      if (health && health.code === "ENGINE_UNREACHABLE") state.engine = "unreachable";
      return;
    }
    const data = health.data && typeof health.data === "object" ? health.data : {};
    const conn = await readConnection();
    if (!conn) return;
    await clearStaleDisconnecting(data.pinned, conn);

    if (data.pinned !== false) {
      // The engine has a pin again (or still): the next wipe would be a new
      // episode, so the in-memory guard is armed again.
      resetEpisode.notified = false;
    }

    if (data.pinned === false && conn.engineEpoch) {
      // A disconnect that did not finish leaves the engine unpinned on purpose: that is the
      // engine obeying the owner, not the engine losing its pin, so nothing is flagged and
      // nobody is told. A retried Disconnect finishes it.
      if (conn.disconnecting) return;
      // The engine forgot its pin while the connection remembers an install:
      // pushing now would seal nothing the engine would take.
      if (resetEpisode.notified) return;
      resetEpisode.notified = true;
      if (!conn.needsReconnect) {
        try {
          await connection.markNeedsReconnect();
        } catch {
          // The notice still goes: the owner has to reconnect either way.
        }
        try {
          await notify({
            priority: "high",
            title: RESET_TITLE,
            body: RESET_BODY,
            action_url: TRADING_PANEL_URL,
          });
        } catch {
          // A notification writer that fails changes nothing about the wipe.
        }
      }
      return;
    }

    if (data.credentials === "ready") {
      // The engine holds a key it accepts, so whatever refused the last push is
      // over: the next refusal is a new episode and starts at the first wait.
      closeRepushEpisode();
      state.repushNotBefore = 0;
      return;
    }

    if (data.credentials !== "not_ready" || data.pinned === false || conn.needsReconnect) return;
    if (now() < state.repushNotBefore) return;

    const result = await connection.repush();
    if (result && result.ok) {
      state.repushNotBefore = 0;
      state.lastError = null;
      closeRepushEpisode();
      return;
    }

    const code = result && typeof result.code === "string" && result.code ? result.code : "ENGINE_UNREACHABLE";
    if (code === "RATE_LIMITED") {
      const waitS = Number.isFinite(result.retryAfterS) ? result.retryAfterS : DEFAULT_RATE_LIMITED_RETRY_S;
      state.repushNotBefore = now() + (waitS || DEFAULT_RATE_LIMITED_RETRY_S) * 1000;
      return;
    }
    state.lastError = code;

    const status = result && Number.isFinite(result.status) ? result.status : 0;
    if (code === KEY_INVALID) {
      // The engine answers this to a passing Coinbase fault, so retry on the
      // same ladder as a re-push it could not take, and tell the owner only
      // once the run of them is long enough to be worth a look.
      if (keyInvalidRun.firstAt === null) keyInvalidRun.firstAt = now();
      keyInvalidRun.failures += 1;
      const waitS = TRANSIENT_REPUSH_BACKOFF_S[Math.min(repushBackoffStep, TRANSIENT_REPUSH_BACKOFF_S.length - 1)];
      repushBackoffStep += 1;
      state.repushNotBefore = now() + waitS * 1000;
      const at = now();
      const persisted =
        keyInvalidRun.failures >= KEY_INVALID_ALERT_COUNT || at - keyInvalidRun.firstAt >= KEY_INVALID_ALERT_AFTER_MS;
      if (persisted) await alertAttention(ATTENTION_RETRYING_BODY);
      return;
    }

    if (isTransientRepushFailure(code, status)) {
      const waitS = TRANSIENT_REPUSH_BACKOFF_S[Math.min(repushBackoffStep, TRANSIENT_REPUSH_BACKOFF_S.length - 1)];
      repushBackoffStep += 1;
      state.repushNotBefore = now() + waitS * 1000;
      return;
    }

    // Anything else the engine answered is told to the owner at once, once per
    // episode: no amount of retrying it soon will make the engine take the key.
    state.repushNotBefore = now() + OTHER_FAILURE_RETRY_MS;
    if (code === SECRET_MISMATCH && !conn.needsReconnect) {
      try {
        await connection.markNeedsReconnect();
      } catch {
        // The notice still goes: the owner has to reconnect either way.
      }
    }
    await alertAttention();
  }

  async function notifyTick() {
    await notifier.pollOnce();
    state.holding = notifier.isHolding();
  }

  /** Run one tick, skipping a run that is still going, and never throwing. */
  async function run(name, tick) {
    if (running[name]) return undefined;
    running[name] = true;
    try {
      await tick();
      return undefined;
    } catch {
      return undefined;
    } finally {
      running[name] = false;
    }
  }

  function schedule(name, ms, tick) {
    const handle = setIntervalImpl(() => {
      void run(name, tick);
    }, ms);
    if (handle && typeof handle.unref === "function") handle.unref();
    handles.push(handle);
    return handle;
  }

  schedule("lease", intervals.lease, leaseTick);
  schedule("repush", intervals.repush, repushTick);
  schedule("notify", intervals.notify, notifyTick);

  void run("lease", leaseTick);
  void run("repush", repushTick);

  return {
    stop() {
      for (const handle of handles) {
        try {
          clearIntervalImpl(handle);
        } catch {
          // A timer that cannot be cleared is already gone.
        }
      }
      handles.length = 0;
    },
    ticks: {
      lease: () => run("lease", leaseTick),
      repush: () => run("repush", repushTick),
      notify: () => run("notify", notifyTick),
    },
    state() {
      return {
        engine: state.engine,
        mode: state.mode,
        holding: state.holding,
        lastError: state.lastError,
        repushNotBefore: state.repushNotBefore,
        cursor: notifier.getCursor(),
      };
    },
  };
}