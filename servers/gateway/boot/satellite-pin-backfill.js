/**
 * boot/satellite-pin-backfill.js — pin the ADDRESS of every satellite that was paired before the
 * pin existed.
 *
 * The host a satellite is dialled at lives in <CROW_HOME>/secrets/satellite-pins.json, a directory
 * a bot sandbox cannot read; `satellites.tailnet_host` it CAN write. Every sender therefore builds
 * its URL from the pin (servers/shared/satellite-pins.js: satelliteBaseUrlFor), and refuses when
 * the row says anything else.
 *
 * Rows made before that pin existed have no entry, and refusing all of them would break every live
 * satellite on upgrade. This runs ONCE, before any route serves, and pins each such row from its
 * CURRENT value — the last moment at which that address is still the operator's, not a bot's.
 *
 * ONCE EVER is enforced by a marker in its OWN file
 * (<CROW_HOME>/secrets/satellite-pin-backfill.json, written atomically — see
 * satellitePinBackfillPath), never by "are there any unpinned rows?": a marker is blind to the row
 * afterwards, so a bot that later rewrites tailnet_host can never get itself pinned by the next
 * reboot. A row whose address does not normalize stays unpinned (its senders refuse) until the
 * owner runs scripts/cli/satellite-pin.js.
 *
 * The trust limit is stated plainly: a row already tampered with before this ran is pinned to the
 * tampered address. The pinned ids are logged once (ids only, never a host) and `--show` lists them
 * so the owner can eyeball the result.
 *
 * Fail-soft: every error is logged and swallowed. A DB that could not be read (or one whose
 * satellite tables are not migrated yet) leaves the marker UNwritten, so the next boot tries again
 * — nothing is silently pinned from a stale or partial read.
 */
import {
  getSatellitePin,
  markSatellitePinBackfillDone,
  normalizeSatelliteHost,
  pinSatelliteHost,
  satellitePinBackfillDoneAt,
} from "../../shared/satellite-pins.js";
import { listSatellites, satellitesMigrated } from "../satellites/store.js";

/** A row this backfill should pin: not revoked, and no pin yet. */
export function needsSatellitePin(row) {
  return Boolean(row) && row.status !== "revoked" && !getSatellitePin(row.id);
}

/**
 * @param {object} o
 * @param {() => object} o.createDbClient   opens this instance's crow.db
 * @param {(msg: string) => void} [o.log]
 * @param {(msg: string) => void} [o.warn]
 * @returns {Promise<{ran: boolean, pinned: number, skipped: number, pending: number, alreadyDoneAt?: string}>}
 */
export async function runSatellitePinBackfill({ createDbClient, log = console.log, warn = console.warn } = {}) {
  const out = { ran: false, pinned: 0, skipped: 0, pending: 0 };
  let done = null;
  try { done = satellitePinBackfillDoneAt(); } catch (err) {
    warn(`[satellite-pin] could not read the one-time marker (${err?.code || "unreadable"})`);
    return out;
  }
  if (done) return { ...out, alreadyDoneAt: done };

  out.ran = true;
  let db = null;
  try {
    db = createDbClient();
    let migrated = false;
    try { migrated = await satellitesMigrated(db); } catch (err) {
      warn(`[satellite-pin] backfill skipped: the satellite tables could not be read (${err?.code || "read_failed"}) — it will retry on the next boot`);
      return out;
    }
    if (!migrated) {
      log("[satellite-pin] no satellite table yet; the one-time pin backfill will retry on the next boot");
      return out;
    }

    let rows = [];
    try { rows = await listSatellites(db); } catch (err) {
      warn(`[satellite-pin] backfill skipped: the satellite rows could not be read (${err?.code || "read_failed"}) — it will retry on the next boot`);
      return out;
    }

    if (rows.length === 0) {
      if (!markSatellitePinBackfillDone()) warn("[satellite-pin] could not write the one-time marker; nothing needed pinning, so the next boot retries (harmlessly)");
      else log("[satellite-pin] no satellites to pin (one-time)");
      return out;
    }

    const pinnedIds = [];
    let writeFailed = false;
    for (const row of rows) {
      if (!needsSatellitePin(row)) { out.skipped++; continue; }
      // The row's value is never logged, echoed or repaired: only a normalized address is pinned,
      // and anything else leaves that satellite unpinned until the owner runs the CLI.
      const host = normalizeSatelliteHost(row.tailnet_host);
      if (!host) {
        warn(`[satellite-pin] ${row.id} left unpinned (its address is not a valid satellite address)`);
        out.skipped++;
        continue;
      }
      if (pinSatelliteHost(row.id, host)) { out.pinned++; pinnedIds.push(row.id); } else { out.pending++; writeFailed = true; }
    }

    // A partial pass writes NO marker: the next boot retries with a clean read. Pins already
    // written now are left alone (the row is only ever trusted once).
    if (writeFailed || out.pending > 0) {
      warn(`[satellite-pin] ${out.pending} pin(s) could not be written; the one-time backfill will run again on the next boot`);
      return out;
    }
    if (!markSatellitePinBackfillDone()) {
      warn("[satellite-pin] could not write the one-time marker; the backfill will run again on the next boot (satellites pinned now are left alone)");
      return out;
    }
    if (pinnedIds.length) log(`[satellite-pin] pinned ${pinnedIds.length} satellite(s): ${pinnedIds.join(", ")}`);
    else log("[satellite-pin] no satellite needed a pin (one-time)");
  } catch (err) {
    // No marker on any unexpected failure: the next boot retries with a clean read.
    warn(`[satellite-pin] backfill skipped (${err?.code || "error"}) — it will retry on the next boot`);
  } finally {
    try { db?.close?.(); } catch { /* gone */ }
  }
  return out;
}