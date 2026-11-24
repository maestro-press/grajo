/**
 * boot/peer-origin-backfill.js — pin the paired gateway ORIGIN of every peer
 * that was paired before the pin existed.
 *
 * Peer credentials live in <CROW_HOME>/secrets/peer-tokens.json, which a
 * contained bot cannot read; `crow_instances.gateway_url` it CAN write. So the
 * origin a credential may be sent to is recorded in the store at pairing, and
 * every sender refuses a URL that normalizes to anything else
 * (servers/shared/peer-credentials.js: peerUrlAllowed).
 *
 * Pairs made before that pin existed have no `pinned_origin`, and refusing all
 * of them would break every live federation on upgrade. This runs ONCE, before
 * any route can serve, and pins each such peer from its CURRENT trusted row —
 * the last moment at which that address is still the operator's, not a bot's.
 *
 * ONCE EVER is enforced by a marker in its OWN file
 * (<CROW_HOME>/secrets/peer-pin-backfill.json, 0600, written atomically — see
 * peerPinBackfillPath), never by "are there any unpinned peers?": a marker is
 * blind to the row afterwards, so a bot that later rewrites gateway_url can
 * never get itself pinned by the next reboot. A marker USED to live as a
 * top-level key in the credential store, where every key is an instance id: the
 * trust sweeper deleted it (its mint time was -Infinity) and any store writer
 * on that id clobbered it, letting a later boot backfill again from bot-written
 * rows. A legacy key is migrated into the file on first read.
 * Peers whose row has no usable URL
 * stay unpinned (their senders refuse with `no-pin`) until the operator runs
 * scripts/cli/peer-pin.js.
 *
 * Fail-soft: every error is logged and swallowed. A DB that could not be read
 * leaves the marker UNwritten, so the next boot tries again — nothing is
 * silently pinned from a stale or partial read.
 */
import { TRUSTED_PEER_SQL } from "../../shared/peer-trust.js";
import {
  loadPeerCreds,
  normalizeGatewayOrigin,
  pinBackfillDoneAt,
  pinPeerOrigin,
  markPinBackfillDone,
} from "../../shared/peer-credentials.js";

/** Does this store entry still need a pin? (Metadata keys are never entries.) */
export function needsOriginPin(entry) {
  return !entry || typeof entry !== "object" || !entry.pinned_origin;
}

/**
 * @param {object} o
 * @param {() => object} o.createDbClient   opens this instance's crow.db
 * @param {(msg: string) => void} [o.log]
 * @param {(msg: string) => void} [o.warn]
 * @returns {Promise<{ran: boolean, pinned: number, skipped: number, pending: number, alreadyDoneAt?: string}>}
 */
export async function runPeerOriginBackfill({ createDbClient, log = console.log, warn = console.warn } = {}) {
  const out = { ran: false, pinned: 0, skipped: 0, pending: 0 };
  let done = null;
  try { done = pinBackfillDoneAt(); } catch (err) {
    warn(`[peer-pin] could not read the one-time marker: ${err?.message || err}`);
    return out;
  }
  if (done) return { ...out, alreadyDoneAt: done };

  out.ran = true;
  let db = null;
  try {
    let entries = {};
    try { entries = loadPeerCreds(); } catch (err) {
      warn(`[peer-pin] could not read the credential store: ${err?.message || err}`);
      return out;
    }
    const ids = Object.keys(entries).filter((id) => needsOriginPin(entries[id]));
    db = createDbClient();
    for (const id of ids) {
      let url = null;
      try {
        const r = await db.execute({
          sql: `SELECT id, gateway_url FROM crow_instances WHERE id = ? AND ${TRUSTED_PEER_SQL}`,
          args: [id],
        });
        url = r?.rows?.[0]?.gateway_url ?? null;
      } catch (err) {
        // A row we could not read is never guessed at; it stays unpinned.
        warn(`[peer-pin] could not read the peer row for ${id}: ${err?.message || err}`);
        out.pending++;
        continue;
      }
      if (!url || !normalizeGatewayOrigin(url)) { out.skipped++; continue; }
      if (pinPeerOrigin(id, url)) out.pinned++; else out.pending++;
    }
    if (!markPinBackfillDone()) {
      warn("[peer-pin] could not write the one-time marker; the backfill will run again on the next boot (peers pinned now are left alone)");
    }
    log(`[peer-pin] pinned ${out.pinned} peer(s) from their current address (one-time)`);
  } catch (err) {
    // No marker on a partial pass: the next boot retries with a clean read.
    warn(`[peer-pin] backfill skipped: ${err?.message || err}`);
  } finally {
    try { db?.close?.(); } catch { /* gone */ }
  }
  return out;
}