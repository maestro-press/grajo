/**
 * v1 Fix-it remedy (instant): grant a capability to the ONE peer that asked.
 *
 * N1b-8 (security audit): this used to add the capability to the local
 * all-trusted-peers allowlist (`remote_exposed_tools`), so a single click caused
 * by one peer's request exposed the capability to every peer, permanently.
 * Now:
 *   - the target peer is the VERIFIED instance id recorded on the card
 *     (`args.requestingInstance`, or the stored card's context as a fallback);
 *     there is deliberately NO path from here to the all-peer list;
 *   - a missing/ill-shaped peer id refuses the remedy (fail closed) rather than
 *     widening the grant;
 *   - a peer that is no longer TRUSTED here (revoked, paused, untrusted, or its
 *     row is gone) refuses too (review round 2, N-a): a revoke→re-pair reuses
 *     the instance id, so a grant left behind for an untrusted id would come
 *     alive the moment that id pairs again;
 *   - Fix round 3 (N1b-8): the peer's row can be trusted again because it
 *     RE-PAIRED under the same id — a different device (or the same one with a
 *     new token) that never asked. The card therefore carries
 *     `context.pairingTag`, a tag of the `auth_token_hash` that verified the
 *     request; the remedy refuses unless it equals the tag of the peer's
 *     CURRENT hash. A card with no tag (written before this round) refuses as
 *     well — fail closed, on a mismatch and on an unreadable row alike;
 *   - the grant's duration comes from the CLICKED action id (the card's own
 *     buttons, `CARD_DURATIONS`), never from the stored card's args: those are
 *     a snapshot of the detector's write, not the operator's choice at click
 *     time, so a stored `untilRemoved`/`days` could stretch a 30-day button
 *     into a permanent grant. Args that disagree with the action id refuse.
 *
 * Local-only: writes this instance's own settings; never a cross-instance write,
 * never synced.
 */
import { grantPeerCapability } from "../../peer-exposure-store.js";
import { normalizePeerId, normalizePairingTag, pairingTag } from "../../../shared/peer-id.js";
import { peerTrust } from "../../../shared/peer-trust.js";
import { CARD_DURATIONS } from "../peer-card-policy.js";

/** The duration each button's actionId means (`days: null` = until removed). */
const DAYS_BY_ACTION = new Map(CARD_DURATIONS.map((d) => [d.actionId, d.days]));
/** The id old cards posted, before the card offered a duration per button. */
export const LEGACY_ACTION_ID = "expose-capability";
/** What that old single button meant: the 30-day entry's duration. */
const LEGACY_DAYS = DAYS_BY_ACTION.get("expose-capability-30d");

/**
 * The refusal for a card raised by a pairing that is gone (re-pair, token
 * rotation, or a card written before cards carried a pairing at all).
 */
export const PAIRED_AGAIN_MESSAGE =
  "That device's pairing has changed since it asked, so nothing was shared. If it still needs this, it will ask again.";

/**
 * The duration the clicked action id means, or `undefined` when it means none
 * (an id this card never posts, or no id at all).
 */
function durationForAction(actionId) {
  if (typeof actionId !== "string") return undefined;
  if (actionId === LEGACY_ACTION_ID) return LEGACY_DAYS;
  return DAYS_BY_ACTION.has(actionId) ? DAYS_BY_ACTION.get(actionId) : undefined;
}

/**
 * Whether the stored args carry a duration that is NOT the clicked one. Args
 * with no duration field make no claim and agree; args that claim BOTH
 * "until removed" and a finite day count claim nothing coherent, so they
 * disagree with every button (including the forever one).
 */
function argsDisagree(args, days) {
  if (!args || typeof args !== "object") return false;
  const untilRemoved = args.untilRemoved === true;
  const hasDays = args.days !== undefined;
  if (!untilRemoved && !hasDays) return false;
  if (untilRemoved && args.days != null) return true;
  const argDays = untilRemoved || args.days === null ? null : Number(args.days);
  return argDays !== days;
}

export default async function exposeCapability(args, ctx) {
  const capability = args && typeof args.capability === "string" ? args.capability.trim() : "";
  if (!capability) return { resolved: false, message: "No capability specified." };
  // A federation peer's proxy entry (instance-<id>) is never a capability of
  // this instance: exposing it would let one peer reach another through us.
  if (capability.startsWith("instance-")) return { resolved: false, message: "That is another instance, not a capability of this one." };

  // The duration is the operator's choice AT CLICK TIME: the action id of the
  // button they pressed. The stored args only describe what the detector wrote
  // when the card was raised, so a duration in them that contradicts the button
  // is a forged/stale card — refuse it before anything is read or written.
  const days = durationForAction(ctx?.actionId);
  if (days === undefined) return { resolved: false, message: "Could not record the allowance." };
  if (argsDisagree(args, days)) return { resolved: false, message: "Could not record the allowance." };

  // The peer that asked, as recorded on the card from the verified request
  // identity. Never a name, never a value taken from the peer's own request.
  const peerId = normalizePeerId(args?.requestingInstance) || normalizePeerId(ctx?.item?.context?.requestingInstance);
  if (!peerId) {
    return { resolved: false, message: "This card has no verified requesting device, so the allowance cannot be limited to one. Nothing was shared." };
  }

  // N1b-8 review round 2 (N-a): the card is a snapshot of a past request; the
  // peer must still be trusted NOW. This is the same predicate the gate uses —
  // `enforcePeerExposure` only ever runs for an instance whose bearer hash
  // matched `TRUSTED_PEER_SQL` (trusted = 1 AND status IN ('active','offline'))
  // at the moment of use. A revoked or paused peer (or one this instance can no
  // longer read) is refused, and the lookup fails closed.
  const db = ctx?.db;
  if (!db) return { resolved: false, message: "Could not read this instance's peer list, so nothing was shared." };
  const trust = await peerTrust(db, peerId);
  if (!trust.ok) {
    const why = trust.reason === "trust_lookup_failed"
      ? "Crow couldn't confirm that device is still paired, so nothing was shared."
      : "That device isn't a trusted peer of this Crow any more, so nothing was shared. Pair it again and it can ask afresh.";
    return { resolved: false, message: why };
  }

  // Fix round 3 (N1b-8): the row being trusted again is NOT enough — a
  // revoke→re-pair reuses the instance id, so `peerTrust` passes for a device
  // that never made this request. `peerTrust` read the peer's row (`SELECT *
  // FROM crow_instances`) a moment ago, so its `auth_token_hash` is the CURRENT
  // pairing: the card must carry the tag of that same hash. A card with no tag
  // (written before this round) cannot be matched either, so it refuses too.
  // Fail closed: a missing/unreadable hash is a refusal, never a grant.
  const cardTag = normalizePairingTag(ctx?.item?.context?.pairingTag);
  const currentTag = pairingTag(trust.row?.auth_token_hash);
  if (!cardTag || !currentTag || cardTag !== currentTag) {
    return { resolved: false, message: PAIRED_AGAIN_MESSAGE };
  }

  const untilRemoved = days == null;
  const now = Date.now();
  const expiresAt = untilRemoved ? null : new Date(now + days * 86_400_000).toISOString();
  const result = await grantPeerCapability(db, { peerId, capability, expiresAt, now });
  if (!result.ok) return { resolved: false, message: "Could not record the allowance." };

  const when = untilRemoved ? "until you remove it" : `for ${days} day${days === 1 ? "" : "s"}`;
  console.log(`[fix-it] granted capability "${capability}" to peer ${peerId} ${when} (local scope)`);
  return { resolved: true, message: `${capability} is now shared with that device ${when}.` };
}