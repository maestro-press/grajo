/**
 * Crow-initiated satellite pairing (SAT-1, spec §4.2) and unpair (§3.3), crow side.
 *
 * Every pairing packet flows crow → satellite over the satellite's Serve :443:
 *   1. startPairing: POST /satellite/v1/pair/hello {nonce_c}; check the hello signature and that
 *      satellite_id derives from satellite_pubkey; look the address up with `tailscale whois`
 *      (when that fails the answer says warning "whois_unavailable" and complete then needs an
 *      explicit confirm_without_whois). The host must be a *.ts.net name or a 100.64.0.0/10
 *      address. A pending record is kept in memory only (10 min, at most 8). Nothing is signed.
 *   2. completePairing (the owner confirmed and typed the code): the code is normalised (and a
 *      malformed one refused) before any network; crow makes the mgmt key, signs the cert, sends
 *      the MAC (never the code), verifies the done signature, PINS the ceremony's host outside
 *      crow.db, then inserts the `satellites` row. A failed pin write fails the pairing; a failed
 *      row write puts the previous pin back. Any failure shreds the new key and inserts nothing.
 *      The pending record is claimed synchronously, so two concurrent completes can't both
 *      proceed. A revoked row for the same satellite is replaced in place on success (re-pair,
 *      spec §4.3).
 *   3. unpairSatellite: signed POST /satellite/v1/unpair (best-effort), then crow's side alone:
 *      row revoked, signed revocation stored, the address pin dropped; the mgmt key is shredded
 *      and tool pins deleted whatever fails first.
 *
 * Network calls are injectable (`fetchImpl`, `whoisImpl`); errors are PairingError {code, status}.
 */
import { randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import {
  AGENT_PROTOCOL, satelliteIdFromPub, isSatelliteId, formatFingerprint, verifyBytes,
  helloSigningString, doneSigningString, normalizePairCode, pairMac, certSha256,
} from "../../shared/satellite-protocol.js";
import {
  getSatellitePin, isTailnetIPv4, normalizeSatelliteHost, pinSatelliteHost, unpinSatellite,
} from "../../shared/satellite-pins.js";
import { loadIdentityIfPresent } from "../../sharing/identity.js";
import { getOrCreateLocalInstanceId, selfPairingAddress } from "../instance-registry.js";
import { getBootSha } from "../convergence.js";
import {
  getSatellite, insertSatellite, markRevoked, recordRevocation, deleteToolPins,
  satellitesMigrated, replaceRevokedSatellite,
} from "./store.js";
import { createMgmtKey, shredMgmtKey } from "./mgmt-keys.js";
import { issueCert, revokeSatelliteRecord } from "./certs.js";
import { satelliteFetch, pairingBaseUrl, readCapped, assertJsonResponse, sendOnce } from "./client.js";

export const PENDING_TTL_MS = 10 * 60000;
export const MAX_PENDING = 8;
export const STARTS_PER_MINUTE = 10;
const PAIR_MAX_BYTES = 64 * 1024;

export class PairingError extends Error {
  constructor(code, status, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
    this.status = status;
    if (detail !== undefined) this.detail = detail;
  }
}
const fail = (code, status, detail) => new PairingError(code, status, detail);

// The pairing host form lives in servers/shared/satellite-pins.js now (the pin module is shared with
// the CLI and the tests, and the pin compare must use exactly the same rules the ceremony used).
// Re-exported here so every existing importer of pairing.js keeps working.
export const normalizeHost = normalizeSatelliteHost;
export { isTailnetIPv4 };

const NAME_MAX = 64;
function normalizeName(input, host) {
  const n = typeof input === "string" ? input.trim() : "";
  const name = n || host.split(".")[0];
  if (!name || name.length > NAME_MAX || /[\u0000-\u001f\u007f]/.test(name)) return null;
  return name;
}

/** `tailscale whois --json` output → {node, tags} for a tagged node, else {node, login}. */
export function parseWhois(j) {
  const node = j?.Node;
  if (!node || typeof node.Name !== "string") return null;
  const name = node.Name.replace(/\.$/, "");
  const tags = Array.isArray(node.Tags) ? node.Tags.filter((t) => typeof t === "string") : [];
  if (tags.length) return { node: name, tags };
  const login = j?.UserProfile?.LoginName;
  return typeof login === "string" && login ? { node: name, login } : { node: name };
}

/** Resolve `host` (MagicDNS) and run `tailscale whois --json <addr>`. Null on any failure. */
export async function defaultWhois(host, { timeoutMs = 5000 } = {}) {
  let addr = host;
  if (!isIP(host)) addr = (await dnsLookup(host, { family: 0 })).address;
  const out = await new Promise((resolve, reject) => {
    execFile("tailscale", ["whois", "--json", addr], { timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
  return parseWhois(JSON.parse(out));
}

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ERR_CODE = /^[a-z0-9_]{1,48}$/;

export function createPairingService({
  fetchImpl = globalThis.fetch,
  whoisImpl = defaultWhois,
  identityFn = () => loadIdentityIfPresent(),
  instanceIdFn = getOrCreateLocalInstanceId,
  primaryUrlFn = async (db) => (await selfPairingAddress(db)).gateway_url,
  targetShaFn = getBootSha,
  env = process.env,
  now = Date.now,
  timeoutMs = 15000,
} = {}) {
  const pending = new Map();
  const inflight = new Set(); // satellite ids with a complete in flight
  let starts = [];

  const sweep = () => {
    const t = now();
    for (const [id, p] of pending) if (p.expires <= t) pending.delete(id);
  };

  /** POST a JSON body to an unpaired satellite; returns {status, json}. */
  async function postPair(host, path, obj) {
    const res = await sendOnce(fetchImpl, pairingBaseUrl(host) + path, {
      method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(obj), timeoutMs,
    });
    try {
      assertJsonResponse(res);
      const raw = await readCapped(res, PAIR_MAX_BYTES);
      return { status: res.status, json: JSON.parse(raw.toString("utf8")) };
    } catch (err) {
      throw fail("protocol", 502, err?.code === "protocol" ? err.message : "response is not JSON");
    }
  }

  async function startPairing({ host } = {}) {
    const h = normalizeHost(host);
    if (!h) throw fail("bad_host", 400);
    sweep();
    if (pending.size >= MAX_PENDING) throw fail("too_many_pending", 429);
    const t = now();
    starts = starts.filter((s) => t - s < 60000);
    if (starts.length >= STARTS_PER_MINUTE) throw fail("rate_limited", 429);
    starts.push(t);

    const nonce_c = randomBytes(16).toString("hex");
    let r;
    try {
      r = await postPair(h, "/satellite/v1/pair/hello", { nonce_c });
    } catch (err) {
      if (err instanceof PairingError) throw err;
      throw fail("unreachable", 502);
    }
    if (r.status !== 200) throw fail("pairing_refused", 400, ERR_CODE.test(r.json?.error) ? r.json.error : "hello_refused");
    const { satellite_id, satellite_pubkey, nonce_s, agent_protocol, sig } = r.json || {};
    if (!isSatelliteId(satellite_id) || !HEX64.test(satellite_pubkey ?? "") || !HEX32.test(nonce_s ?? "") || typeof sig !== "string") {
      throw fail("protocol", 502, "malformed hello");
    }
    if (agent_protocol !== AGENT_PROTOCOL) throw fail("protocol", 502, "unsupported agent protocol");
    if (satelliteIdFromPub(satellite_pubkey) !== satellite_id) throw fail("id_mismatch", 502);
    const signed = Buffer.from(helloSigningString({ nonceC: nonce_c, nonceS: nonce_s, satelliteId: satellite_id }), "utf8");
    if (!verifyBytes(satellite_pubkey, signed, sig)) throw fail("bad_hello_sig", 502);

    let whois = null;
    try { whois = await whoisImpl(h); } catch { whois = null; }
    if (!whois) whois = { unknown: true };

    sweep();
    if (pending.size >= MAX_PENDING) throw fail("too_many_pending", 429);
    const pairing_id = randomBytes(16).toString("hex");
    pending.set(pairing_id, {
      host: h, nonce_c, nonce_s, satellite_id, satellite_pubkey, agent_protocol, whois, expires: now() + PENDING_TTL_MS,
    });
    const out = { pairing_id, satellite_id, fingerprint: formatFingerprint(satellite_id), whois };
    if (whois.unknown) out.warning = "whois_unavailable"; // complete then needs confirm_without_whois
    return out;
  }

  async function assertMigrated(db) {
    if (!(await satellitesMigrated(db))) throw fail("not_migrated", 503);
  }

  /** Make the mgmt key without ever replacing a live one; a key left by a crashed attempt is shredded. */
  function freshMgmtKey(satId) {
    try {
      return createMgmtKey(satId, { replace: false, env });
    } catch (err) {
      if (!/already exists/.test(String(err?.message))) throw err;
      // We hold the in-flight claim for this satellite and its row is absent or revoked
      // (checked by the caller), so no live pairing uses this file: it is an orphan.
      shredMgmtKey(satId, { env });
      return createMgmtKey(satId, { replace: false, env });
    }
  }

  async function completePairing({ db, pairing_id, code, name, confirm_without_whois = false } = {}) {
    sweep();
    const p = typeof pairing_id === "string" ? pending.get(pairing_id) : undefined;
    if (!p) throw fail("unknown_pairing", 404);
    // Claim synchronously, before any await: a second complete for this id finds nothing.
    pending.delete(pairing_id);
    if (inflight.has(p.satellite_id)) {
      pending.set(pairing_id, p);
      throw fail("pairing_in_progress", 409);
    }
    inflight.add(p.satellite_id);
    // Pre-network refusals give the pending record back (it is still valid to retry).
    const refuse = (code, status) => {
      if (p.expires > now()) pending.set(pairing_id, p);
      return fail(code, status);
    };
    try {
      const norm = normalizePairCode(code);
      if (!norm) throw refuse("bad_code", 400);
      // The pin is only ever written from the ceremony's OWN vetted host. If a pending record ever
      // carried none, refuse rather than fall back to a row value (a contained bot can write the
      // row, so a host taken from it would undo the pin).
      if (!normalizeHost(p.host)) throw refuse("bad_host", 400);
      const label = normalizeName(name, p.host);
      if (!label) throw refuse("bad_name", 400);
      if (p.whois?.unknown && confirm_without_whois !== true) throw refuse("whois_required", 409);
      if (!(await satellitesMigrated(db))) throw refuse("not_migrated", 503);
      const identity = identityFn();
      if (!identity) throw refuse("no_identity", 409);
      const instanceId = instanceIdFn();
      const primaryUrl = await primaryUrlFn(db);
      if (typeof primaryUrl !== "string" || !/^https:\/\//.test(primaryUrl)) throw refuse("no_primary_url", 409);
      const existing = await getSatellite(db, p.satellite_id);
      if (existing && existing.status !== "revoked") throw refuse("already_paired", 409);
      const repair = !!existing; // a revoked row is replaced in place on success (spec §4.3)

      const key = freshMgmtKey(p.satellite_id);
      // The pin write is tracked so the catch below can put back exactly what was there before.
      let pinned = false;
      let previousPin = null;
      try {
        const t = now();
        const cert = issueCert({
          identity, instanceId, primaryUrl, satellite_id: p.satellite_id,
          satellite_pubkey: p.satellite_pubkey, mgmt_pubkey: key.ed25519_pub, now: t,
        });
        const certHash = certSha256(cert);
        const mac = pairMac(norm, { nonceC: p.nonce_c, nonceS: p.nonce_s, certSha256: certHash, satelliteId: p.satellite_id });
        let r;
        try {
          r = await postPair(p.host, "/satellite/v1/pair/complete", {
            cert, crow_id: cert.payload.crow_id, root_pubkey: cert.payload.root_pubkey,
            primary_instance_id: instanceId, primary_url: primaryUrl, target_sha: targetShaFn() || null,
            protocol: AGENT_PROTOCOL, nonce_s: p.nonce_s, mac,
          });
        } catch (err) {
          if (err instanceof PairingError) throw err;
          throw fail("unreachable", 502);
        }
        if (r.status !== 200) throw fail("pairing_refused", 400, ERR_CODE.test(r.json?.error) ? r.json.error : "refused");
        const doneSig = r.json?.sig;
        const doneStr = Buffer.from(doneSigningString({ nonceC: p.nonce_c, certSha256: certHash }), "utf8");
        if (typeof doneSig !== "string" || !verifyBytes(p.satellite_pubkey, doneStr, doneSig)) throw fail("bad_done_sig", 502);

        // PIN before the row exists: every send dials the host recorded OUTSIDE crow.db
        // (servers/shared/satellite-pins.js), so no row may come into being without one. The
        // owner just re-authenticated this host in the ceremony, so a re-pair overwrites it.
        previousPin = getSatellitePin(p.satellite_id, { env });
        if (!pinSatelliteHost(p.satellite_id, p.host, { env })) throw fail("pin_failed", 500);
        pinned = true;

        const at = new Date(t).toISOString();
        const row = {
          id: p.satellite_id, name: label, tailnet_host: p.host, satellite_pubkey: p.satellite_pubkey,
          mgmt_pubkey: key.ed25519_pub, cert_json: JSON.stringify(cert), cert_serial: cert.payload.serial,
          cert_expires_at: cert.payload.expires_at, primary_url: primaryUrl, agent_protocol: p.agent_protocol,
          last_seen_at: at,
        };
        if (repair) {
          if (!(await replaceRevokedSatellite(db, row))) throw fail("already_paired", 409);
        } else {
          await insertSatellite(db, { ...row, status: "active", created_at: at });
        }
        return { satellite_id: p.satellite_id, name: label, fingerprint: formatFingerprint(p.satellite_id), cert_expires_at: cert.payload.expires_at, repaired: repair };
      } catch (err) {
        // A row write that failed for ANY reason (a losing re-pair, a duplicate key, a DB error)
        // must not leave the satellite pointed at the fresh ceremony host: put the previous state
        // back, so a failed ceremony can never re-point an ACTIVE satellite. Ids only, never a host.
        if (pinned) {
          if (previousPin) pinSatelliteHost(p.satellite_id, previousPin, { env });
          else unpinSatellite(p.satellite_id, { env });
        }
        try { shredMgmtKey(p.satellite_id, { env }); } catch { /* best effort */ }
        if (err?.code === "not_migrated" && !(err instanceof PairingError)) throw fail("not_migrated", 503);
        throw err;
      }
    } finally {
      inflight.delete(p.satellite_id);
    }
  }

  function shredQuietly(id) {
    try { shredMgmtKey(id, { env }); } catch (err) { console.warn(`[satellites] shred ${id}: ${err.message}`); }
  }

  async function unpairSatellite({ db, id, reason } = {}) {
    if (!isSatelliteId(id)) throw fail("bad_id", 400);
    const why = typeof reason === "string" && reason.trim() ? reason.trim().slice(0, 200) : "owner";
    await assertMigrated(db);
    const row = await getSatellite(db, id);
    if (!row) throw fail("not_found", 404);
    if (row.status === "revoked") {
      shredQuietly(id); // a key an earlier, interrupted unpair left on disk
      throw fail("already_revoked", 409);
    }
    const identity = identityFn();
    if (!identity) throw fail("no_identity", 409);

    let reached = false;
    const t = now();
    const at = new Date(t).toISOString();
    try {
      try {
        const r = await satelliteFetch(row, { method: "POST", path: "/satellite/v1/unpair", body: { reason: why }, caller: "owner-local", fetchImpl, env, timeoutMs });
        reached = r.status === 200;
      } catch { reached = false; } // unreachable is fine: crow does its side alone (§3.3)
      await markRevoked(db, id, at);
      await recordRevocation(db, revokeSatelliteRecord({ identity, serial: row.cert_serial, satellite_id: id, reason: why, now: t }));
      // Only AFTER crow's side succeeded: if either write above threw, the row is not revoked and
      // the satellite keeps its address (so a retry can still reach it).
      // The ONLY caller of unpairSatellite is the owner-only route POST /api/satellites/:id/unpair
      // in servers/gateway/routes/satellites.js (session gate + local password session + CSRF; it
      // refuses peer and instance-authenticated requests). No MCP tool, bot door, tools-mount.js or
      // tool-entry.js calls it, and none may be added: dropping the pin is a step of the owner's
      // revocation, not something a contained bot can trigger.
      unpinSatellite(id, { env });
    } finally {
      // Whatever failed above, crow stops being able to manage this satellite.
      shredQuietly(id);
      try { await deleteToolPins(db, id); } catch (err) { console.warn(`[satellites] tool pins ${id}: ${err.message}`); }
    }
    return { satellite_id: id, reached, revoked_at: at };
  }

  return { startPairing, completePairing, unpairSatellite, pendingCount: () => { sweep(); return pending.size; } };
}
