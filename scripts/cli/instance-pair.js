#!/usr/bin/env node
/**
 * `crow instance pair` — Pair this Crow instance with a peer.
 *
 * Modes:
 *   1. Network: POSTs /instance/enroll-request to the peer gateway, which
 *      accepts credentials and returns its symmetric pair.
 *   2. Manual: prints the credentials to paste on the peer side, and reads
 *      the peer's credentials from stdin.
 *
 * Both modes:
 *   - Register the peer in this node's crow_instances table (trusted=1).
 *   - Store { auth_token, signing_key } in <CROW_HOME>/secrets/peer-tokens.json.
 *
 * Usage:
 *   node scripts/cli/instance-pair.js --generate-otc            (on the PEER)
 *   node scripts/cli/instance-pair.js --peer-url https://peer.example.ts.net:8444 --otc <code>
 *   node scripts/cli/instance-pair.js --allow-re-pair <source-id>   (on the PEER, re-pair only)
 *   node scripts/cli/instance-pair.js --manual-paste
 *
 * With --peer-url, the peer's gateway must expose the /instance/enroll
 * endpoints (Phase 5-MVP wires these into routes/bundles.js sibling route
 * file servers/gateway/routes/instance-enroll.js).
 *
 * BOTH modes check the local keyed-verifier key FIRST (`ensurePeerKey`), before
 * the peer is contacted (or our half is printed): the verifier stored for the
 * peer's bearer is minted from that key, and finding it missing afterwards
 * would leave a half pairing — the peer already committed (its code is spent
 * and it holds our bearer) while this side cannot verify anything it says.
 */

import { createDbClient, resolveDataDir } from "../../servers/db.js";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { resolve as resolvePath } from "path";
import {
  registerInstance,
  getInstance,
  updateInstance,
  reactivateOnRepair,
  getOrCreateLocalInstanceId,
  selfPairingAddress,
} from "../../servers/gateway/instance-registry.js";
import {
  pickPeerGatewayUrl, isTailnetAddress, rememberPeerSyncPort, forgetPeerHandshakeState,
  isDialableGatewayUrl, gatewayUrlHost, ownTailnetSuffix,
} from "../../servers/shared/self-dial-address.js";
import { ensurePeerKey, legacyStoredHash, mintPeerInbound } from "../../servers/gateway/peer-inbound-token.js";
import {
  setPeerCreds,
  pinPeerOrigin,
  normalizeGatewayOrigin,
  generateSecret,
  peerTokensPath,
} from "../../servers/shared/peer-credentials.js";
import {
  generateEnrollOtc, ENROLL_OTC_MIN_LENGTH, repairProof, repairProofKey, sha256Hex as guardSha256, writeRepairAllowance, REPAIR_ALLOW_DEFAULT_MINUTES, REPAIR_ALLOW_MAX_MINUTES,
  ENROLL_ID_RE, acceptableAdvertisedUrl, tailnetSuffix,
} from "../../servers/shared/enroll-guard.js";
import { loadPeerCreds } from "../../servers/shared/peer-credentials.js";
import { createInterface } from "readline";
import { hostname as osHostname } from "os";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--peer-url") out.peerUrl = argv[++i];
    else if (a === "--peer-id") out.peerId = argv[++i];
    else if (a === "--peer-name") out.peerName = argv[++i];
    else if (a === "--manual-paste") out.manual = true;
    else if (a === "--otc") out.otc = argv[++i];
    else if (a === "--generate-otc") out.generateOtc = true;
    else if (a === "--allow-re-pair") out.allowRePair = argv[++i];
    else if (a === "--minutes") out.minutes = argv[++i];
    else if (a === "--help" || a === "-h") out.help = true;
  }
  return out;
}

function printHelp() {
  console.log(`Crow instance pair — provision cross-host RPC credentials.

Usage:
  node scripts/cli/instance-pair.js --generate-otc
  node scripts/cli/instance-pair.js --peer-url <url> --otc <code> [--peer-name <name>] [--peer-id <id>]
  node scripts/cli/instance-pair.js --allow-re-pair <instance-id> [--minutes <n>]
  node scripts/cli/instance-pair.js --manual-paste --peer-id <id> --peer-name <name> --peer-url <url>

Pairing ceremony (network mode):
  1. On the PEER: run --generate-otc, then set CROW_ENROLL_ENABLED=1 and
     CROW_ENROLL_OTC=<code> in the peer gateway's environment and restart it.
  2. On THIS instance: --peer-url <peer tailnet URL> --otc <code>
     (or export CROW_ENROLL_OTC=<code>). The code is single-use and expires
     CROW_ENROLL_WINDOW_MINUTES (default 30) after the peer gateway first saw it.
  3. On the PEER: remove CROW_ENROLL_ENABLED and CROW_ENROLL_OTC, restart.

  The peer refuses enrollment without a code of >= ${ENROLL_OTC_MIN_LENGTH} characters, locks a
  source after 5 wrong codes, and never accepts it over Tailscale Funnel.

Re-pairing an instance the peer already knows:
  A current CLI proves it still holds its credentials for the peer (without
  sending them), so re-pairing just works. If those credentials are lost, or
  the peer revoked this instance, the PEER's operator must first run
  --allow-re-pair <this instance's id> on the peer (single-use, default
  ${REPAIR_ALLOW_DEFAULT_MINUTES} min, max ${REPAIR_ALLOW_MAX_MINUTES}); otherwise the peer answers 409 already_paired.
  The proof is sent only for the peer whose stored address matches --peer-url
  (or the one named by --peer-id), is bound to that peer's id and this code,
  and never reveals the credentials.

Refusals (checked on the peer's answer BEFORE anything is written here):
  - the peer answers with an id other than --peer-id, or with this instance's
    own id;
  - the peer answers with the id of a peer this instance already has a row
    or credentials for (trusted, credentialed, revoked, or an uncredentialed
    row with a stored address) while that stored address does not match
    --peer-url — re-run with --peer-id <id> if it really is that instance; a
    revoked peer is only re-paired with --peer-id; an uncredentialed row with
    no stored address is simply filled in.
  In each case the PEER has already spent its code and holds new credentials
  for this instance, so re-pairing with it later needs --allow-re-pair on it.
  The peer's advertised gateway_url is kept only if it is a tailnet IP, a
  MagicDNS name in this tailnet, or a 10/8 / 192.168/16 address; otherwise the
  existing dialable address, else the --peer-url origin, is stored.

Manual mode (--manual-paste):
  Prints credentials to paste on the peer side, and reads peer's credentials
  from stdin. Useful for first-time setup before gateways can talk.

Credentials stored at: ${peerTokensPath()}`);
}

async function readJsonFromStdin() {
  const rl = createInterface({ input: process.stdin });
  let buf = "";
  for await (const line of rl) {
    buf += line + "\n";
    try {
      return JSON.parse(buf);
    } catch {
      // keep reading
    }
  }
  throw new Error("stdin closed before valid JSON was received");
}

function generateOtcCommand() {
  const code = generateEnrollOtc();
  console.log(`One-time pairing code (single-use):

  ${code}

On THIS host (the peer being paired with), add to the gateway's environment
(the repo .env, or a systemd drop-in) and restart the gateway:

  CROW_ENROLL_ENABLED=1
  CROW_ENROLL_OTC=${code}

On the OTHER instance, run:

  node scripts/cli/instance-pair.js --peer-url <this host's tailnet URL> --otc ${code}

The code expires CROW_ENROLL_WINDOW_MINUTES (default 30) after this gateway
first sees it. Remove both variables and restart once pairing completes.`);
}

async function allowRePairCommand(db, { allowRePair, minutes }) {
  const peerId = String(allowRePair || "").trim();
  if (!peerId) throw new Error("--allow-re-pair needs the instance id of the peer that will re-pair");
  const localId = getOrCreateLocalInstanceId();
  if (peerId === localId) throw new Error("that is this instance's own id");
  const row = await getInstance(db, peerId);
  const hasCreds = Boolean(loadPeerCreds()[peerId]);
  const dbPath = process.env.CROW_DB_PATH || resolvePath(resolveDataDir(), "crow.db");
  console.log(`  this instance: ${localId}  (DB ${dbPath})`);
  if (!row && !hasCreds) {
    throw new Error(`${peerId} is not known on this instance (${localId}) — a first pairing needs no allowance. If you meant another co-hosted instance, run with its CROW_HOME / CROW_DATA_DIR.`);
  }
  const { expiresAt, minutes: m } = await writeRepairAllowance(db, localId, peerId, { minutes });
  console.log(`✓ ${peerId}${row ? ` (${row.name}, status ${row.status})` : " (not known here yet)"} may re-pair with this gateway once,`);
  console.log(`  replacing its credentials and dial address, until ${new Date(expiresAt).toISOString()} (${m} min).`);
  console.log("  Enrollment must also be enabled with a one-time code (see --generate-otc).");
}

function urlHost(raw) {
  try { return new URL(String(raw)).hostname.toLowerCase().replace(/^\[|\]$/g, ""); } catch { return null; }
}

/** True when this instance already has trust state for `id`: a trusted or
 * credentialed row, a revoked row, or peer-tokens.json creds. */
function isKnownPeer(row, creds) {
  if (creds) return true;
  if (!row) return false;
  return Number(row.trusted) === 1 || Boolean(row.auth_token_hash) || row.status === "revoked";
}

/**
 * THE rule for "which already-known peer is --peer-url": the single known
 * peer whose stored gateway_url host or tailscale_ip equals the URL's host,
 * or null (none, or ambiguous). Used to pick the re-pair proof to send, and —
 * with includeBare (every row, also uncredentialed ones registered by the
 * operator or learned by sync) — to decide whether the peer's answer may
 * update an existing row.
 */
async function knownPeerForUrl(db, peerUrl, { includeBare = false } = {}) {
  const host = urlHost(peerUrl);
  if (!host) return null;
  const creds = loadPeerCreds();
  const ids = new Set(Object.keys(creds));
  try {
    const { rows } = await db.execute("SELECT id FROM crow_instances");
    for (const r of rows) ids.add(r.id);
  } catch { /* table missing */ }
  const localId = getOrCreateLocalInstanceId();
  const hits = [];
  for (const id of ids) {
    if (id === localId) continue;
    const row = await getInstance(db, id).catch(() => null);
    if (!row || (!includeBare && !isKnownPeer(row, creds[id]))) continue;
    if (urlHost(row.gateway_url) === host || String(row.tailscale_ip || "").toLowerCase() === host) hits.push(id);
  }
  return hits.length === 1 ? hits[0] : null;
}

/**
 * Re-pair proof for the ONE peer this request is meant for: the peer named by
 * --peer-id, else knownPeerForUrl. Never a proof for any other peer. The
 * proof (servers/shared/enroll-guard.js) is bound to that peer's id and to
 * this code's digest, and keyed by hash(our current bearer) + our current
 * signing key, so it reveals neither and is useless anywhere else.
 */
async function buildRepairProofs(db, reqBody, { peerUrl, peerId, otc }) {
  const creds = loadPeerCreds();
  const target = peerId || await knownPeerForUrl(db, peerUrl);
  const c = target ? creds[target] : null;
  if (!c || typeof c.auth_token !== "string" || !c.auth_token || typeof c.signing_key !== "string") return [];
  const key = repairProofKey(guardSha256(c.auth_token), c.signing_key);
  return [repairProof(key, reqBody, { targetId: target, otcDigest: guardSha256(otc) })];
}

/**
 * Decide, BEFORE anything is written locally, whether the peer's answer may
 * be stored. The answering peer must not choose which local peer gets
 * re-keyed: a peer (or a mistyped URL) answering with the id of a DIFFERENT,
 * already-known peer would otherwise take over that identity here. Throws
 * with an operator-facing message; returns the validated peer id.
 */
async function vetPeerAnswer(db, peerPayload, { peerUrl, expectPeerId, localId }) {
  const peerId = peerPayload?.peer_instance_id;
  const spent = `The peer has already recorded this pairing attempt: its one-time code is spent and it now holds new credentials for this instance (${localId}), so re-pairing with it later needs \`node scripts/cli/instance-pair.js --allow-re-pair ${localId}\` on the peer. Nothing was written here.`;
  if (typeof peerId !== "string" || !ENROLL_ID_RE.test(peerId)) {
    throw new Error(`peer answered with an invalid instance id. ${spent}`);
  }
  const bearer = peerPayload.peer_outbound_bearer;
  if (typeof bearer !== "string" || bearer.length < 32) {
    throw new Error(`peer answered without a usable peer_outbound_bearer (>= 32 chars). ${spent}`);
  }
  if (expectPeerId && peerId !== expectPeerId) {
    throw new Error(`peer answered as ${peerId}, not the --peer-id ${expectPeerId} you named. ${spent}`);
  }
  if (peerId === localId) {
    throw new Error(`peer answered with THIS instance's own id (${localId}) — the URL points back at this instance. ${spent}`);
  }
  const row = await getInstance(db, peerId);
  const creds = loadPeerCreds()[peerId];
  if (row || creds) {
    const named = expectPeerId === peerId;
    if (row?.status === "revoked" && !named) {
      throw new Error(`peer answered as ${peerId}, which is REVOKED here; a revoked peer is only re-paired with --peer-id ${peerId}. ${spent}`);
    }
    // Any existing row (even an uncredentialed one the operator registered or
    // sync learned) or creds: the answer may claim it only if --peer-id names
    // it or its stored address is the one dialed. A bare row with NO stored
    // address has nothing to contradict and may be filled in.
    const hasAddress = Boolean(row && (urlHost(row.gateway_url) || row.tailscale_ip));
    const mustMatch = isKnownPeer(row, creds) || hasAddress;
    if (!named && mustMatch && (await knownPeerForUrl(db, peerUrl, { includeBare: true })) !== peerId) {
      const label = row?.name ? `${peerId} (${row.name})` : peerId;
      throw new Error(`peer answered as ${label}, a peer this instance already knows at a different address than ${peerUrl}. If it really is that instance, re-run with --peer-id ${peerId}. ${spent}`);
    }
  }
  return { peerId, row };
}

/** The gateway_url to store for the peer: its answer only when it passes the
 * route's acceptance rule (and does not downgrade a dialable row), else the
 * existing dialable address, else the origin the operator typed. Never a URL
 * with userinfo. This is the ROW only — crow_instances.gateway_url is
 * bot-writable, so it never decides the pin (see peerPinCandidateForCeremony). */
function vetPeerGatewayUrl(answerUrl, { row, peerUrl, ownTailnet }) {
  const ok = acceptableAdvertisedUrl(answerUrl, { ownTailnet });
  const existing = row?.gateway_url && isDialableGatewayUrl(row.gateway_url) ? row.gateway_url : null;
  if (ok && (isDialableGatewayUrl(ok) || !existing)) return ok;
  if (existing) return existing;
  try { return new URL(String(peerUrl)).origin; } catch { return null; }
}

/**
 * The gateway ORIGIN this pairing may pin, or null (store the credentials
 * unpinned). ONLY a URL that came from the authenticated ceremony itself:
 *   - the peer's ADVERTISED gateway_url, when this host accepts it; else
 *   - the origin the operator typed as --peer-url (the address this ceremony
 *     actually reached the peer on).
 * NEVER a value read from crow_instances: that row is bot-writable, so a
 * pre-poisoned row would otherwise become the pin the bot needs.
 */
function peerPinCandidateForCeremony(answerUrl, { peerUrl, ownTailnet }) {
  return acceptableAdvertisedUrl(answerUrl, { ownTailnet }) || operatorOrigin(peerUrl);
}

/** The http(s) ORIGIN of the URL the operator typed, or null. */
function operatorOrigin(peerUrl) {
  try {
    const u = new URL(String(peerUrl));
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (u.username || u.password) return null;
    return u.origin;
  } catch { return null; }
}

async function networkPair(db, { peerUrl, peerName, peerId: expectPeerId, otc: otcArg }) {
  const otc = otcArg || process.env.CROW_ENROLL_OTC || "";
  if (otc.length < ENROLL_OTC_MIN_LENGTH) {
    throw new Error(`a one-time code is required (>= ${ENROLL_OTC_MIN_LENGTH} chars): on the PEER run \`node scripts/cli/instance-pair.js --generate-otc\`, follow its instructions, then pass --otc <code> here`);
  }
  // THE KEY IS CHECKED BEFORE THE PEER IS CONTACTED, exactly as the enroll route mints before it
  // commits. The verifier this side STORES for the peer's bearer is an `h1.` MAC, minted after the
  // answer arrives — but the PEER has already committed by then (its one-time code is spent and it
  // holds our bearer), so a key that turns out to be missing/unusable would leave a HALF pairing:
  // the peer trusts us and we cannot verify it. Here the failure costs nothing and nothing is
  // written on either side.
  await ensurePeerKey(db);
  const localId = getOrCreateLocalInstanceId();
  // Our outbound bearer (what we send to peer in Authorization: Bearer).
  // Peer stores its hash in crow_instances.auth_token_hash.
  const sourceOutboundBearer = generateSecret();
  // Shared symmetric HMAC key (same both directions for MVP).
  const sharedSigningKey = generateSecret();
  // Our TAILNET dial address (never CROW_GATEWAY_URL — the public :443 door).
  const self = await selfPairingAddress(db);

  const reqBody = {
    source_instance_id: localId,
    // HOSTNAME is a bash variable, not exported to node — the old
    // `process.env.HOSTNAME || "unknown"` named every pair "unknown" (raven, 2026-09-24).
    source_name: process.env.HOSTNAME || osHostname() || "unknown",
    source_gateway_url: self.gateway_url,
    source_tailscale_ip: self.tailscale_ip,
    source_sync_port: self.sync_port,
    source_outbound_bearer: sourceOutboundBearer,
    shared_signing_key: sharedSigningKey,
    otc,
  };
  const proofs = await buildRepairProofs(db, reqBody, { peerUrl, peerId: expectPeerId, otc });
  if (proofs.length) reqBody.repair_proofs = proofs;
  const url = String(peerUrl).replace(/\/+$/, "") + "/instance/enroll-request";
  console.log(`→ POST ${url}`);
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(reqBody),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    const err = await res.text().catch(() => "");
    throw new Error(`enroll-request failed: HTTP ${res.status} — ${err}`);
  }
  const peerPayload = await res.json();
  if (!peerPayload?.peer_instance_id || !peerPayload?.peer_outbound_bearer) {
    throw new Error("peer response missing peer_instance_id or peer_outbound_bearer");
  }

  const { peerId, row: knownRow } = await vetPeerAnswer(db, peerPayload, { peerUrl, expectPeerId, localId });
  const ownTailnet = tailnetSuffix(gatewayUrlHost(self.gateway_url)) || ownTailnetSuffix();
  const answerName = typeof peerPayload.peer_name === "string" ? peerPayload.peer_name.slice(0, 128) : null;
  await storePeerCredsLocally(db, {
    // vetPeerAnswer already refused a revoked id the operator did not name.
    allowReactivate: expectPeerId === peerId,
    peerId,
    peerName: peerName || answerName || knownRow?.name || peerId,
    peerGatewayUrl: vetPeerGatewayUrl(peerPayload.peer_gateway_url, { row: knownRow, peerUrl, ownTailnet }),
    // The pin comes ONLY from this ceremony: the peer's advertised address when
    // acceptable, else the --peer-url origin the operator typed. Never the row.
    pinOrigin: peerPinCandidateForCeremony(peerPayload.peer_gateway_url, { peerUrl, ownTailnet }),
    peerTailscaleIp: peerPayload.peer_tailscale_ip,
    peerSyncPort: peerPayload.peer_sync_port,
    peerCrowId: peerId,
    // Creds for OUTBOUND calls us → peer:
    auth_token: sourceOutboundBearer,   // we generated; peer stored its hash
    signing_key: sharedSigningKey,      // both sides share
    // The verifier we store for the peer's bearer is the KEYED MAC (family `peer:inbound`); the
    // legacy sha256 of the same bearer is kept for the re-pair proof (design D4) — the peer's own
    // install computes that value, and `repairProofKey` has always been keyed by it.
    peerOutboundBearerHash: await mintPeerInbound(db, peerPayload.peer_outbound_bearer),
    inboundBearerSha256: legacyStoredHash(peerPayload.peer_outbound_bearer),
  });

  console.log(`✓ Paired with peer ${peerId} (${peerName || peerPayload.peer_name || "unnamed"})`);
  console.log(`  Credentials stored: ${peerTokensPath()}`);
}

async function manualPair(db, { peerId, peerName, peerUrl }) {
  if (!peerId || !peerName || !peerUrl) {
    throw new Error("--manual-paste requires --peer-id, --peer-name, --peer-url");
  }
  // Same rule as `networkPair`, before anything is printed or read: the peer operator pastes its
  // half out of band, so a key problem found AFTER our credentials are printed leaves the same
  // half pairing (the peer holds a bearer we cannot verify). Fail before the ceremony starts.
  await ensurePeerKey(db);
  const localId = getOrCreateLocalInstanceId();
  const sourceOutboundBearer = generateSecret();
  const sharedSigningKey = generateSecret();
  const self = await selfPairingAddress(db);

  console.log("=== Give these to the peer operator ===");
  console.log(JSON.stringify({
    source_instance_id: localId,
    // HOSTNAME is a bash variable, not exported to node — the old
    // `process.env.HOSTNAME || "unknown"` named every pair "unknown" (raven, 2026-09-24).
    source_name: process.env.HOSTNAME || osHostname() || "unknown",
    source_gateway_url: self.gateway_url,
    source_tailscale_ip: self.tailscale_ip,
    source_sync_port: self.sync_port,
    source_outbound_bearer: sourceOutboundBearer,
    shared_signing_key: sharedSigningKey,
  }, null, 2));
  console.log("=========================================\n");

  console.log("Paste the peer's JSON block here (must include peer_instance_id, peer_outbound_bearer) then ^D:");
  const peerPayload = await readJsonFromStdin();
  if (!peerPayload?.peer_outbound_bearer) {
    throw new Error("peer JSON missing peer_outbound_bearer");
  }
  // The pasted answer must be the peer the operator named (the manual
  // counterpart of vetPeerAnswer): an answer for another id would otherwise
  // re-key, and reactivate, whichever row it names.
  const answeredId = peerPayload.peer_instance_id;
  if (typeof answeredId !== "string" || !ENROLL_ID_RE.test(answeredId)) {
    throw new Error("peer JSON has no valid peer_instance_id; nothing was written");
  }
  if (answeredId !== peerId) {
    throw new Error(`peer JSON is for ${answeredId}, not the --peer-id ${peerId} you named; nothing was written`);
  }
  if (answeredId === localId) {
    throw new Error(`peer JSON names THIS instance's own id (${localId}); nothing was written`);
  }

  await storePeerCredsLocally(db, {
    allowReactivate: true, // --peer-id named this id, and the answer matched it
    peerId: answeredId,
    peerName,
    peerGatewayUrl: pickPeerGatewayUrl(peerPayload.peer_gateway_url, peerUrl),
    // Same rule as the network ceremony: the advertised address if acceptable,
    // else the --peer-url origin the operator typed — never a stored row.
    pinOrigin: peerPinCandidateForCeremony(peerPayload.peer_gateway_url, {
      peerUrl,
      ownTailnet: tailnetSuffix(gatewayUrlHost(self.gateway_url)) || ownTailnetSuffix(),
    }),
    peerTailscaleIp: peerPayload.peer_tailscale_ip,
    peerSyncPort: peerPayload.peer_sync_port,
    peerCrowId: peerPayload.peer_crow_id || peerId,
    auth_token: sourceOutboundBearer,
    signing_key: sharedSigningKey,
    peerOutboundBearerHash: await mintPeerInbound(db, peerPayload.peer_outbound_bearer),
    inboundBearerSha256: legacyStoredHash(peerPayload.peer_outbound_bearer),
  });

  console.log(`✓ Paired with peer ${peerId} (${peerName})`);
  console.log(`  Credentials stored: ${peerTokensPath()}`);
}

/**
 * The write half of a pairing: the row, the credentials, and the pin. Exported
 * for the tests that must prove what it does (and what it logs) when a ceremony
 * supplies no pin of its own.
 */
export async function storePeerCredsLocally(db, {
  allowReactivate = false,
  peerId,
  peerName,
  peerGatewayUrl,
  pinOrigin,
  peerTailscaleIp,
  peerSyncPort,
  peerCrowId,
  auth_token,
  signing_key,
  peerOutboundBearerHash,
  inboundBearerSha256 = null,
}) {
  const tailscaleIp = typeof peerTailscaleIp === "string" && isTailnetAddress(peerTailscaleIp.trim()) ? peerTailscaleIp.trim() : null;
  const existing = await getInstance(db, peerId);
  if (existing?.status === "revoked" && !allowReactivate) {
    throw new Error(`${peerId} is REVOKED here; a revoked peer is only re-paired when --peer-id names it. Nothing was written.`);
  }
  if (existing) {
    // PT-1: the CLI side of a re-pair. Unlike updateInstance (which refuses
    // any edit to a revoked row) this flips a revoked row back to active and
    // writes the re-pair fence in the same transaction.
    await reactivateOnRepair(db, peerId, {
      name: peerName,
      gatewayUrl: peerGatewayUrl,
      tailscaleIp,
      authTokenHash: peerOutboundBearerHash,
      localInstanceId: getOrCreateLocalInstanceId(),
    });
  } else {
    await registerInstance(db, {
      id: peerId,
      name: peerName,
      crowId: peerCrowId,
      gatewayUrl: peerGatewayUrl,
      tailscaleIp,
      authTokenHash: peerOutboundBearerHash,
    });
    await updateInstance(db, peerId, { trusted: 1 });
  }
  await rememberPeerSyncPort(db, getOrCreateLocalInstanceId(), peerId, peerSyncPort);
  await forgetPeerHandshakeState(db, getOrCreateLocalInstanceId(), peerId);

  setPeerCreds(peerId, {
    auth_token,
    signing_key,
    // Design D4: the legacy `sha256(bearer)` of the bearer the peer presents TO us, which is what
    // the peer's own install still computes for the re-pair proof. `setPeerCreds` MERGES, so an
    // entry that already carries one keeps it when a caller passes nothing.
    ...(inboundBearerSha256 ? { inbound_bearer_sha256: inboundBearerSha256 } : {}),
  });
  // Pin only an ORIGIN this ceremony itself supplied (the peer's accepted
  // advertised address, else the --peer-url the operator typed). The row above
  // is bot-writable, so an address read from it (or kept from an older row) is
  // never pinned: such a pair is stored UNPINNED and every sender refuses with
  // `no-pin` until the operator re-pins (scripts/cli/peer-pin.js), rather than
  // pinning whatever a bot wrote into crow_instances.gateway_url.
  //
  // A pin and the row it authorizes must be the SAME origin, because every
  // sender compares its target against the pin. A pin taken from the peer's
  // accepted advertised address while the row keeps a different dial address is
  // a pair nothing can reach; neither value is changed here (the row follows the
  // stored pairing, the pin follows the ceremony), so say so plainly.
  //
  // The stored row origin is NOT printed: crow_instances is bot-writable, so
  // echoing it back — and worse, printing a ready-to-run `peer-pin.js <id>
  // <row origin>` — would turn operator guidance into a pin-poisoning rail. The
  // operator is told to confirm the peer's real address themselves and paste
  // THAT, never a value this CLI read out of the row.
  const pinOriginNorm = normalizeGatewayOrigin(pinOrigin);
  const rowOriginNorm = normalizeGatewayOrigin(peerGatewayUrl);
  if (pinOriginNorm && rowOriginNorm && pinOriginNorm !== rowOriginNorm) {
    console.warn(`WARNING: [peer-pin] ${peerId} is pinned to ${pinOriginNorm} (from this pairing) but its stored gateway_url points elsewhere; senders will refuse this peer until they agree. The stored address may have been written by a bot: confirm the peer's real gateway address yourself, then run: node scripts/cli/peer-pin.js ${peerId} <the address you confirmed>`);
  }
  if (!pinOrigin || !pinPeerOrigin(peerId, pinOrigin)) {
    // No ceremony address to take a pin from. setPeerCreds() merges, so a pin
    // recorded at an earlier pairing is still in place — it stays, and saying
    // "left unpinned" would be wrong (and would send the operator to re-pin a
    // peer that is already pinned).
    const keptPin = loadPeerCreds()[peerId]?.pinned_origin;
    if (typeof keptPin === "string" && keptPin) {
      console.warn(`[peer-pin] ${peerId} kept its previous pin (${keptPin}): this pairing had no ceremony address to take a new one from`);
    } else {
      console.warn(`[peer-pin] ${peerId} left unpinned: run node scripts/cli/peer-pin.js ${peerId} <url>`);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) return printHelp();
  if (args.generateOtc) return generateOtcCommand();

  const db = await createDbClient();
  try {
    if (args.allowRePair !== undefined) {
      await allowRePairCommand(db, args);
    } else if (args.manual) {
      await manualPair(db, args);
    } else if (args.peerUrl) {
      await networkPair(db, args);
    } else {
      printHelp();
      process.exit(1);
    }
  } finally {
    try { db.close?.(); } catch {}
  }
}

/**
 * Is this file the process's entry point? Compared on the RESOLVED paths, so a
 * relative invocation (`node scripts/cli/instance-pair.js`, how the installer
 * and the tests run it) and a symlinked checkout both still count. The tests
 * import storePeerCredsLocally() from here, and importing must never pair.
 */
function isEntryPoint() {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return realpathSync(arg) === realpathSync(fileURLToPath(import.meta.url));
  } catch { return false; }
}

if (isEntryPoint()) {
  main().catch((err) => {
    console.error(`FAIL: ${err.message}`);
    process.exit(1);
  });
}