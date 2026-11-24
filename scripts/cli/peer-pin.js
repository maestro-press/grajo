#!/usr/bin/env node
/**
 * `peer-pin` — show or re-pin the gateway ORIGIN this instance will send a
 * paired peer's credentials to.
 *
 * A peer bearer (and a signature made with the pair key) goes only to the
 * origin recorded in <CROW_HOME>/secrets/peer-tokens.json at pairing — that
 * store is hidden from bot sandboxes, while `crow_instances.gateway_url` is
 * bot-writable and therefore never authorizes a destination. When a peer
 * LEGITIMATELY moves (a new host, port or tailnet address), every sender will
 * refuse with "gateway origin is not the paired one (mismatch)" until the
 * operator re-pins it here.
 *
 * Usage (run in this instance's own environment: CROW_HOME, and
 * CROW_PEER_TOKENS_PATH when the store lives somewhere of its own):
 *   node scripts/cli/peer-pin.js --show
 *   node scripts/cli/peer-pin.js <instance-id> <gateway-url>
 *
 * --show prints `<instance-id> <pinned_origin|none>` per peer entry.
 * Re-pinning prints the normalized origin it stored (protocol//host:port,
 * default port explicit). The URL that also belongs in the peer's row
 * (Settings → Paired Instances) is the operator's to set: this CLI never writes
 * crow.db.
 *
 * It resolves this instance's Crow home through servers/shared/crow-home.js, so
 * under `node --test` with no CROW_HOME it refuses instead of touching a real
 * ~/.crow.
 */
import { pathToFileURL } from "node:url";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import {
  loadPeerCreds,
  normalizeGatewayOrigin,
  pinPeerOrigin,
} from "../../servers/shared/peer-credentials.js";
import { ENROLL_ID_RE } from "../../servers/shared/enroll-guard.js";

const USAGE = `Usage:
  node scripts/cli/peer-pin.js --show
  node scripts/cli/peer-pin.js <instance-id> <gateway-url>`;

/**
 * Run the CLI. Returns the exit code: 0 ok, 1 refused or bad input, 2 nothing
 * matched. Every dependency is a parameter so a test can run it in-process.
 */
export async function main({ argv = process.argv.slice(2), stdout = process.stdout, stderr = process.stderr } = {}) {
  const out = (s) => stdout.write(s);
  const fail = (s) => { stderr.write(`${s}\n`); return 1; };

  if (argv.includes("--help") || argv.includes("-h")) { out(`${USAGE}\n`); return 0; }

  // Fails with CROW_HOME_REQUIRED_IN_TESTS under `node --test` when this
  // instance's home would silently resolve to a real ~/.crow.
  resolveCrowHome();

  if (argv.length === 1 && argv[0] === "--show") {
    const all = loadPeerCreds();
    for (const id of Object.keys(all).sort()) {
      const pin = typeof all[id]?.pinned_origin === "string" && all[id].pinned_origin ? all[id].pinned_origin : "none";
      out(`${id} ${pin}\n`);
    }
    return 0;
  }

  const [instanceId, gatewayUrl, ...rest] = argv;
  if (rest.length || !instanceId || !gatewayUrl) return fail(`give --show, or <instance-id> <gateway-url>\n${USAGE}`);
  if (!ENROLL_ID_RE.test(instanceId)) return fail(`${JSON.stringify(String(instanceId).slice(0, 60))} is not a valid instance id`);
  const origin = normalizeGatewayOrigin(gatewayUrl);
  if (!origin) return fail("that is not a usable http(s) gateway URL (a scheme, a host, and no userinfo are required); nothing was written");

  const entry = loadPeerCreds()[instanceId];
  if (!entry || typeof entry !== "object") {
    return fail(`this instance holds no peer credentials for ${instanceId}; pair it first (nothing was written)`);
  }
  if (!pinPeerOrigin(instanceId, gatewayUrl)) return fail(`could not write the pin for ${instanceId} (nothing was written)`);
  out(`${instanceId} ${origin}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`FAIL: ${err?.message || err}`);
    process.exit(1);
  });
}