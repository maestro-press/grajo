/**
 * Static inventory: every sender of a PEER CREDENTIAL consults the paired
 * gateway-origin gate.
 *
 * `crow_instances.gateway_url` is bot-writable, so a destination taken from it
 * is not authorization to carry a peer bearer or a pair-key signature. The
 * origin pinned host-side at pairing is
 * servers/shared/peer-credentials.js: peerUrlAllowed(), and every sender must
 * call it before it attaches anything. A new sender that forgets the gate is
 * exactly the bug this file refuses to let back in, so it is checked in the
 * source rather than only per-sender (tests/peer-pinned-origin.test.js proves
 * the runtime behaviour of each one).
 *
 * The SENDER set is DISCOVERED, not listed from memory: every source file under
 * servers/, scripts/ and bundles/<id>/{panel,server}/ that both handles a peer
 * credential (getPeerCreds / signRequest / signTicket / signRemoteActor /
 * signingFetch / an `auth_token`) and can issue an outbound request (fetch /
 * fetchImpl / requestInit / the SDK's StreamableHTTPClientTransport) must be
 * reviewed here. A reviewed sender must call peerUrlAllowed(); anything else
 * needs a NON_SENDERS entry with the reason it cannot carry a peer credential
 * anywhere. A file that starts doing both without being reviewed fails, and so
 * does a reviewed file that quietly stopped calling the gate.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { tmpdir } from "node:os";

const REPO = new URL("../", import.meta.url).pathname;
const read = (p) => readFileSync(join(REPO, p), "utf8");

/**
 * Reviewed SENDERS: [file, what it sends]. Each MUST call peerUrlAllowed()
 * before it attaches a credential — including against the FINAL URL it dials.
 */
const SENDERS = [
  ["servers/gateway/routes/peer-relay.js", "the loopback relay's peer bearer + remote-actor signature"],
  ["servers/gateway/proxy.js", "the federation MCP client's peer bearer"],
  ["servers/gateway/ai/remote-voice-tools.js", "the voice path's peer bearer + remote-actor signature"],
  ["servers/shared/peer-forward.js", "the signed cross-host forwarder (bearer + HMAC)"],
  ["servers/gateway/dashboard/index.js", "the SSO launch ticket (pair-key signature) handed to the browser"],
  ["bundles/meta-glasses/panel/routes.js", "the glasses stream proxy's peer bearer"],
];

/**
 * Reviewed NON_SENDERS: discovered files that must NOT be forced through
 * peerUrlAllowed(), with the reason each one cannot send a peer credential to a
 * destination of its own choosing.
 */
const NON_SENDERS = {
  "servers/shared/remote-actor.js":
    "the actor-signing fetch WRAPPER: it signs an init it is handed and never chooses a host (and forces redirect: manual); the modules that install it are the reviewed senders",
  "servers/shared/peer-credentials.js":
    "the credential store and the gate ITSELF: it defines peerUrlAllowed() and noRedirectFetch(); it never picks a destination",
  "servers/gateway/satellites/backup-pull.js":
    "a SATELLITE call signed with a satellite ed25519 MANAGEMENT key (never a paired peer credential); its destination is NOT a peer origin: it is the host pinned by servers/shared/satellite-pins.js (satelliteBaseUrlFor) from the pairing ceremony, not the bot-writable satellites.tailnet_host — this file is in NON_SENDERS only because this test's discovery sees a signature and a fetch, not because it carries a peer credential; satelliteFetch already refuses redirects",
  "servers/gateway/satellites/offsite.js":
    "SATELLITE offsite vault calls signed with a satellite ed25519 management key, never a paired peer credential; the same address pin as backup-pull.js (servers/shared/satellite-pins.js satelliteBaseUrlFor, checked before any key read), and every call goes through sendOnce (redirect: manual)",
  "servers/gateway/satellites/client.js":
    "the SATELLITE transport: satellite ed25519 management-key signing, redirect: manual, never a peer bearer; its destination is the host pinned by servers/shared/satellite-pins.js (satelliteBaseUrlFor), not a bot-writable row — reviewed as a peer NON_SENDER only because this test discovers a signature plus a fetch",
  "scripts/cli/instance-pair.js":
    "the pairing CLI: its destination is the URL the OPERATOR typed (--peer-url) or pasted, never a stored row; it only PINS what it stores (pinPeerOrigin)",
  "bundles/media/panel/media.js":
    "an add-on's own service credential field (an input the operator fills in for its library), not a paired peer credential",
};

// A file that handles a peer credential in ANY of its forms: the bearer, the
// pair's signing key (the pair-key signatures and subkeys are derived from it),
// or a lookup that hands either one out (defaultPairKey / pairSubkeyVia /
// keyLookup). Discovered from the source, so a new sender cannot slip in.
const CREDENTIAL_RE = /\bgetPeerCreds\s*\(|\bsignRequest\s*\(|\bsignTicket\s*\(|\bsignRemoteActor\s*\(|\bsigningFetch\b|(?<![A-Za-z0-9_])auth_token(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])signing_key(?![A-Za-z0-9_])|\bdefaultPairKey\b|\bpairSubkeyVia\b|(?<![A-Za-z0-9_])keyLookup(?![A-Za-z0-9_])/;
const OUTBOUND_RE = /\bfetch\s*\(|\bfetchImpl\b|\brequestInit\b|StreamableHTTPClientTransport|\bhttps?\.request\s*\(/;

const SKIP_DIRS = new Set(["node_modules", ".git", "vendor", "public", "fixtures", "tests", "test"]);

/** Every .js/.mjs file under `root` (absolute), minus tests/vendor/client trees. */
function listSourceFiles(root) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const abs = join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith(".")) continue;
        walk(abs);
      } else if (e.isFile() && /\.c?m?js$/.test(e.name) && !e.name.endsWith(".min.js")) {
        out.push(abs);
      }
    }
  };
  walk(root);
  return out;
}

/** The scan roots: servers/, scripts/, and each bundle's own server + panel trees. */
function scanRoots() {
  const roots = [join(REPO, "servers"), join(REPO, "scripts")];
  let bundles = [];
  try { bundles = readdirSync(join(REPO, "bundles"), { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name); } catch { /* none */ }
  for (const id of bundles) {
    for (const sub of ["panel", "server"]) {
      const dir = join(REPO, "bundles", id, sub);
      try { if (statSync(dir).isDirectory()) roots.push(dir); } catch { /* the bundle has no such tree */ }
    }
  }
  return roots;
}

const rel = (abs) => relative(REPO, abs).split(sep).join("/");

/**
 * The discovery rule: a file that handles a peer credential AND can issue an
 * outbound request. `files` is [{path, src}] so a fixture can be scanned too.
 */
export function discoverSenders(files) {
  return files
    .filter((f) => CREDENTIAL_RE.test(f.src) && OUTBOUND_RE.test(f.src))
    .map((f) => f.path)
    .sort();
}

function scanRepo() {
  const files = [];
  for (const root of scanRoots()) {
    for (const abs of listSourceFiles(root)) files.push({ path: rel(abs), src: readFileSync(abs, "utf8") });
  }
  return files;
}

test("every discovered peer-credential sender asks peerUrlAllowed() before attaching a credential", () => {
  const discovered = discoverSenders(scanRepo());
  const reviewedSenders = new Set(SENDERS.map(([f]) => f));
  const reviewedNonSenders = new Set(Object.keys(NON_SENDERS));

  const unreviewed = discovered.filter((f) => !reviewedSenders.has(f) && !reviewedNonSenders.has(f));
  assert.deepEqual(unreviewed, [],
    "a file that handles a peer credential and can issue a request must be reviewed: add it to SENDERS (and call peerUrlAllowed) or to NON_SENDERS with the reason it cannot carry one");

  const stale = [...reviewedSenders, ...reviewedNonSenders].filter((f) => !discovered.includes(f));
  assert.deepEqual(stale, [], "every reviewed entry must still be a discovered sender (update the list when the code moves)");

  const offenders = [];
  for (const [file, what] of SENDERS) {
    if (!/\bpeerUrlAllowed\s*\(/.test(read(file))) offenders.push(`${file}: ${what}`);
  }
  assert.deepEqual(offenders, [], `a peer credential may only go to the PAIRED gateway origin (peerUrlAllowed):\n${offenders.join("\n")}`);
});

test("the discovery catches a NEW sender (fixture)", () => {
  const dir = mkdtempSync(join(tmpdir(), "pin-inventory-"));
  try {
    const serverDir = join(dir, "servers", "gateway", "routes");
    mkdirSync(serverDir, { recursive: true });
    writeFileSync(join(serverDir, "new-sender.js"), [
      'import { getPeerCreds } from "../../shared/peer-credentials.js";',
      "export async function go(id, url) {",
      "  const creds = getPeerCreds(id);",
      '  return fetch(url, { headers: { Authorization: `Bearer ${creds.auth_token}` } });',
      "}",
      "",
    ].join("\n"));
    // …and a control that handles no credential, which must NOT be discovered.
    writeFileSync(join(serverDir, "not-a-sender.js"), "export const x = () => fetch('http://example.test/x');\n");

    const files = listSourceFiles(join(dir, "servers"))
      .map((abs) => ({ path: relative(dir, abs).split(sep).join("/"), src: readFileSync(abs, "utf8") }));
    assert.equal(files.length, 2, "the fixture walk found both files");
    const discovered = discoverSenders(files);
    assert.deepEqual(discovered, ["servers/gateway/routes/new-sender.js"], "the credential + fetch file is discovered, the plain fetch file is not");

    // And the gate the real test applies would refuse it: it is unreviewed.
    const reviewed = new Set(SENDERS.map(([f]) => f));
    assert.equal(reviewed.has(discovered[0]), false, "an unreviewed new sender fails the inventory");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the pin API and its one-time backfill are wired where they must be", () => {
  const pc = read("servers/shared/peer-credentials.js");
  for (const fn of ["normalizeGatewayOrigin", "pinPeerOrigin", "peerUrlAllowed", "pinBackfillDoneAt", "markPinBackfillDone", "noRedirectFetch"]) {
    assert.match(pc, new RegExp(`export function ${fn}\\b`), `peer-credentials.js exports ${fn}`);
  }
  // The pin is set at pairing, in the flows that write the row themselves — and
  // only from a URL the ceremony itself supplied (never from the row).
  assert.match(read("scripts/cli/instance-pair.js"), /\bpinPeerOrigin\s*\(/, "the pair CLI pins what it stores");
  assert.match(read("scripts/cli/instance-pair.js"), /peerPinCandidateForCeremony\(/, "…from the ceremony's address, not the row");
  assert.match(read("servers/gateway/routes/instance-enroll.js"), /\bpinPeerOrigin\s*\(/, "the enroll route pins the address it writes");
  // One-time backfill, run at boot BEFORE routes serve.
  assert.match(read("servers/gateway/index.js"), /runPeerOriginBackfill\(/, "the gateway runs the backfill at boot");
  assert.match(read("servers/gateway/boot/peer-origin-backfill.js"), /pinBackfillDoneAt\(/, "the backfill is marker-gated");
  // The marker is its own file, never a store key, and the store's writers and
  // the trust sweeper never treat a metadata value as an entry.
  assert.match(pc, /export function peerPinBackfillPath\b/, "the marker has its own path");
  assert.match(pc, /for \(const k of STORE_META_KEYS\)[\s\S]{0,160}!isPeerEntry\(parsed\[k\]\)[\s\S]{0,40}delete parsed\[k\]/, "loadPeerCreds strips only a metadata VALUE, never a peer entry");
  assert.match(read("servers/gateway/peer-trust-sweeper.js"), /if \(!isStoreEntry\(entry\)\) continue;/, "the sweeper only ever deletes real entries");
});