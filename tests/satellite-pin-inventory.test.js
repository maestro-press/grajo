/**
 * Static inventory: every sender of a SATELLITE management-key request builds its destination
 * through the ADDRESS PIN.
 *
 * `satellites.tailnet_host` is bot-writable crow.db; a management-key signature covers the
 * method, path, body, id, ts, nonce and caller — never the destination — and the request BODY is
 * the leak (add-on env values, a bot's tool arguments, a whole encrypted backup). The host is
 * therefore recorded in <CROW_HOME>/secrets/satellite-pins.json at pairing, and every sender asks
 * servers/shared/satellite-pins.js for its URL: satelliteBaseUrlFor() (which refuses a row that
 * does not normalize to the pin) or, for the unsigned health probe, satelliteUrlAllowed().
 *
 * The SENDER set is DISCOVERED, not listed from memory: every source file under servers/, scripts/
 * and bundles/<id>/{panel,server}/ that both handles a satellite management credential (a key
 * loader, a signing primitive, an X-Crow-Sat- header, `mgmtKey`, `tailnet_host`, the pin gate) and
 * can issue an outbound request must be reviewed here. A reviewed sender must consult the gate
 * itself, or call satelliteFetch() — the one transport that does (client.js, reviewed as a gate
 * sender). A new sender that forgets is exactly the bug this file refuses to let back in.
 *
 * The satellite-side server (servers/satellite/) is excluded wholesale: it is the OTHER end of the
 * wire. It reads incoming requests and verifies signatures; it never dials a satellite and has no
 * address to pin.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { basename, join, relative, sep } from "node:path";
import { tmpdir } from "node:os";

const REPO = new URL("../", import.meta.url).pathname;
const read = (p) => readFileSync(join(REPO, p), "utf8");

/** The one directory excluded wholesale, with the reason kept beside the rule. */
const EXCLUDED_DIRS = {
  "servers/satellite":
    "the satellite-side agent: it RECEIVES signed requests and verifies them; it never dials a satellite, so it has no address to pin (its own files are not senders)",
};

/**
 * Reviewed SENDERS: `via` says how the file reaches the gate.
 *   "gate"           — it builds the URL itself and must call satelliteBaseUrlFor()/satelliteUrlAllowed()
 *   "satelliteFetch" — it only calls satelliteFetch(), whose gate is client.js (reviewed below)
 */
const SENDERS = [
  {
    file: "servers/gateway/satellites/client.js",
    via: "gate",
    what: "the signed satellite transport (satelliteFetch/sendOnce): the management key is read and the request is signed only AFTER satelliteBaseUrlFor()",
  },
  {
    file: "servers/gateway/satellites/backup-pull.js",
    via: "gate",
    what: "the backup manifest GET and the plain file download, both built from satelliteBaseUrlFor()",
  },
  {
    file: "servers/gateway/satellites/offsite.js",
    via: "gate",
    what: "the off-site vault list/put/get/delete, each gated by satelliteBaseUrlFor() before the key is read and the body opened",
  },
  {
    file: "servers/gateway/satellites/remote.js",
    via: "gate",
    what: "the unsigned /health probe (satelliteUrlAllowed + satelliteBaseUrlFor) and the signed tool list (satelliteFetch)",
  },
  {
    file: "servers/gateway/satellites/tool-entry.js",
    via: "satelliteFetch",
    what: "a bot-driven satellite tool call: one signed tools/call through satelliteFetch",
  },
  {
    file: "servers/gateway/satellites/renewal.js",
    via: "satelliteFetch",
    what: "cert renewal and management-key rotation calls, through satelliteFetch",
  },
  {
    file: "servers/gateway/satellites/manage.js",
    via: "satelliteFetch",
    what: "the owner's remote-management relay (bundles, consent, jobs, env, logs, backups), through satelliteFetch",
  },
  {
    file: "servers/gateway/satellites/poller.js",
    via: "satelliteFetch",
    what: "the status poller: satelliteFetch for status, readHealth (gated in remote.js) for the clock",
  },
];

/**
 * Reviewed NON_SENDERS: discovered files that must NOT be forced through the pin gate, with the
 * reason each one cannot choose a satellite destination of its own.
 */
const NON_SENDERS = {
  "servers/gateway/satellites/pairing.js":
    "the pairing ceremony: its pair legs dial the host the OWNER typed (vetted and kept in the in-memory pending record — there is no pin yet), and its unpair leg goes through satelliteFetch (gated in client.js). The rules this file carries instead are that it calls pinSatelliteHost() with the ceremony host BEFORE insertSatellite()/replaceRevokedSatellite() and never derives one from a row (asserted below)",
  "servers/shared/peer-forward.js":
    "the cross-host PEER forwarder: it signs with the peer's pair key (cross-host-auth.js signRequest), never a satellite management key, and its destination is the paired peer origin (peerUrlAllowed in peer-credentials.js) — covered by tests/peer-origin-pin-inventory.test.js",
};

// A file that handles a satellite management credential in ANY of its forms: the key loader, a
// signing primitive from servers/shared/satellite-protocol.js, an X-Crow-Sat- header, the
// `mgmtKey` parameter, the post-pairing `tailnet_host` read, the pin gate itself, or the one
// transport all of them go through (satelliteFetch).
const CREDENTIAL_RE = /\bloadMgmtKey\s*\(|\bcreateMgmtKey\b|\bloadStagedMgmtKey\s*\(|\bsignRequest\s*\(|\bsignBytes\s*\(|\bX-Crow-Sat-(?:Sig|Nonce|Caller)\b|\bmgmtKey\b|(?<![A-Za-z0-9_])tailnet_host(?![A-Za-z0-9_])|satelliteBaseUrl|\bsatelliteFetch\b/;
const OUTBOUND_RE = /\bfetch\s*\(|\bfetchImpl\b|\bsendOnce\b|\bsatelliteFetch\b|\bpostPair\b|\bhttps?\.request\s*\(|StreamableHTTPClientTransport/;

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

/** The discovery rule: a file that handles a satellite credential AND can issue a request. */
export function discoverSenders(files) {
  return files
    .filter((f) => !Object.keys(EXCLUDED_DIRS).some((dir) => f.path === dir || f.path.startsWith(`${dir}/`)))
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

// ── the address READ (per file) ─────────────────────────────────────────────
//
// The second half of the inventory is about the primitive itself, not the file list: no code under
// servers/gateway/satellites/ may READ the row's address, and no dial may take its URL from
// anything but the pin gate. Both checks are exported so fixtures can prove they catch what they
// claim to.

/** A file whose every `tailnet_host` token is allowed: the store IS the column's own reader. */
const STORE_FILES = new Set(["store.js"]);
/** The one allowed row literal: the ceremony writing the row it has just pinned. */
const PAIRING_ROW_LITERAL = /^tailnet_host\s*:\s*p\.host(?![A-Za-z0-9_$])/;

/** A readable window around `index`, for an error message (never a whole file). */
function snippet(source, index, width = 60) {
  const from = Math.max(0, index - width);
  const to = Math.min(source.length, index + width);
  return source.slice(from, to).replace(/\s+/g, " ").trim();
}

/** A `/` after one of these (or at the start) opens a regex literal, not a division. */
const REGEX_PREV = new Set(["(", "[", "{", ",", ";", ":", "=", "!", "&", "|", "?", "+", "-", "*", "%", "~", "^", "<", ">"]);

/**
 * `source` with COMMENTS blanked out (same length, newlines kept), so the checks below see code
 * only: a doc comment that merely mentions a name is not a read. With `keepStrings` false, STRING
 * and TEMPLATE TEXT is blanked too, so a `(` inside a string cannot unbalance an argument list
 * (a `${…}` expression in a template stays — that part IS code, and it is where the gate is
 * called). Regex literals are handled either way, so the `//` inside `/^https:\/\//` is not
 * mistaken for a comment.
 */
function maskCode(source, { keepStrings = false } = {}) {
  const out = source.split("");
  const blank = (i) => { if (out[i] !== "\n" && !keepStrings) out[i] = " "; };
  const comment = (i) => { if (out[i] !== "\n") out[i] = " "; };
  const templates = []; // one brace depth per open `${ … }`
  let depth = 0;
  let mode = "code";
  let inClass = false;
  let prev = "";
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    const d = source[i + 1];
    if (mode === "line") {
      if (c === "\n") { mode = "code"; prev = ""; } else comment(i);
      continue;
    }
    if (mode === "block") {
      if (c === "*" && d === "/") { comment(i); comment(i + 1); i++; mode = "code"; prev = ""; continue; }
      comment(i);
      continue;
    }
    if (mode === "single" || mode === "double") {
      if (c === "\\") { blank(i); blank(i + 1); i++; continue; }
      if (c === (mode === "single" ? "'" : '"')) { mode = "code"; prev = c; continue; }
      blank(i);
      continue;
    }
    if (mode === "template") {
      if (c === "\\") { blank(i); blank(i + 1); i++; continue; }
      if (c === "`") { mode = "code"; prev = c; continue; }
      if (c === "$" && d === "{") { templates.push(depth); depth = 0; mode = "code"; i++; continue; }
      blank(i);
      continue;
    }
    if (mode === "regex") {
      if (c === "\\") { blank(i); blank(i + 1); i++; continue; }
      if (c === "[") inClass = true;
      else if (c === "]") inClass = false;
      else if (c === "/" && !inClass) { mode = "code"; prev = c; continue; }
      blank(i);
      continue;
    }
    // code
    if (c === "/" && d === "/") { mode = "line"; comment(i); comment(i + 1); i++; continue; }
    if (c === "/" && d === "*") { mode = "block"; comment(i); comment(i + 1); i++; continue; }
    if (c === "'") { mode = "single"; prev = c; continue; }
    if (c === '"') { mode = "double"; prev = c; continue; }
    if (c === "`") { mode = "template"; prev = c; continue; }
    if (c === "/") {
      if (prev === "" || REGEX_PREV.has(prev)) { mode = "regex"; inClass = false; }
      prev = c;
      continue;
    }
    if (c === "{") { if (templates.length) depth++; prev = c; continue; }
    if (c === "}") {
      if (templates.length && depth === 0) { templates.pop(); mode = "template"; prev = c; continue; }
      if (templates.length) depth--;
      prev = c;
      continue;
    }
    if (!/\s/.test(c)) prev = c;
  }
  return out.join("");
}

/**
 * Every READ of `satellites.tailnet_host` in `source`, as offending snippets (empty when clean).
 *
 * The value is bot-writable crow.db, so it may only be read inside
 * servers/shared/satellite-pins.js — and by the `satellites` store, which is the column's own
 * reader. Anywhere under servers/gateway/satellites/ a read — dot access, a destructuring pattern,
 * a bracket key, a template literal or a concatenation — means a sender built a destination out of
 * the row instead of out of the pin, which is the bug the pin exists to stop. The SINGLE exception
 * is the pairing ceremony's own row literal (`tailnet_host: p.host`): that WRITES the row from the
 * host the ceremony vetted, it does not read one.
 */
export function findTailnetHostReads(source, fileName) {
  const file = basename(fileName);
  if (STORE_FILES.has(file)) return [];
  // Strings are KEPT here: `sat["tailnet_host"]` and `${sat.tailnet_host}` are reads.
  const src = maskCode(source, { keepStrings: true });
  const out = [];
  for (const m of src.matchAll(/tailnet_host/g)) {
    if (file === "pairing.js" && PAIRING_ROW_LITERAL.test(src.slice(m.index, m.index + 48))) continue;
    out.push(snippet(source, m.index));
  }
  return out;
}

/** The gate each file's dials must take a URL from. A file not listed here claims no URL rule. */
const GATE_BY_FILE = {
  "client.js": "satelliteBaseUrlFor",
  "backup-pull.js": "satelliteBaseUrlFor",
  "offsite.js": "satelliteBaseUrlFor",
  "remote.js": "satelliteBaseUrlFor",
  "pairing.js": "pairingBaseUrl",
};
/** The two call expressions that actually dial (sendOnce delegates to the fetch impl). */
const DIAL_CALLS = ["sendOnce", "fetchImpl"];

/** The argument texts of the call whose `(` is at `open`, on paren-safe (masked) source. */
function callArguments(src, open) {
  let paren = 1;
  let braces = 0;
  let brackets = 0;
  const args = [];
  let start = open + 1;
  for (let i = open + 1; i < src.length; i++) {
    const c = src[i];
    if (c === "(") paren++;
    else if (c === ")") {
      paren--;
      if (paren === 0) { args.push(src.slice(start, i)); return { args, close: i }; }
    } else if (c === "{") braces++;
    else if (c === "}") braces--;
    else if (c === "[") brackets++;
    else if (c === "]") brackets--;
    else if (c === "," && paren === 1 && braces === 0 && brackets === 0) { args.push(src.slice(start, i)); start = i + 1; }
  }
  return null;
}

/** Every `<dialCall>(…)` call expression in masked source, in source order. */
function dialCalls(src) {
  const calls = [];
  for (const name of DIAL_CALLS) {
    for (const m of src.matchAll(new RegExp(`(?<![A-Za-z0-9_$.])${name}\\s*\\(`, "g"))) {
      const got = callArguments(src, m.index + m[0].length - 1);
      if (got) calls.push({ name, start: m.index, end: got.close, args: got.args });
    }
  }
  return calls.sort((a, b) => a.start - b.start);
}

/** `[start, end]` of `function <name>(…) { … }` in masked source, or null. */
function definitionSpan(src, name) {
  const m = new RegExp(`function\\s+${name}\\s*\\(`).exec(src);
  if (!m) return null;
  const params = callArguments(src, m.index + m[0].length - 1);
  if (!params) return null;
  const bodyOpen = src.indexOf("{", params.close);
  if (bodyOpen < 0) return null;
  let depth = 0;
  for (let i = bodyOpen; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return [m.index, i];
  }
  return null;
}

/** Variables holding a URL the gate built: `const base = satelliteBaseUrlFor(sat, { env })`. */
function gateVars(src, gate) {
  const out = new Set();
  for (const m of src.matchAll(new RegExp(`(?<![A-Za-z0-9_$.])([A-Za-z_$][\\w$]*)\\s*=(?!=)\\s*${gate}\\s*\\(`, "g"))) out.add(m[1]);
  return out;
}

const escapeVar = (v) => v.replace(/\$/g, "\\$");

/**
 * Does this URL argument start at the gate — its own expression, or its first `${…}`?
 * `base`, `base + path`, `` `${base}/health` `` and `${satelliteBaseUrlFor(sat)}/health` all do;
 * anything beginning with a string literal or an unassigned name does not.
 */
function startsAtGate(rawArg, vars, gate) {
  const text = rawArg.trim().replace(/^`/, "");
  const heads = [text, text.replace(/^\$\{\s*/, "")];
  return heads.some((h) => new RegExp(`^${gate}\\s*\\(`).test(h)
    || [...vars].some((v) => new RegExp(`^${escapeVar(v)}(?![A-Za-z0-9_$])`).test(h)));
}

/**
 * Every `sendOnce(…)` / `fetchImpl(…)` call in a gate file whose URL does not come from the pin
 * gate, as offending snippets (empty when clean).
 *
 * `sendOnce`'s URL is its SECOND argument (the first is the fetch impl, `client.js` defines it);
 * `fetchImpl`'s is its first. Any argument of either call that mentions `tailnet_host` is an
 * offender whatever position it is in. `client.js`'s own `sendOnce` DEFINITION is exempt — that IS
 * the transport, and its `fetchImpl(url, …)` dials the URL it was handed.
 */
export function findUngatedCalls(source, fileName) {
  const file = basename(fileName);
  const gate = GATE_BY_FILE[file];
  if (!gate) return [];
  const src = maskCode(source);
  const withStrings = maskCode(source, { keepStrings: true });
  const vars = gateVars(src, gate);
  const def = file === "client.js" ? definitionSpan(src, "sendOnce") : null;
  const out = [];
  for (const call of dialCalls(src)) {
    if (def && call.start >= def[0] && call.start <= def[1]) continue;
    const url = call.args[call.name === "sendOnce" ? 1 : 0];
    // Any mention of the row's column in the call is a refusal, in whatever position or spelling
    // (read from the strings-kept copy, so a bracket key is not hidden by the structure mask).
    const mentionsRow = /tailnet_host/.test(withStrings.slice(call.start, call.end + 1));
    if (url === undefined || mentionsRow || !startsAtGate(url, vars, gate)) out.push(snippet(source, call.start, 80));
  }
  return out;
}

test("every discovered satellite sender asks the address gate (or goes through satelliteFetch)", () => {
  const discovered = discoverSenders(scanRepo());
  const reviewedSenders = new Set(SENDERS.map((s) => s.file));
  const reviewedNonSenders = new Set(Object.keys(NON_SENDERS));

  const unreviewed = discovered.filter((f) => !reviewedSenders.has(f) && !reviewedNonSenders.has(f));
  assert.deepEqual(unreviewed, [],
    "a file that handles a satellite management credential and can issue a request must be reviewed: add it to SENDERS (with the gate it calls) or to NON_SENDERS with the reason it cannot choose a satellite destination");

  const stale = [...reviewedSenders, ...reviewedNonSenders].filter((f) => !discovered.includes(f));
  assert.deepEqual(stale, [], "every reviewed entry must still be a discovered sender (update the list when the code moves)");

  const offenders = [];
  for (const s of SENDERS) {
    const src = read(s.file);
    if (s.via === "gate") {
      if (!/\bsatelliteBaseUrlFor\s*\(|\bsatelliteUrlAllowed\s*\(/.test(src)) offenders.push(`${s.file}: ${s.what}`);
    } else if (s.via === "satelliteFetch") {
      // satelliteFetch is the one transport; client.js is where its gate lives. A file that
      // calls it is covered only while that transport is itself a reviewed gate sender.
      if (!/\bsatelliteFetch\s*\(/.test(src)) offenders.push(`${s.file}: ${s.what}`);
      if (!reviewedSenders.has("servers/gateway/satellites/client.js")) offenders.push(`${s.file}: satelliteFetch has no reviewed gate`);
    } else {
      offenders.push(`${s.file}: unknown via ${JSON.stringify(s.via)}`);
    }
  }
  assert.deepEqual(offenders, [], `a satellite request may only go to its PINNED address:\n${offenders.join("\n")}`);

  // The transport satelliteFetch delegates to must itself be a gate sender, or every "via"
  // entry above would be a promise with nothing behind it.
  const client = SENDERS.find((s) => s.file === "servers/gateway/satellites/client.js");
  assert.equal(client?.via, "gate", "client.js is the reviewed gate for every satelliteFetch caller");
  assert.match(read("servers/gateway/satellites/client.js"), /\bsatelliteBaseUrlFor\s*\(/, "client.js gates before the management key is read");
});

test("the discovery catches a NEW sender (fixture)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sat-pin-inventory-"));
  try {
    const serverDir = join(dir, "servers", "gateway", "routes");
    mkdirSync(serverDir, { recursive: true });
    writeFileSync(join(serverDir, "new-sender.js"), [
      'import { loadMgmtKey } from "../satellites/mgmt-keys.js";',
      "export async function go(url) {",
      "  const key = loadMgmtKey(\"sat_aaaaaaaaaaaaaaaaaaaa\");",
      "  return fetch(url, { headers: { \"X-Crow-Sat-Sig\": key.ed25519_priv } });",
      "}",
      "",
    ].join("\n"));
    // …and a control that handles no satellite credential, which must NOT be discovered.
    writeFileSync(join(serverDir, "not-a-sender.js"), "export const x = () => fetch('http://example.test/x');\n");
    // …and the excluded satellite side, which must never be discovered.
    const satDir = join(dir, "servers", "satellite");
    mkdirSync(satDir, { recursive: true });
    writeFileSync(join(satDir, "agent.js"), [
      'import Database from "better-sqlite3";',
      "export const go = (url) => fetch(url, { headers: { \"X-Crow-Sat-Nonce\": \"n\" } });",
      "",
    ].join("\n"));

    const files = listSourceFiles(join(dir, "servers"))
      .map((abs) => ({ path: relative(dir, abs).split(sep).join("/"), src: readFileSync(abs, "utf8") }));
    assert.equal(files.length, 3, "the fixture walk found every file");
    const discovered = discoverSenders(files);
    assert.deepEqual(discovered, ["servers/gateway/routes/new-sender.js"],
      "the credential + fetch file is discovered; the plain fetch file and the satellite-side agent are not");

    // And the gate the real test applies would refuse it: it is unreviewed.
    const reviewed = new Set(SENDERS.map((s) => s.file));
    assert.equal(reviewed.has(discovered[0]), false, "an unreviewed new sender fails the inventory");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("nothing under gateway/satellites builds a URL from a row, and the pairing writes the pin first", () => {
  // The removed helper: a bare `satelliteBaseUrl(host)` would dial a row's value again.
  const dir = join(REPO, "servers", "gateway", "satellites");
  for (const abs of listSourceFiles(dir)) {
    const path = rel(abs);
    const src = readFileSync(abs, "utf8");
    assert.doesNotMatch(src, /\bsatelliteBaseUrl\s*\(/, `${path} must use satelliteBaseUrlFor(row) (pin) or pairingBaseUrl(host), never satelliteBaseUrl`);
    assert.doesNotMatch(src, /tailnet_host\s*\}/, `${path} must not build a value from the row's tailnet_host`);
    assert.doesNotMatch(src, /\$\{[^}\n]*tailnet_host/, `${path} must not put the row's tailnet_host in a template/String URL`);
  }

  // The ceremony pins BEFORE the row exists (the inventory for the ordering itself: the runtime
  // proof is in tests/satellite-pairing.test.js "writes the pin BEFORE the row exists").
  const pairing = read("servers/gateway/satellites/pairing.js");
  const pinAt = pairing.indexOf("pinSatelliteHost(");
  const insertAt = pairing.indexOf("insertSatellite(");
  const replaceAt = pairing.indexOf("replaceRevokedSatellite(");
  assert.ok(pinAt >= 0, "pairing.js calls pinSatelliteHost");
  assert.ok(insertAt >= 0 && replaceAt >= 0, "pairing.js writes a row");
  assert.ok(pinAt < insertAt, "the pin is written before insertSatellite");
  assert.ok(pinAt < replaceAt, "the pin is written before replaceRevokedSatellite");
  // …and it is the ceremony's host that is pinned, never one read back from a row.
  assert.match(pairing, /pinSatelliteHost\(\s*p\.satellite_id\s*,\s*p\.host\s*(?:,\s*\{[^}]*\})?\s*\)/, "the pin comes from the pending ceremony record");
  assert.doesNotMatch(pairing, /pinSatelliteHost\([^)]*tailnet_host/, "the pin never comes from a row");
});

test("no file under gateway/satellites reads the row's address (store.js and the pairing row literal excepted)", () => {
  // remote.js is the case this rule was written for: its health probe used to read
  // `sat?.tailnet_host`. It now asks the gate, exactly like every other sender.
  const dir = join(REPO, "servers", "gateway", "satellites");
  const offenders = [];
  for (const abs of listSourceFiles(dir)) {
    const path = rel(abs);
    for (const found of findTailnetHostReads(readFileSync(abs, "utf8"), path)) offenders.push(`${path}: ${found}`);
  }
  assert.deepEqual(offenders, [],
    `the row's tailnet_host may only be read inside servers/shared/satellite-pins.js (satelliteRowAllowed/satelliteBaseUrlFor) or the satellites store:\n${offenders.join("\n")}`);

  // The exemptions are real, and minimal: the store is exempt whole, pairing.js only for the row
  // literal it writes.
  assert.deepEqual(findTailnetHostReads(read("servers/gateway/satellites/store.js"), "servers/gateway/satellites/store.js"), []);
  const pairing = read("servers/gateway/satellites/pairing.js");
  assert.match(pairing, /tailnet_host: p\.host/, "the ceremony still writes the row from its vetted host");
  assert.deepEqual(findTailnetHostReads(pairing, "servers/gateway/satellites/pairing.js"), []);
  // …and a destructuring read in the same file is NOT covered by that exemption.
  assert.deepEqual(findTailnetHostReads(`${pairing}\nconst { tailnet_host: h } = sat;\n`, "servers/gateway/satellites/pairing.js").length, 1);
});

test("every dial in a gate file takes its URL from the pin gate", () => {
  const offenders = [];
  for (const file of Object.keys(GATE_BY_FILE)) {
    const path = `servers/gateway/satellites/${file}`;
    for (const found of findUngatedCalls(read(path), path)) offenders.push(`${path}: ${found}`);
  }
  assert.deepEqual(offenders, [],
    `a sendOnce()/fetchImpl() URL must be built by satelliteBaseUrlFor(row) (or pairingBaseUrl(host) in the ceremony):\n${offenders.join("\n")}`);
});

test("the two checks catch what they claim to, and a clean snippet passes (fixtures)", () => {
  const clean = [
    "const base = satelliteBaseUrlFor(sat, { env });",
    "const res = await sendOnce(fetchImpl, base + path, { method: \"GET\", timeoutMs });",
    "const health = await fetchImpl(`${base}/health`, { method: \"GET\" });",
    "const r = await fetchImpl(`${satelliteBaseUrlFor(sat)}/health`, { method: \"GET\" });",
  ].join("\n");
  assert.deepEqual(findUngatedCalls(clean, "client.js"), [], "gated calls are not flagged");
  assert.deepEqual(findTailnetHostReads(`${clean}\n// a comment may mention tailnet_host\n`, "remote.js"), [], "a comment is not a read");
  // The transport's own definition is exempt, and only the definition.
  const def = "export async function sendOnce(fetchImpl, url, { method, headers, body, timeoutMs }) {\n  return await fetchImpl(url, { method });\n}\n";
  assert.deepEqual(findUngatedCalls(def, "client.js"), []);
  assert.equal(findUngatedCalls(`${def}const r = await sendOnce(fetchImpl, url, {});\n`, "client.js").length, 1, "a call with an unassigned `url` in the same file is flagged");

  // A URL built from the row, concatenated: caught (and it names the reason).
  assert.equal(findUngatedCalls('const r = await sendOnce(fetchImpl, "https://" + sat.tailnet_host + path, {});\n', "client.js").length, 1);
  assert.equal(findTailnetHostReads('const r = await sendOnce(fetchImpl, "https://" + sat.tailnet_host + path, {});\n', "client.js").length, 1);
  // A URL the gate never built: caught.
  assert.equal(findUngatedCalls('const r = await sendOnce(fetchImpl, sat.url, {});\n', "offsite.js").length, 1);
  assert.equal(findUngatedCalls('const r = await fetchImpl(row.url, {});\n', "offsite.js").length, 1);
  // Destructuring, bracket and template reads: all caught.
  assert.equal(findTailnetHostReads("const { tailnet_host: h } = sat;\n", "remote.js").length, 1);
  assert.equal(findTailnetHostReads("const { tailnet_host } = sat;\n", "remote.js").length, 1);
  assert.equal(findTailnetHostReads('const h = sat["tailnet_host"];\n', "remote.js").length, 1);
  assert.equal(findTailnetHostReads("const h = sat['tailnet_host'];\n", "remote.js").length, 1);
  assert.equal(findTailnetHostReads("const u = `${sat.tailnet_host}/health`;\n", "remote.js").length, 1);
  assert.equal(findTailnetHostReads('const u = "https://" + sat.tailnet_host;\n', "remote.js").length, 1);
  assert.equal(findTailnetHostReads("const u = sat.tailnet_host;\n", "remote.js").length, 1);
  // The store is the only whole-file exemption.
  assert.deepEqual(findTailnetHostReads("const u = sat.tailnet_host;\n", "servers/gateway/satellites/store.js"), []);
  // pairing.js: the row literal passes, a read next to it does not.
  assert.deepEqual(findTailnetHostReads("const row = { id: p.satellite_id, tailnet_host: p.host };\n", "pairing.js"), []);
  assert.equal(findTailnetHostReads("const row = { id, tailnet_host: h };\n", "pairing.js").length, 1);
  // pairing.js dials through pairingBaseUrl, not the pin gate.
  assert.deepEqual(findUngatedCalls("const res = await sendOnce(fetchImpl, pairingBaseUrl(host) + path, {});\n", "pairing.js"), []);
  assert.equal(findUngatedCalls("const res = await sendOnce(fetchImpl, `https://${host}${path}`, {});\n", "pairing.js").length, 1);
});

test("the pin module, the boot backfill and the owner CLI are wired where they must be", () => {
  const pins = read("servers/shared/satellite-pins.js");
  for (const fn of ["normalizeSatelliteHost", "pinSatelliteHost", "getSatellitePin", "listSatellitePins", "unpinSatellite", "satelliteUrlAllowed", "satelliteBaseUrlFor", "satellitePinBackfillDoneAt", "markSatellitePinBackfillDone", "satellitePinBackfillPath"]) {
    assert.match(pins, new RegExp(`export function ${fn}\\b`), `satellite-pins.js exports ${fn}`);
  }
  // One-time backfill, run at boot BEFORE routes serve, gated by its own marker file.
  assert.match(read("servers/gateway/index.js"), /runSatellitePinBackfill\(/, "the gateway runs the backfill at boot");
  assert.match(read("servers/gateway/boot/satellite-pin-backfill.js"), /satellitePinBackfillDoneAt\(/, "the backfill is marker-gated");
  // Unpair drops the pin only after crow's side succeeded (inside the try, before the finally).
  const pairing = read("servers/gateway/satellites/pairing.js");
  const unpinAt = pairing.search(/unpinSatellite\(id[,)]/);
  const finallyAt = pairing.indexOf("} finally {", pairing.indexOf("async function unpairSatellite"));
  assert.ok(unpinAt >= 0 && finallyAt > unpinAt, "unpairSatellite unpins inside the try, never in the finally");
  // The owner's CLI exists and never writes crow.db.
  const cli = read("scripts/cli/satellite-pin.js");
  assert.match(cli, /resolveCrowHome\(\)/, "the CLI refuses under a test runner without CROW_HOME");
  assert.match(cli, /normalizeSatelliteHost\(/, "the CLI normalizes the host it is given");
  assert.match(cli, /readonly:\s*true/, "the CLI opens crow.db read-only");
  assert.doesNotMatch(cli, /createDbClient\s*\(|INSERT INTO|UPDATE |DELETE FROM/, "the CLI never writes crow.db");
});