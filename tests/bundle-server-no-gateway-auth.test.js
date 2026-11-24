/**
 * bundle-server-no-gateway-auth — nothing a bot can load may reach the gateway's
 * session checks.
 *
 * WHY (2026, token-HMAC key move): a bundle's `server/` tree is BOT-REACHABLE —
 * a bot MCP child can be spawned on it — while a bundle's `panel/` code runs
 * only inside the gateway (the gateway imports the panel and its panel routes,
 * and their imports with them). The session checks read
 * `servers/gateway/dashboard/auth.js` and
 * `servers/gateway/dashboard/local-session.js`, which both go through
 * `servers/gateway/token-store.js` — the ONE place a session / OAuth verifier is
 * minted and checked, under `servers/shared/token-mac.js`'s host-only HMAC key.
 *
 * Two modules used to sit in a server/ tree and import them:
 *   - bundles/maker-lab/server/device-binding.js  (auth.js, for hasAdminSession)
 *   - bundles/phone/server/authority.js           (local-session.js)
 * They had exactly one kind of caller — that bundle's panel/ code — so they now
 * live in panel/ (panel/device-binding.js, panel/authority.js), resolved through
 * the bundle's app root. `tests/bot-seed-import-guard.test.js` no longer has to
 * allow-list `servers/gateway/token-store.js`, and this file keeps the tree
 * shape that made that possible: a static, TRANSITIVE scan of every
 * `bundles/<id>/server/**.js`, following relative specifiers, the app-root seam
 * (`appImport("servers/…")`, `import("servers/…")`) and `bundleImport("…")`.
 *
 * THE CORE SERVERS ARE SCANNED TOO, with the SAME entry set the seed guard derives
 * (`coreBotServerFiles()` from tests/bot-seed-import-guard.test.js): every stdio server the bot
 * catalog can emit is spawned for a bot exactly like a bundle's server/ tree, so
 * "bundle code may not reach the session checks" was only half the rule. It is what caught the
 * real hole: `servers/research/server.js` -> `servers/shared/project-lifecycle.js` -> (lazy,
 * literal) `servers/gateway/proxy.js` -> `fix-it/index.js` -> every remedy -> the owner rule
 * (`dashboard/local-session.js`) -> `token-store.js`. The fix is at the source (the ownership
 * helpers the research server needs now live in `servers/shared/project-ownership.js`), and this
 * scan proves it: nothing a bot can load reaches any of the three modules.
 *
 * Only statically-written literal specifiers are checked (the same stated limit
 * as the seed guard): a computed import cannot be followed by any static check,
 * which is why the seed guard reviews those separately — over the whole walked set.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
// The SAME derivation the seed guard uses, so the two guards cannot disagree about which trees a
// bot can load. Importing the guard module registers its tests in this process as well (the
// repo's existing pattern — tests/pibot-hidden-files.test.js does the same).
import { coreBotServerFiles } from "./bot-seed-import-guard.test.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CODE_FILE = /\.(?:js|mjs|cjs)$/;

/** The modules a bundle's server/ tree may never import, directly or transitively. */
const FORBIDDEN = [
  "servers/gateway/dashboard/auth.js",
  "servers/gateway/dashboard/local-session.js",
  "servers/gateway/token-store.js",
];

/** Every regular .js/.mjs/.cjs file under `dir` (recursive, symlinks not followed). */
function walkCode(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walkCode(p, out);
    else if (e.isFile() && CODE_FILE.test(e.name)) out.push(p);
  }
  return out;
}

/** Every `bundles/<id>/server/**` code file. */
function bundleServerFiles({ root = ROOT } = {}) {
  const out = [];
  let bundles;
  try { bundles = readdirSync(resolve(root, "bundles"), { withFileTypes: true }); } catch { return out; }
  for (const ent of bundles) {
    if (!ent.isDirectory()) continue;
    out.push(...walkCode(resolve(root, "bundles", ent.name, "server")));
  }
  return out;
}

/**
 * The scan roots: every bundle server/ tree PLUS the core bot-reachable servers, derived the
 * way the seed guard derives them (coreBotServerFiles walks each server entry's directory).
 */
function botLoadableFiles({ root = ROOT } = {}) {
  const seen = new Set();
  const out = [];
  for (const f of [...bundleServerFiles({ root }), ...coreBotServerFiles({ root })]) {
    if (seen.has(f)) continue;
    seen.add(f);
    out.push(f);
  }
  return out;
}

const SPEC_PATTERNS = [
  /\bfrom\s*["']([^"']+)["']/g,               // import … from "x" | export … from "x"
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,    // dynamic import("x")
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,   // createRequire / CJS
  /\bappImport\s*\(\s*["']([^"']+)["']\s*\)/g, // the bundle app-root seam
];
/** `bundleImport("store.js")` — both bundles resolve it against their own server/ dir. */
const BUNDLE_IMPORT = /\bbundleImport\s*\(\s*["']([^"']+)["']\s*\)/g;

/** The string-literal specifiers of every import/require seam in `src`. */
function specifiers(src) {
  const out = [];
  for (const re of SPEC_PATTERNS) {
    let m;
    while ((m = re.exec(src)) !== null) out.push({ kind: "path", spec: m[1] });
  }
  let b;
  while ((b = BUNDLE_IMPORT.exec(src)) !== null) out.push({ kind: "bundle", spec: b[1] });
  return out;
}

/** The bundle id of a file under `bundles/<id>/server/`, else null. */
function bundleIdOf(file, { root = ROOT } = {}) {
  const rel = relative(resolve(root, "bundles"), file);
  if (rel.startsWith("..")) return null;
  const parts = rel.split(sep);
  return parts.length > 2 && parts[1] === "server" ? parts[0] : null;
}

/**
 * The repo file a specifier names, from a file at `file`, or null when it names
 * nothing this scan can read (a bare package, a node: builtin, a computed path).
 */
function resolveTarget({ kind, spec }, file, { root = ROOT } = {}) {
  const clean = String(spec || "").split("?")[0];
  if (!clean) return null;
  let abs = null;
  if (kind === "bundle") {
    const id = bundleIdOf(file, { root });
    if (!id) return null;
    abs = resolve(root, "bundles", id, "server", clean);
  } else if (clean.startsWith(".")) abs = resolve(dirname(file), clean);
  else if (clean.startsWith("/")) abs = clean;
  // The app-root seam names a REPO-relative path ("servers/…"), resolved against the app root.
  else if (/^(?:servers|bundles|scripts|src)\//.test(clean)) abs = resolve(root, clean);
  else return null;
  for (const candidate of [abs, abs + ".js", abs + ".mjs", abs + ".cjs", join(abs, "index.js")]) {
    if (candidate !== root && !candidate.startsWith(root + sep)) continue; // never outside the app
    try { if (statSync(candidate).isFile()) return candidate; } catch { /* try the next shape */ }
  }
  return null;
}

/**
 * Breadth-first over the static import graph from `files`. Each finding is
 * reported against the bundle server/ FILE the walk started from (the rule's
 * subject), with the specifier that crossed into a forbidden module and the
 * whole chain, so the message reads
 * `bundles/x/server/a.js -> servers/gateway/dashboard/auth.js (a.js -> b.js -> auth.js)`.
 *
 * @returns {Array<{file: string, spec: string, chain: string[]}>} repo-relative paths
 */
function gatewayAuthChains(files, { root = ROOT, forbidden = FORBIDDEN } = {}) {
  const relOf = (f) => relative(root, f).split(sep).join("/");
  const forbiddenAbs = new Set(forbidden.map((p) => resolve(root, p)));
  const violations = [];
  const seen = new Set();
  const queue = files.map((file) => ({ file, origin: file, chain: [relOf(file)] }));
  while (queue.length > 0) {
    const { file, origin, chain } = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    let src;
    try { src = readFileSync(file, "utf8"); } catch { continue; }
    for (const edge of specifiers(src)) {
      const target = resolveTarget(edge, file, { root });
      if (!target) continue;
      if (forbiddenAbs.has(target)) {
        violations.push({ file: relOf(origin), spec: edge.spec, chain: [...chain, relOf(target)] });
        continue;
      }
      if (seen.has(target)) continue;
      queue.push({ file: target, origin, chain: [...chain, relOf(target)] });
    }
  }
  return violations;
}

// ─── the rule ───────────────────────────────────────────────────────────────

test("no bot-loadable file reaches the gateway's session checks (auth.js, local-session.js, token-store.js)", () => {
  const files = botLoadableFiles();
  assert.ok(files.length > 100, `the scan covers the real bundle trees, not a handful of files: ${files.length}`);
  // Non-vacuous: both trees this rule was written for are in the scan, and so are the core
  // server directories a bot MCP child is spawned on.
  const rels = files.map((f) => relative(ROOT, f).split(sep).join("/"));
  for (const id of ["maker-lab", "phone"]) {
    assert.ok(rels.some((f) => f.startsWith(`bundles/${id}/server/`)), `bundles/${id}/server/ must be scanned`);
  }
  for (const rel of ["servers/research/server.js", "servers/memory/server.js", "servers/storage/index.js"]) {
    assert.ok(rels.includes(rel), `${rel} is bot-reachable (a core MCP server entry) and must be scanned`);
  }
  // The two session-checking modules live in panel/ now, and those panel files
  // really do carry the checks — so "no violation" cannot mean "the code vanished".
  for (const rel of ["bundles/maker-lab/panel/device-binding.js", "bundles/phone/panel/authority.js"]) {
    const panelFile = resolve(ROOT, rel);
    assert.ok(gatewayAuthChains([panelFile]).length > 0,
      `${rel} is the gateway-side home of a session check and must still reach it`);
  }

  const violations = gatewayAuthChains(files);
  assert.deepEqual(
    violations,
    [],
    "a bot-loadable tree (a bundle's server/, or a core MCP server entry) is spawned for a bot, so it may not " +
    "reach the gateway's session checks or the token store behind them. Move the session-checking module to the " +
    "bundle's panel/ (which runs only inside the gateway) and resolve it through the app root, or — for a core " +
    "server — take the helper you need from a module that does not carry the host-side machinery. Chains: " +
    violations.map((v) => `${v.file} -> ${v.spec} (${v.chain.join(" -> ")})`).join(" | "),
  );
});

test("the scan is transitive and catches each seam (fixture tree: it cannot pass vacuously)", () => {
  const root = mkdtempSync(join(tmpdir(), "crow-bundle-auth-scan-"));
  try {
    const write = (rel, body) => {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), body);
    };
    for (const p of FORBIDDEN) write(p, "export const x = 1;\n");
    write("servers/gateway/dashboard/totp.js", "export const y = 1;\nexport * from \"./auth.js\";\n");

    write("bundles/planted/server/seam.js", 'const a = await appImport("servers/gateway/token-store.js");\n');
    write("bundles/planted/server/relative.js", 'import { x } from "../../../servers/gateway/token-store.js";\n');
    write("bundles/planted/server/via-hop.js", 'import "./hop.js";\n');
    write("bundles/planted/server/hop.js", 'export * from "../../../servers/gateway/dashboard/local-session.js";\n');
    write("bundles/planted/server/via-bundle-import.js", 'const m = await bundleImport("authority.js");\n');
    write("bundles/planted/server/authority.js", 'const s = await appImport("servers/gateway/dashboard/auth.js");\n');
    write("bundles/planted/server/via-gateway-hop.js", 'const t = await appImport("servers/gateway/dashboard/totp.js");\n');
    write("bundles/planted/server/clean.js", 'import { readFileSync } from "node:fs";\nimport "./ok.js";\n');
    write("bundles/planted/server/ok.js", "export const ok = 1;\n");
    // The allowed side: the same import in panel/ is the gateway's own business.
    write("bundles/planted/panel/ok.js", 'const s = await appImport("servers/gateway/dashboard/auth.js");\n');

    const flagged = gatewayAuthChains(botLoadableFiles({ root }), { root })
      .map((v) => `${v.file} -> ${v.spec}`).sort();
    // One finding per file that NAMES a forbidden module, with the chain spelled
    // out — so an indirect chain (via-hop -> hop -> local-session) is reported at
    // hop.js, and a gateway hop in between (via-gateway-hop -> totp -> auth) at the
    // bundle file that followed it. Nothing is missed either way.
    assert.deepEqual(flagged, [
      "bundles/planted/server/authority.js -> servers/gateway/dashboard/auth.js",
      "bundles/planted/server/hop.js -> ../../../servers/gateway/dashboard/local-session.js",
      "bundles/planted/server/relative.js -> ../../../servers/gateway/token-store.js",
      "bundles/planted/server/seam.js -> servers/gateway/token-store.js",
      "bundles/planted/server/via-gateway-hop.js -> ./auth.js",
    ].sort());
    const chains = gatewayAuthChains(botLoadableFiles({ root }), { root });
    // The visit is per file, so a sibling that only reaches an already-visited
    // offender is not reported twice — the offender itself is the finding.
    assert.equal(chains.some((v) => v.file === "bundles/planted/server/via-bundle-import.js"), false);
    // Scanned on its own, though, the `bundleImport("authority.js")` seam IS
    // followed into the bundle's own server/ dir and reported on the file that
    // started there — so the seam cannot hide a chain.
    const viaBundle = gatewayAuthChains([join(root, "bundles/planted/server/via-bundle-import.js")], { root });
    assert.deepEqual(viaBundle.map((v) => `${v.file} -> ${v.spec}`), [
      "bundles/planted/server/via-bundle-import.js -> servers/gateway/dashboard/auth.js",
    ]);
    assert.deepEqual(viaBundle[0].chain, [
      "bundles/planted/server/via-bundle-import.js",
      "bundles/planted/server/authority.js",
      "servers/gateway/dashboard/auth.js",
    ]);

    // panel/ files are never entries of the real scan, and the same import there is fine.
    assert.equal(gatewayAuthChains([join(root, "bundles/planted/panel/ok.js")], { root }).length, 1);
    assert.deepEqual(
      gatewayAuthChains(botLoadableFiles({ root }).filter((f) => /\/(clean|ok)\.js$/.test(f)), { root }),
      [],
      "a clean file and its clean sibling are not flagged",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});