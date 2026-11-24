/**
 * Finance Hub P2 — the Coinbase bundle's beta manifest, its install-token hook and its compose
 * mounts. Reads the committed bundle files only; every hook run happens in a scratch CROW_HOME
 * under os.tmpdir() (never ~/.crow).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateManifest } from "../scripts/lib/bundle-contract.mjs";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const BUNDLE_DIR = join(REPO, "bundles", "coinbase");
const MANIFEST = JSON.parse(readFileSync(join(BUNDLE_DIR, "manifest.json"), "utf8"));
const COMPOSE = readFileSync(join(BUNDLE_DIR, "docker-compose.yml"), "utf8");
const HOOK = join(BUNDLE_DIR, "ops", "install-token.sh");
const SCRATCH = mkdtempSync(join(tmpdir(), "crow-coinbase-p2-"));

after(() => {
  rmScratch(SCRATCH);
});

const envVar = (name) => (MANIFEST.env_vars || []).find((v) => v && v.name === name);
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;

/** Every name a compose environment anchor declares, in file order. */
function anchorNames(text, anchor) {
  const lines = String(text).split("\n");
  const start = lines.findIndex((l) => l.trim().startsWith(`${anchor}:`));
  assert.ok(start >= 0, `compose has the ${anchor} anchor`);
  const names = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (!/^\s/.test(lines[i])) break; // the next top-level key ends the anchor
    const m = /^\s+([A-Za-z_][A-Za-z0-9_]*):/.exec(lines[i]);
    if (m) names.push(m[1]);
  }
  return names;
}

// ---- the manifest -----------------------------------------------------------------------------

test("test_manifest_valid_panel_beta", () => {
  const r = validateManifest(MANIFEST, BUNDLE_DIR);
  assert.deepEqual(r.errors, [], `manifest errors: ${r.errors.join("; ")}`);
  assert.equal(r.ok, true, r.errors.join("; "));

  assert.equal(MANIFEST.version, "0.4.14", `version "${MANIFEST.version}" is 0.4.14`);
  assert.equal(MANIFEST.draft, false);
  assert.match(MANIFEST.name, /Beta/, `name "${MANIFEST.name}" says beta`);
  assert.match(MANIFEST.description, /beta/i, "the description says it is a beta");

  assert.deepEqual(MANIFEST.connect, {
    method: "panel",
    group: "paste",
    panel_route: "/dashboard/coinbase",
    panel_secrets: ["COINBASE_KEY_NAME", "COINBASE_PRIVATE_KEY", "COINBASE_APPROVE_SECRET"],
  });

  // The bundle now ships its own stdio MCP server. It reads its own `.env` (the engine
  // token lives there) and may reach the engine's host and nothing else.
  assert.deepEqual(
    MANIFEST.server,
    { command: "node", args: ["server/index.js"] },
    "the bundle declares its MCP server entry",
  );
  assert.equal(
    MANIFEST.server.envKeys,
    undefined,
    "the engine token is read from the bundle .env, never passed by envKeys",
  );
  assert.deepEqual(
    MANIFEST.sandbox,
    { ownEnvFile: true, network: { hosts: ["env:CROW_COINBASE_ENGINE_URL"] } },
    "the server reads its own .env and reaches only the engine's host",
  );
  const engineUrl = envVar("CROW_COINBASE_ENGINE_URL");
  assert.ok(engineUrl, "CROW_COINBASE_ENGINE_URL is declared");
  assert.equal(engineUrl.default, "http://127.0.0.1:3062", "the engine address defaults to loopback");
  assert.notEqual(engineUrl.secret, true, "the engine address is not a secret");
  assert.equal(engineUrl.generate, undefined, "the engine address is not generated");
  assert.equal(MANIFEST.panel, "panel/coinbase.js", "the Trading panel's page is declared");
  assert.equal(MANIFEST.panelRoutes, "panel/routes.js", "the Trading panel's routes are declared");

  // No exchange credential in the environment: the gateway pushes them at runtime.
  for (const gone of ["COINBASE_API_KEY", "COINBASE_API_SECRET"]) {
    assert.equal(envVar(gone), undefined, `${gone} is not an env var`);
  }

  const added = {
    CROW_COINBASE_PROJECT_ID: undefined,
    CROW_COINBASE_AI_ORDER_MODE: "approve",
    CROW_COINBASE_AI_PREVIEW_TTL_S: "900",
    CROW_COINBASE_TRAIL_ALERT_DAYS: "7",
    CROW_COINBASE_AI_CAPITAL_USD: "25",
  };
  for (const [name, def] of Object.entries(added)) {
    const ev = envVar(name);
    assert.ok(ev, `${name} is declared`);
    assert.equal(ev.default, def, `${name} default`);
    assert.equal(ev.required, false, `${name} is not required`);
    assert.notEqual(ev.secret, true, `${name} is not a secret`);
  }

  const caps = {
    CROW_COINBASE_DAILY_NOTIONAL_USD: "200",
    CROW_COINBASE_ORDERS_PER_HOUR: "30",
    CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT: "20",
    CROW_COINBASE_BOT_MAX_ORDER_USD: "50",
    CROW_COINBASE_MAX_BOT_CAPITAL_USD: "100",
    CROW_COINBASE_AI_MAX_ORDER_USD: "25",
    CROW_COINBASE_AI_DAILY_NOTIONAL_USD: "50",
    CROW_COINBASE_AI_ORDERS_PER_HOUR: "10",
    CROW_COINBASE_AI_CAPITAL_USD: "25",
  };
  for (const [name, def] of Object.entries(caps)) {
    const ev = envVar(name);
    assert.ok(ev, `${name} is declared`);
    assert.equal(ev.default, def, `${name} keeps its default`);
    assert.match(ev.description, /^Ceiling for /, `${name} leads with "Ceiling for"`);
    assert.match(ev.description, /can lower it but never raise it\.$/, `${name} says the panel can only lower it`);
  }

  for (const ev of MANIFEST.env_vars || []) {
    const text = `${ev.name} ${ev.description || ""}`;
    assert.doesNotMatch(text, /install[_ ]?token/i, `${ev.name} mentions no install token`);
  }
});

test("test_manifest_declares_trading_panel", () => {
  assert.equal(MANIFEST.version, "0.4.14", "the manifest version is 0.4.14");
  assert.equal(MANIFEST.panel, "panel/coinbase.js", "the panel key names the Trading panel's page");
  assert.equal(MANIFEST.panelRoutes, "panel/routes.js", "the panelRoutes key names the Trading panel's routes");

  for (const rel of [MANIFEST.panel, MANIFEST.panelRoutes]) {
    assert.ok(existsSync(join(BUNDLE_DIR, rel)), `${rel} exists under the bundle`);
    assert.ok(statSync(join(BUNDLE_DIR, rel)).isFile(), `${rel} is a file`);
  }
});

test("test_compose_and_manifest_ceiling_default", () => {
  // The live ceiling is on by default; a host sets it false to forbid live here.
  const liveLines = COMPOSE.split("\n").filter((line) => /CROW_COINBASE_LIVE:/.test(line));
  assert.equal(liveLines.length, 2, `both anchors declare the ceiling (found ${liveLines.length})`);
  for (const line of liveLines) {
    assert.match(line, /\$\{CROW_COINBASE_LIVE:-true\}/, `the ceiling defaults on: ${line.trim()}`);
    assert.doesNotMatch(line, /:-false/, `the ceiling is not defaulted off: ${line.trim()}`);
  }

  const live = envVar("CROW_COINBASE_LIVE");
  assert.ok(live, "CROW_COINBASE_LIVE is declared");
  assert.equal(live.default, "true", "the ceiling defaults on");
  assert.equal(live.advanced, true, "the ceiling is an advanced setting");
  assert.equal(live.required, false, "the ceiling is not required");
  assert.notEqual(live.secret, true, "the ceiling is not a secret");
  assert.equal(
    live.description,
    "Safety ceiling. Set to false to forbid live trading on this computer no matter what the Trading page says.",
  );

  // The header describes both books instead of calling the bundle dry-run only.
  const lines = COMPOSE.split("\n");
  const anchor = lines.findIndex((line) => line.startsWith("x-coinbase-env:"));
  assert.ok(anchor > 0, "the engine anchor is there");
  const header = lines.slice(0, anchor).join("\n");
  assert.doesNotMatch(header, /dry-run only/i, "the header no longer says dry-run only");
  assert.match(header, /dry book/i, "the header names the dry book");
  assert.match(header, /live book/i, "the header names the live book");
  assert.match(header, /ceiling/i, "the header names the ceiling");
});

test("test_install_token_never_an_env_var", () => {
  for (const ev of MANIFEST.env_vars || []) {
    assert.doesNotMatch(JSON.stringify(ev), /install[_ ]?token/i, `${ev.name} carries no install token`);
  }

  // The engine anchor may name the engine's own API token and nothing else TOKEN-ish.
  for (const anchor of ["x-coinbase-env", "x-coinbase-watchdog-env"]) {
    const names = anchorNames(COMPOSE, anchor);
    assert.ok(names.length > 0, `${anchor} declares env names`);
    for (const name of names) {
      if (!/TOKEN/.test(name)) continue;
      assert.equal(name, "CROW_COINBASE_ENGINE_TOKEN", `${anchor} names no token env var other than the engine token`);
    }
    for (const name of names) assert.doesNotMatch(name, /INSTALL/i, `${anchor} names no install-token env var`);
  }
  for (const gone of ["COINBASE_API_KEY", "COINBASE_API_SECRET", "COINBASE_PRIVATE_KEY", "COINBASE_APPROVE_SECRET"]) {
    assert.equal(COMPOSE.includes(gone), false, `the compose file carries no ${gone}`);
  }

  // The install token reaches the engine as a read-only file, and only the engine gets it.
  const MOUNT = "/coinbase/install:/run/secrets:ro";
  const occurrences = COMPOSE.split(MOUNT).length - 1;
  assert.equal(occurrences, 1, `the install mount appears exactly once (found ${occurrences})`);
  const [engineHalf, watchdogHalf = ""] = COMPOSE.split("coinbase-watchdog:");
  assert.ok(engineHalf.includes(MOUNT), "the install mount is on the coinbase-engine service");
  assert.equal(watchdogHalf.includes(MOUNT), false, "the watchdog has no install mount");
});

test("test_precreate_and_post_install_declared", () => {
  // The token's own folder under <CROW_HOME>/coinbase: the compose check counts <CROW_HOME>/<id>
  // as this bundle's own, and the add-on wall never binds it into a walled child.
  assert.deepEqual(MANIFEST.docker.precreate, ["coinbase/install"]);
  assert.equal(MANIFEST.docker.composefile, "docker-compose.yml", "the composefile is kept");

  assert.deepEqual(MANIFEST.postInstall, { script: "ops/install-token.sh", timeout_s: 60 });

  assert.ok(existsSync(HOOK), "the hook script ships in the bundle");
  const mode = statSync(HOOK).mode & 0o777;
  assert.equal(mode, 0o755, `the hook script is executable (mode ${mode.toString(8)})`);
});

// ---- the hook itself --------------------------------------------------------------------------

function runHook(env, cwd) {
  try {
    const stdout = execFileSync("bash", [HOOK], { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { status: 0, stdout };
  } catch (err) {
    return { status: err.status, stdout: String(err.stdout || ""), stderr: String(err.stderr || "") };
  }
}

test("test_install_hook_creates_token_once", () => {
  const home = join(SCRATCH, "hook-home");
  const dir = join(home, "coinbase", "install");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tokenFile = join(dir, "install_token");
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    CROW_HOME: home,
    CROW_BUNDLE_DIR: BUNDLE_DIR,
  };

  const first = runHook(env, SCRATCH);
  assert.equal(first.status, 0, `the hook succeeded: ${first.stdout}${first.stderr || ""}`);
  assert.ok(existsSync(tokenFile), "the install token file exists");

  const token = readFileSync(tokenFile, "utf8").trim();
  assert.match(token, TOKEN_SHAPE, "the token is 43 base64url characters");
  assert.equal((statSync(tokenFile).mode & 0o777), 0o644, "the token file is 0644");
  assert.equal((statSync(dir).mode & 0o777), 0o755, "the token directory is 0755");

  const output = `${first.stdout}${first.stderr || ""}`;
  assert.equal(output.includes(token), false, "the hook never prints the token");
  const tokenLike = output.match(/[A-Za-z0-9_-]{43}/g) || [];
  assert.deepEqual(tokenLike, [], `no token-shaped string in the hook output: ${tokenLike.join(", ")}`);

  // A second run leaves the existing token alone.
  const second = runHook(env, SCRATCH);
  assert.equal(second.status, 0, `the second run succeeded: ${second.stdout}${second.stderr || ""}`);
  assert.equal(readFileSync(tokenFile, "utf8").trim(), token, "the token is never rotated");
  assert.equal(second.stdout.trim(), "Install token already present.");

  // A bad CROW_HOME is refused before anything is written.
  const unset = runHook({ PATH: process.env.PATH, HOME: process.env.HOME, CROW_BUNDLE_DIR: BUNDLE_DIR }, SCRATCH);
  assert.equal(unset.status, 1, "an unset CROW_HOME exits 1");
  assert.equal(existsSync(join(SCRATCH, "coinbase")), false, "an unset CROW_HOME writes nothing");

  const relative = runHook(
    { PATH: process.env.PATH, HOME: process.env.HOME, CROW_HOME: "relative-home", CROW_BUNDLE_DIR: BUNDLE_DIR },
    SCRATCH,
  );
  assert.equal(relative.status, 1, "a relative CROW_HOME exits 1");
  assert.equal(existsSync(join(SCRATCH, "relative-home")), false, "a relative CROW_HOME writes nothing");
});

// ---- what the hook protects, and how it publishes ---------------------------------------------

const hookEnv = (home) => ({
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  CROW_HOME: home,
  CROW_BUNDLE_DIR: BUNDLE_DIR,
});

const modeOf = (path) => statSync(path).mode & 0o777;
const octal = (mode) => `0${mode.toString(8)}`;

// The hook is run under a permissive umask, so whatever mode the script itself leaves behind is
// the script's own doing and not an inheritance from this test process.
const PERMISSIVE_UMASK = 'umask 022; exec bash "$0"';

function runHookPermissiveUmask(env, cwd) {
  try {
    const stdout = execFileSync("bash", ["-c", PERMISSIVE_UMASK, HOOK], {
      cwd,
      env,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout, stderr: "" };
  } catch (err) {
    return { status: err.status, stdout: String(err.stdout || ""), stderr: String(err.stderr || "") };
  }
}

function spawnHookPermissiveUmask(env, cwd) {
  return new Promise((resolve) => {
    const child = spawn("bash", ["-c", PERMISSIVE_UMASK, HOOK], {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("error", (err) => resolve({ status: null, stdout, stderr: `${stderr}${err.message}` }));
    child.on("close", (code) => resolve({ status: code, stdout, stderr }));
  });
}

test("test_install_hook_token_parent_is_private", () => {
  // The token's own folder (<CROW_HOME>/coinbase) is the protected parent now: it is the
  // folder the compose check calls this bundle's own, and the only one the wall must keep
  // out of a walled child's reach.

  // Case 1: a CROW_HOME with no coinbase directory at all — this run creates it.
  const home = join(SCRATCH, "private-home");
  mkdirSync(home);
  const parent = join(home, "coinbase");
  const dir = join(parent, "install");
  const tokenFile = join(dir, "install_token");

  const first = runHookPermissiveUmask(hookEnv(home), SCRATCH);
  assert.equal(first.status, 0, `the hook succeeded: ${first.stdout}${first.stderr}`);
  assert.ok(existsSync(tokenFile), "the install token file exists");
  assert.equal(
    modeOf(parent),
    0o700,
    `a parent directory this run created is 0700, not ${octal(modeOf(parent))}`,
  );
  assert.equal(modeOf(dir), 0o755, `the token directory is 0755, not ${octal(modeOf(dir))}`);
  assert.equal(modeOf(tokenFile), 0o644, `the token file is 0644, not ${octal(modeOf(tokenFile))}`);
  assert.match(readFileSync(tokenFile, "utf8").trim(), TOKEN_SHAPE, "the token is 43 base64url characters");

  // Case 2: a parent directory that already exists does NOT keep its mode — a loose folder on
  // disk is narrowed on the next run.
  const existingHome = join(SCRATCH, "existing-home");
  const existingParent = join(existingHome, "coinbase");
  mkdirSync(existingParent, { recursive: true });
  chmodSync(existingParent, 0o755);

  const second = runHookPermissiveUmask(hookEnv(existingHome), SCRATCH);
  assert.equal(second.status, 0, `the hook succeeded: ${second.stdout}${second.stderr}`);
  assert.equal(
    modeOf(existingParent),
    0o700,
    `a pre-existing 0755 parent directory is made 0700, not ${octal(modeOf(existingParent))}`,
  );
  const existingDir = join(existingParent, "install");
  const existingToken = join(existingDir, "install_token");
  assert.equal(modeOf(existingDir), 0o755, `the token directory is 0755, not ${octal(modeOf(existingDir))}`);
  assert.equal(modeOf(existingToken), 0o644, `the token file is 0644, not ${octal(modeOf(existingToken))}`);
});

test("test_install_hook_parent_is_always_private", () => {
  // Whatever mode a <CROW_HOME>/coinbase folder already has, the run leaves it 0700: the 0755
  // token directory and the 0644 token file are only ever reachable through a private folder.
  for (const before of [0o750, 0o700]) {
    const home = join(SCRATCH, `always-home-${octal(before)}`);
    const parent = join(home, "coinbase");
    const dir = join(parent, "install");
    const tokenFile = join(dir, "install_token");
    mkdirSync(parent, { recursive: true });
    chmodSync(parent, before);
    writeFileSync(join(parent, "notes.txt"), "an operator's own file is left alone\n");

    const r = runHookPermissiveUmask(hookEnv(home), SCRATCH);
    assert.equal(r.status, 0, `the hook succeeded from ${octal(before)}: ${r.stdout}${r.stderr}`);
    assert.ok(existsSync(tokenFile), "the install token file exists");
    assert.equal(
      modeOf(parent),
      0o700,
      `the parent is 0700 after a run over ${octal(before)}, not ${octal(modeOf(parent))}`,
    );
    assert.equal(modeOf(dir), 0o755, `the token directory is 0755, not ${octal(modeOf(dir))}`);
    assert.equal(modeOf(tokenFile), 0o644, `the token file is 0644, not ${octal(modeOf(tokenFile))}`);
    assert.equal(readFileSync(join(parent, "notes.txt"), "utf8"), "an operator's own file is left alone\n");
  }
});

test("test_install_hook_tightens_parent_when_token_exists", () => {
  // A token is already on disk, so the run takes its "already present" path. The parent folder
  // still has to end up 0700, and nothing else in the tree may change.
  const home = join(SCRATCH, "existing-token-home");
  const parent = join(home, "coinbase");
  const dir = join(parent, "install");
  const tokenFile = join(dir, "install_token");
  const notesFile = join(parent, "notes.txt");
  const notesBody = "an operator's own file is left alone\n";
  const token = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
  assert.equal(token.length, 43, "the fixture token is 43 characters");
  assert.match(token, TOKEN_SHAPE, "the fixture token is base64url");
  const tokenBytes = `${token}\n`;

  mkdirSync(dir, { recursive: true });
  writeFileSync(tokenFile, tokenBytes, "utf8");
  writeFileSync(notesFile, notesBody, "utf8");
  chmodSync(dir, 0o755);
  chmodSync(tokenFile, 0o644);
  chmodSync(parent, 0o755);
  assert.equal(modeOf(parent), 0o755, "the fixture parent starts at 0755");

  const r = runHookPermissiveUmask(hookEnv(home), SCRATCH);
  assert.equal(r.status, 0, `the hook succeeded: ${r.stdout}${r.stderr}`);
  assert.equal(
    modeOf(parent),
    0o700,
    `the parent is 0700 after a run that found an existing token, not ${octal(modeOf(parent))}`,
  );
  assert.equal(readFileSync(tokenFile, "utf8"), tokenBytes, "the existing token is left byte for byte as it was");
  assert.equal(modeOf(dir), 0o755, `the token directory is 0755, not ${octal(modeOf(dir))}`);
  assert.equal(modeOf(tokenFile), 0o644, `the token file is 0644, not ${octal(modeOf(tokenFile))}`);
  const output = `${r.stdout}${r.stderr}`;
  assert.equal(output.includes(token), false, "the run never prints the token");
  assert.equal(readFileSync(notesFile, "utf8"), notesBody, "a sibling file in the parent is untouched");

  // A repeat run over the now-private parent leaves the mode where it is.
  const again = runHookPermissiveUmask(hookEnv(home), SCRATCH);
  assert.equal(again.status, 0, `the repeat run succeeded: ${again.stdout}${again.stderr}`);
  assert.equal(modeOf(parent), 0o700, `the parent stays 0700, not ${octal(modeOf(parent))}`);
  assert.equal(readFileSync(tokenFile, "utf8"), tokenBytes, "the repeat run leaves the token as it was");
});

test("test_install_hook_stops_when_the_parent_cannot_be_made_private", () => {
  // The parent mode is not best-effort: when it cannot be made 0700 (here a `chmod` that always
  // fails), no token is published and the run exits 1.
  const home = join(SCRATCH, "chmod-fail-home");
  const parent = join(home, "coinbase");
  mkdirSync(parent, { recursive: true });
  chmodSync(parent, 0o755); // pre-existing: only the unconditional chmod touches it

  const fakebin = join(SCRATCH, "chmod-fail-bin");
  mkdirSync(fakebin, { recursive: true });
  const failing = join(fakebin, "chmod");
  writeFileSync(failing, "#!/bin/sh\nexit 1\n", { mode: 0o755 });
  chmodSync(failing, 0o755);

  const env = { ...hookEnv(home), PATH: `${fakebin}:${process.env.PATH}` };
  const r = runHookPermissiveUmask(env, SCRATCH);

  assert.equal(r.status, 1, `the hook exits 1 when the parent cannot be made private: ${r.stdout}${r.stderr}`);
  assert.equal(existsSync(join(parent, "install", "install_token")), false, "no install token was published");
  const output = `${r.stdout}${r.stderr}`;
  const tokenLike = output.match(/[A-Za-z0-9_-]{43}/g) || [];
  assert.deepEqual(tokenLike, [], `no token-shaped string in the hook output: ${tokenLike.join(", ")}`);
});

test("test_install_hook_parallel_runs_one_stable_token", async () => {
  const home = join(SCRATCH, "parallel-home");
  mkdirSync(home);
  const env = hookEnv(home);
  const dir = join(home, "coinbase", "install");
  const tokenFile = join(dir, "install_token");

  const runs = await Promise.all(
    Array.from({ length: 8 }, () => spawnHookPermissiveUmask(env, SCRATCH)),
  );
  runs.forEach((r, i) => {
    assert.equal(r.status, 0, `copy ${i + 1} of 8 exited 0 (status ${r.status}): ${r.stdout}${r.stderr}`);
  });

  assert.ok(existsSync(tokenFile), "the install token file exists");
  const token = readFileSync(tokenFile, "utf8").trim();
  assert.match(token, TOKEN_SHAPE, "the token is 43 base64url characters");

  // Only one run may mint the token; a run that loses the race must report the token as already
  // there instead of replacing the one another run just published.
  const created = runs.filter((r) => r.stdout.includes("Install token created.")).length;
  assert.equal(created, 1, `exactly one of the 8 parallel runs minted the token (${created} claimed to)`);
  const already = runs.filter((r) => r.stdout.includes("Install token already present.")).length;
  assert.equal(created + already, 8, `all 8 runs reported a known outcome (${already} said already present)`);

  // A later run leaves the published token byte for byte as it was.
  const before = readFileSync(tokenFile, "utf8");
  const ninth = await spawnHookPermissiveUmask(env, SCRATCH);
  assert.equal(ninth.status, 0, `the ninth run exited 0 (status ${ninth.status}): ${ninth.stdout}${ninth.stderr}`);
  assert.equal(ninth.stdout.trim(), "Install token already present.");
  assert.equal(readFileSync(tokenFile, "utf8"), before, "a later run leaves the token byte-identical");

  const temps = readdirSync(dir).filter((name) => name.startsWith(".install_token."));
  assert.deepEqual(temps, [], `no temp files were left in the token directory: ${temps.join(", ")}`);

  for (const [i, r] of [...runs, ninth].entries()) {
    const output = `${r.stdout}${r.stderr}`;
    assert.equal(output.includes(token), false, `run ${i + 1} never printed the token`);
    const tokenLike = output.match(/[A-Za-z0-9_-]{43}/g) || [];
    assert.deepEqual(tokenLike, [], `run ${i + 1} printed no token-shaped string: ${tokenLike.join(", ")}`);
  }
});

test("test_install_hook_documents_mode_assumption", () => {
  const source = readFileSync(HOOK, "utf8");
  // The note may wrap over several comment lines: it says the 0755 directory and the 0644
  // file are only safe under a 0700 parent folder, and names that folder.
  const comments = source.split("\n").filter((l) => /^\s*#/.test(l)).join("\n");
  const MODE_NOTE = /0700[\s\S]{0,300}?(?:coinbase|secrets)|(?:coinbase|secrets)[\s\S]{0,300}?0700/;
  assert.match(
    comments,
    MODE_NOTE,
    "the hook explains, in a comment, that the 0755 directory and 0644 file are only safe under a 0700 parent",
  );
});

// ---- what the notes say a halt does ------------------------------------------------------------

test("test_notes_describe_a_book_halt_cancelling_its_own_orders", () => {
  const notes = String(MANIFEST.notes || "");

  // A book's own drawdown stop no longer leaves its orders resting on the exchange.
  assert.doesNotMatch(
    notes,
    /leaves? (?:its|the book's) resting orders where they are/i,
    `the notes no longer say a halted book keeps its resting orders: ${notes}`,
  );

  // The same sentence says those orders are cancelled.
  assert.match(
    notes,
    /drawdown[^.]*cancel/is,
    `the notes say a book's drawdown stop cancels that book's resting orders: ${notes}`,
  );
});

// ---- the registry (regenerated by the controller) ---------------------------------------------

// EXPECTED TO KEEP FAILING until the controller regenerates the registry: the committed
// registry is produced from the manifests, so it carries the panel connect only afterwards.
test("test_registry_carries_panel_connect", () => {
  const reg = JSON.parse(readFileSync(join(REPO, "registry", "add-ons.json"), "utf8"));
  const entry = (reg["add-ons"] || []).find((e) => e && e.id === "coinbase");
  assert.ok(entry, "the registry has a coinbase entry");
  assert.ok(entry.connect, "the coinbase entry carries a connect block");
  assert.equal(entry.connect.method, "panel");
  assert.equal(entry.connect.panel_route, "/dashboard/coinbase");
});