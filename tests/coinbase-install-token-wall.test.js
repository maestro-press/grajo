/**
 * The Coinbase install token: where it lives, what the compose check says about the
 * mount that carries it to the engine, and what a walled MCP child can see of it.
 *
 * The token is the one secret the engine container reads for itself. It lives in
 * <CROW_HOME>/coinbase/install/install_token — a folder the compose check counts as this
 * bundle's own (<CROW_HOME>/<id>), and one the add-on wall never binds into a walled
 * child, whose filesystem is an empty tmpfs plus this add-on's own folders.
 *
 * Everything here is a scratch dir under os.tmpdir(); nothing reads or writes ~/.crow, and
 * the token value never leaves the fixture file.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { closeSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";

import { checkComposeModel, expandComposeVars, loadComposeModel } from "../servers/gateway/compose-guard.js";
import { buildContainPlan } from "../scripts/pi-bots/pi_contain.mjs";
import { buildAddonPlan } from "../scripts/addon-sandbox/plan.mjs";
import { composePortsFrom, deriveProfile } from "../scripts/addon-sandbox/profile.mjs";
import { dockerSkip } from "./helpers/docker-available.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const BUNDLE_DIR = join(REPO, "bundles", "coinbase");
const MANIFEST = JSON.parse(readFileSync(join(BUNDLE_DIR, "manifest.json"), "utf8"));
const COMPOSE = readFileSync(join(BUNDLE_DIR, "docker-compose.yml"), "utf8");

const T = realpathSync(mkdtempSync(join(tmpdir(), "crow-coinbase-token-wall-")));
after(() => rmSync(T, { recursive: true, force: true }));

const mk = (...parts) => {
  const dir = join(...parts);
  mkdirSync(dir, { recursive: true });
  return dir;
};

// ---- the mount the compose file really declares -----------------------------------------------

/**
 * The one bind this bundle mounts at /run/secrets, as written: its host source (still
 * carrying the compose variable) and whether it is read-only. The source is split at the
 * `/run/secrets` marker, never at a colon: `${CROW_HOME:?…}` contains one.
 */
function installTokenMount() {
  const line = String(COMPOSE)
    .split(/\r?\n/)
    .find((l) => /^\s*-\s/.test(l) && /:\/run\/secrets(?::\w+)?\s*$/.test(l));
  assert.ok(line, "the compose still mounts a host source at /run/secrets");
  const spec = line.trim().replace(/^-\s*/, "");
  const at = spec.indexOf(":/run/secrets");
  assert.ok(at > 0, `the mount names a host source: ${spec}`);
  return { source: spec.slice(0, at), readOnly: spec.slice(at + 1).split(":").includes("ro") };
}

/** The model `docker compose up` builds for this one bind, in the long form Compose emits. */
function modelWithMount(source, { readOnly = true } = {}) {
  return {
    services: {
      "coinbase-engine": {
        image: "busybox",
        volumes: [{ type: "bind", source, target: "/run/secrets", ...(readOnly ? { read_only: true } : {}) }],
      },
    },
  };
}

// A host laid out as on a real install: HOME/.crow is CROW_HOME, the bundle runs from
// CROW_HOME/bundles/<id>, and the token's folder is under the Crow home where the hook puts it.
const HOST = realpathSync(mkdtempSync(join(T, "host-")));
const HOST_HOME = join(HOST, "home");
const CROW_HOME = join(HOST_HOME, ".crow");
mkdirSync(HOST_HOME, { recursive: true });
const BUNDLE_ON_HOST = mk(CROW_HOME, "bundles", "coinbase");
const TOKEN_DIR_ON_HOST = mk(CROW_HOME, "coinbase", "install");
writeFileSync(join(TOKEN_DIR_ON_HOST, "install_token"), "fixture-token-not-a-real-secret\n", { mode: 0o644 });

const CTX = { crowHome: CROW_HOME, dataDir: join(CROW_HOME, "data"), appRoot: REPO, home: HOST_HOME };
const CHECK = (model, bundleDir = BUNDLE_ON_HOST) =>
  checkComposeModel(model, { bundleDir, manifest: MANIFEST, consentVerified: true, ctx: CTX });

// ---- 1. the mount the hook fills passes the compose check --------------------------------------

test("test_install_token_mount_passes_compose_guard", async (t) => {
  const mount = installTokenMount();
  assert.equal(mount.readOnly, true, "the install token is mounted read-only");

  // The declared source is the folder under the Crow home the hook writes into.
  const resolved = expandComposeVars(mount.source, { CROW_HOME });
  assert.equal(resolved, join(CROW_HOME, "coinbase", "install"), `the mount source is the token's own folder: ${mount.source}`);

  // The same model check the first-party compose test runs, for this one bundle only.
  const r = CHECK(modelWithMount(resolved));
  assert.deepEqual(r, { valid: true }, `the install-token mount is refused: ${r.reason}`);

  // And the whole compose file, as Compose itself resolves it, when a daemon is here.
  const skip = dockerSkip();
  if (skip) {
    t.diagnostic(`the full compose model was not read (${skip}); the model check above still ran`);
    return;
  }
  const { cpSync } = await import("node:fs");
  const home = realpathSync(mkdtempSync(join(tmpdir(), "crow-coinbase-compose-home-")));
  try {
    const ch = join(home, ".crow");
    const dir = join(ch, "bundles", "coinbase");
    cpSync(BUNDLE_DIR, dir, { recursive: true, filter: (f) => !f.includes("node_modules") });
    mkdirSync(join(ch, "coinbase", "install"), { recursive: true });
    const env = { PATH: process.env.PATH, HOME: home, CROW_HOME: ch };
    const runConfig = (args, { cwd, env: e }) =>
      new Promise((resolve, reject) =>
        execFile("docker", ["compose", ...args], { cwd, env: e }, (err, stdout, stderr) =>
          err ? reject(Object.assign(err, { stderr })) : resolve({ stdout }),
        ),
      );
    const loaded = await loadComposeModel(dir, { env, runConfig });
    assert.equal(loaded.error, undefined, `compose could not read the bundle: ${loaded.error}`);
    const full = checkComposeModel(loaded.model, {
      bundleDir: dir,
      manifest: MANIFEST,
      consentVerified: true,
      ctx: { crowHome: ch, dataDir: join(ch, "data"), appRoot: REPO, home },
    });
    assert.deepEqual(full, { valid: true }, `the real compose model is refused: ${full.reason}`);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// ---- 2. the check still refuses what the token must NOT be mounted from ------------------------

test("test_compose_guard_still_refuses_secrets_dir", () => {
  // The two older shapes of this mount: the token's folder under the Crow home's secrets
  // dir, and that secrets dir itself. Neither is this bundle's own folder.
  for (const source of [join(CROW_HOME, "secrets", "coinbase-install"), join(CROW_HOME, "secrets")]) {
    const r = CHECK(modelWithMount(source));
    assert.equal(r.valid, false, `${source} is refused`);
    assert.match(r.reason, /not this bundle's own/, `the refusal names the reason: ${r.reason}`);
  }

  // The own folder is the one the guard lets the bundle have, read-write as well as
  // read-only: <CROW_HOME>/<id> is where a bundle keeps its own data.
  const readOnly = CHECK(modelWithMount(TOKEN_DIR_ON_HOST, { readOnly: true }));
  assert.deepEqual(readOnly, { valid: true }, `the own folder, read-only: ${readOnly.reason}`);
  const readWrite = CHECK(modelWithMount(TOKEN_DIR_ON_HOST, { readOnly: false }));
  assert.deepEqual(readWrite, { valid: true }, `the own folder, read-write: ${readWrite.reason}`);

  // And a sibling name under the Crow home is not the own folder.
  const sibling = CHECK(modelWithMount(join(CROW_HOME, "coinbase-install")));
  assert.equal(sibling.valid, false, "a name that is not <CROW_HOME>/coinbase is refused");
  assert.match(sibling.reason, /not this bundle's own/, sibling.reason);
});

// ---- 3. a walled child never gets a bind of the token ------------------------------------------

/** One flag's arity, so the argv can be split into mount ops. */
const ARITY = {
  "--ro-bind": 2, "--bind": 2, "--bind-fd": 2, "--ro-bind-fd": 2, "--ro-bind-data": 2,
  "--symlink": 2, "--tmpfs": 1, "--proc": 1, "--dev": 1, "--chdir": 1, "--perms": 1, "--cap-drop": 1,
};
function pairs(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const n = ARITY[args[i]] ?? 0;
    if (n) { out.push([args[i], ...args.slice(i + 1, i + 1 + n)]); i += n; } else out.push([args[i]]);
  }
  return out;
}
const BIND_FLAGS = new Set(["--bind", "--ro-bind", "--bind-fd", "--ro-bind-fd"]);
const isUnder = (p, root) => p === root || p.startsWith(root.endsWith(sep) ? root : root + sep);

const UID = typeof process.getuid === "function" ? process.getuid() : 0;

test("test_install_token_hidden_from_walled_child", () => {
  // A scratch install: the owner's home, the Crow home with the installed bundle and the
  // token the hook published, and the instance's data folder with this add-on's own folder.
  const home = mk(T, "wall", "home", "alex");
  const crowHome = realpathSync(mk(T, "wall", "crow"));
  const dataDir = mk(crowHome, "data");
  const installDir = mk(crowHome, "bundles", "coinbase", "server");
  writeFileSync(join(installDir, "index.js"), "");
  const installed = dirname(installDir);
  const tokenDir = mk(crowHome, "coinbase", "install");
  const tokenPath = join(tokenDir, "install_token");
  writeFileSync(tokenPath, "fixture-token-not-a-real-secret\n", { mode: 0o644 });
  const dataOwn = mk(dataDir, "coinbase");
  const appRoot = realpathSync(mk(T, "wall", "app"));
  writeFileSync(join(appRoot, "package.json"), "{}");

  // The policy is the repo copy's, exactly as the wall derives it for a first-party bundle.
  const profile = deriveProfile(MANIFEST, {}, {
    composePorts: composePortsFrom(COMPOSE, MANIFEST),
    source: "repo",
    crowDbScan: false,
    gatewayPort: 3001,
  });
  assert.deepEqual(profile.refused, [], JSON.stringify(profile.refused));

  const plan = buildAddonPlan({
    id: "coinbase",
    profile,
    entry: { command: process.execPath, args: ["server/index.js"] },
    home,
    crowHome,
    appRoot,
    nodeBin: process.execPath,
    dataDir,
    dbPath: join(dataDir, "crow.db"),
    gatewayPort: 3001,
    installDir: installed,
    pathEnv: "",
    uid: UID,
  });

  try {
    assert.deepEqual(plan.refused, [], JSON.stringify(plan.refused));

    const ops = pairs(plan.args);
    // An empty root and an empty owner's home: nothing of the host is there unless bound.
    assert.ok(ops.some((q) => q[0] === "--tmpfs" && q[1] === "/"), "the sandbox root is a tmpfs");
    assert.ok(ops.some((q) => q[0] === "--tmpfs" && q[1] === home), "the owner's home is a tmpfs");

    const binds = ops.filter((q) => BIND_FLAGS.has(q[0]));
    const crowReal = realpathSync(crowHome);
    const installReal = realpathSync(installed);
    const dataReal = realpathSync(dataOwn);

    // No bind names the token, its folder, the folder above it, or the Crow home's secrets.
    const forbidden = [
      join(crowReal, "coinbase", "install", "install_token"),
      join(crowReal, "coinbase", "install"),
      join(crowReal, "coinbase"),
      join(crowReal, "secrets"),
    ];
    for (const op of binds) {
      for (const arg of op.slice(1)) {
        for (const p of forbidden) {
          assert.equal(isUnder(arg, p), false, `no bind may name the install token or its folder (${op[0]})`);
        }
      }
    }
    assert.equal(plan.args.includes(tokenPath), false, "the token file is not named anywhere in the argv");

    // The only binds under the Crow home are this add-on's own two folders.
    const underCrow = [...new Set(binds.flatMap((op) => op.slice(1).filter((a) => isUnder(a, crowReal))))].sort();
    assert.deepEqual(underCrow, [dataReal, installReal].sort(),
      `the binds under the Crow home are the install folder and the add-on's data folder: ${underCrow.join(", ")}`);
    assert.ok(
      ops.some((q) => q[0] === "--ro-bind" && q[1] === installReal && q[2] === installReal),
      "the installed bundle is bound read-only",
    );
    assert.ok(
      ops.some((q) => q[0] === "--bind-fd" && q[2] === dataReal),
      "the add-on's own data folder is bound by fd",
    );
  } finally {
    for (const f of plan.fds) {
      try { closeSync(f.fd); } catch { /* already closed */ }
    }
  }
});

// ---- 4. the token's own folder is never a bind source, for a bot or for an add-on ---------------

/**
 * A scratch install whose Crow home is NOT a dot folder: no hidden-home rule applies to it, so a
 * refusal below can only come from the token folder's own rule. `<CROW_HOME>/coinbase/state` is an
 * ordinary data sibling of the token folder.
 */
const TB = realpathSync(mk(T, "tokenbind"));
const TB_HOME = realpathSync(mk(TB, "home", "alex"));
const TB_CROW = realpathSync(mk(TB, "crowhome"));
const TB_DATA = realpathSync(mk(TB_CROW, "data"));
const TB_TOKEN_DIR = realpathSync(mk(TB_CROW, "coinbase", "install"));
const TB_TOKEN = join(TB_TOKEN_DIR, "install_token");
writeFileSync(TB_TOKEN, "fixture-token-not-a-real-secret\n", { mode: 0o644 });
const TB_TOKEN_SUB = realpathSync(mk(TB_TOKEN_DIR, "old"));
writeFileSync(join(TB_TOKEN_SUB, "install_token"), "fixture-token-not-a-real-secret\n", { mode: 0o644 });
const TB_SIBLING = realpathSync(mk(TB_CROW, "coinbase", "state"));
writeFileSync(join(TB_SIBLING, "book.json"), "{}");

/** A bot plan over that home, asking for the given binds. */
function tokenBotPlan({ readPaths = [], writePaths = [] } = {}) {
  const session = realpathSync(mk(TB, "session"));
  return buildContainPlan({
    home: TB_HOME,
    crowHome: TB_CROW,
    dataDir: TB_DATA,
    botCacheDir: realpathSync(mk(TB, "bot-cache")),
    sessionDir: session,
    cwd: session,
    readPaths,
    writePaths,
    mcpServers: [],
  });
}

test("test_bot_bind_of_install_folder_refused", () => {
  // A request for the token's folder, the token file and a child folder of it — read-only and
  // writable — and one request for a data sibling that must stay bindable.
  const asked = [TB_TOKEN_DIR, TB_TOKEN, TB_TOKEN_SUB];
  const plan = tokenBotPlan({
    readPaths: [...asked, TB_SIBLING],
    writePaths: [TB_TOKEN_DIR],
  });

  const binds = pairs(plan.args).filter((q) => BIND_FLAGS.has(q[0]));
  for (const p of asked) {
    const hit = plan.refused.find((r) => r.path === p);
    assert.ok(hit, `${p} is refused by the bind policy: ${JSON.stringify(plan.refused)}`);
    assert.match(hit.reason, /a protected path/, `${p} is refused as a protected path: ${hit.reason}`);
    assert.equal(plan.args.includes(p), false, `${p} is never named in the argv`);
    for (const op of binds) {
      for (const arg of op.slice(1)) {
        assert.equal(isUnder(arg, p), false, `no bind may name ${p} or anything in it (${op[0]})`);
      }
    }
  }

  // The rule is the token's own folder, not `<CROW_HOME>/coinbase`: a data sibling is still bound.
  assert.ok(
    binds.some((q) => q[0] === "--ro-bind" && q[1] === TB_SIBLING && q[2] === TB_SIBLING),
    "a data sibling of the token folder is still a bind source",
  );
  assert.equal(plan.refused.some((r) => r.path === TB_SIBLING), false, JSON.stringify(plan.refused));
  assert.equal(pairs(plan.args).some((q) => q[0] !== "--tmpfs" && q[1] === join(TB_CROW, "coinbase")), false,
    "the coinbase folder itself is not bound either");
});

test("test_addon_bind_of_install_folder_refused", () => {
  const installDir = realpathSync(mk(TB_CROW, "bundles", "coinbase"));
  mk(installDir, "server");
  writeFileSync(join(installDir, "server", "index.js"), "");
  const appRoot = realpathSync(mk(TB, "app"));
  writeFileSync(join(appRoot, "package.json"), "{}");
  mk(TB_DATA, "coinbase");

  // An owner-set grant of the token's folder — read and write, the folder and the file in it.
  const profile = {
    id: "coinbase",
    source: "repo",
    network: { internet: true, hosts: [] },
    doors: [],
    files: {
      read: [{ path: TB_TOKEN_DIR, source: "owner" }, { path: TB_TOKEN, source: "owner" }],
      write: [{ path: TB_TOKEN_DIR, source: "owner" }],
      oauthDir: null,
      state: [],
    },
    crowDb: false,
    ownEnvFile: false,
    refused: [],
  };

  const plan = buildAddonPlan({
    id: "coinbase",
    profile,
    entry: { command: process.execPath, args: ["server/index.js"] },
    home: TB_HOME,
    crowHome: TB_CROW,
    appRoot,
    dataDir: TB_DATA,
    dbPath: join(TB_DATA, "crow.db"),
    gatewayPort: 3001,
    installDir,
    pathEnv: "",
    uid: UID,
  });

  try {
    for (const p of [TB_TOKEN_DIR, TB_TOKEN]) {
      const hit = plan.refused.find((r) => r.path === p);
      assert.ok(hit, `the bind request for ${p} is refused: ${JSON.stringify(plan.refused)}`);
      assert.match(hit.reason, /coinbase\/install/, `the refusal names the token's folder, not the Crow home in general: ${hit.reason}`);
    }

    for (const op of pairs(plan.args)) {
      for (const arg of op.slice(1)) {
        if (typeof arg !== "string") continue;
        assert.equal(isUnder(arg, TB_TOKEN_DIR), false, `the argv never names the token's folder or anything in it (${op[0]})`);
      }
    }
    assert.equal(plan.args.includes(TB_TOKEN_DIR), false, "the folder is not an argument of its own");
    assert.equal(plan.args.includes(TB_TOKEN), false, "the token file is not an argument of its own");

    // The rest of the plan still binds what it always did.
    assert.ok(
      pairs(plan.args).some((q) => q[0] === "--ro-bind" && q[1] === installDir && q[2] === installDir),
      "the add-on's own install folder is still bound read-only",
    );
  } finally {
    for (const f of plan.fds) {
      if (f.role === "door-token") continue;
      try { closeSync(f.fd); } catch { /* already closed */ }
    }
  }
});