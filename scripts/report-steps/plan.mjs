/**
 * The file side of one report custom step: the bwrap argv and the env an approved step runs under,
 * and nothing else. It creates nothing: the caller makes the fresh bundle dir, the work dir and the
 * relay socket, and removes them afterwards.
 *
 * What a step can see is a closed list (spec C3, §5.5):
 *   /env        the report's per-language env (a venv or a node_modules tree), READ-ONLY
 *   /bundle     the step's own files, written fresh from the approved `files_json`, READ-ONLY
 *   /assets/<n> each asset the step binds, READ-ONLY, one file each
 *   /uv-cache   uv's cache, READ-ONLY (a step only resolves nothing: it runs installed code)
 *   /work       ONE fresh tmp dir, the only writable mount, which is the working directory
 * There is no `$HOME` data (the home path is an empty tmpfs from `rootArgs`), no crow.db, no workspace,
 * no Crow home and no relay dir other than the socket's own, which `rootArgs`'s `/run` tmpfs keeps
 * empty apart from the one read-only bind. `--unshare-net` gives the step a namespace with only `lo`;
 * the in-namespace entry (`pi_netns_entry.mjs`) makes one proxy port exist there and forwards it over
 * the bind-mounted relay socket to the spawner's egress relay, which is where the policy lives.
 *
 * The node the wall runs is a single FILE bind of its real path, never its install prefix: node needs
 * only the system libraries `/usr` already binds, and a prefix is a directory that can be an ancestor
 * of, or sit inside, a home (`nodeBinaryFor`).
 *
 * The env is an ALLOWLIST, built here and never spread from the caller's environment: a name that looks
 * like a credential (`SECRET_NAME_RE`) can never be in it, and no keychain path is in it. `PATH`,
 * `LANG` and `TMPDIR` are fixed; the proxy variables are set only for the shapes the relay really
 * serves (`HTTP_PROXY` for an inject host, `HTTPS_PROXY` for an approved plain host); `UV_CACHE_DIR`
 * and `NODE_PATH` name read-only mounts above; `PYTHONDONTWRITEBYTECODE=1` keeps the read-only bundle
 * read-only.
 *
 * A plan this module will not build is a `StepPlanRefused` with a `code`, never a weaker plan: an env,
 * bundle, work or asset mount that is not the thing it names keeps the step from running at all.
 */
import { existsSync, readdirSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { assembleBindArgs, rootArgs } from "../pi-bots/pi_contain.mjs";
import { ENTRY_MARK } from "../pi-bots/pi_netns_entry.mjs";

/** The in-namespace entry every step is started through (the relay's forwarder). */
export const STEP_NETNS_ENTRY = fileURLToPath(new URL("../pi-bots/" + ENTRY_MARK, import.meta.url));

/** Where each mount appears inside the step's root. */
export const STEP_MOUNTS = Object.freeze({
  env: "/env",
  bundle: "/bundle",
  assets: "/assets",
  work: "/work",
  uvCache: "/uv-cache",
});

/** The proxy port inside the step's own network namespace (only `lo` exists there). */
export const STEP_PROXY_PORT = 39080;

/** The interpreter and the PATH a step gets. Neither is read from the caller's environment. */
export const SYSTEM_PYTHON = "/usr/bin/python3";
export const STEP_PATH = "/usr/local/bin:/usr/bin:/bin";
export const STEP_LANG = "C.UTF-8";

/** A step key, a report id and an asset name as this module accepts them on their way into a path. */
const STEP_KEY_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const PATH_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const ASSET_NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;
/** A file path inside a bundle: POSIX, relative, no `..`, no leading `/`, no control character. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f\u0080-\u009f\u2028\u2029]/;
const FILE_PATH_MAX = 200;
/** The two runtimes a step may be written for. */
const LANGUAGES = Object.freeze(["python", "node"]);
/** The conventional roots of users' homes: a binary in one user's home is never another user's. */
const HOMES_ROOTS = Object.freeze(["/home", "/Users"]);
/** A co-hosted Crow instance's home: a `$HOME/.crow*` sibling of this instance's own. */
const INSTANCE_HOME_RE = /^\.crow(-|$)/;

/** A plan that was not built. `code` is a stable word a caller can act on. */
export class StepPlanRefused extends Error {
  constructor(code, detail = "") {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "StepPlanRefused";
    this.code = code;
    if (detail) this.detail = detail;
  }
}

const refuse = (code, detail) => {
  throw new StepPlanRefused(code, detail);
};

/** `p` is `root` or inside it: a SEGMENT-aware test, so `/usr/local` is neither `/usr` nor under it. */
const under = (p, root) => p === root || p.startsWith(root.endsWith(sep) ? root : root + sep);

/**
 * The `$HOME/.crow*` siblings of one user home, at their real paths, minus this instance's own home.
 * A sibling that no longer exists, or that is not a directory, is left out.
 */
function siblingInstanceHomes(userHome, realHome) {
  const out = [];
  let names = [];
  try { names = readdirSync(userHome); } catch { names = []; }
  for (const name of names) {
    if (!INSTANCE_HOME_RE.test(name)) continue;
    let real = null;
    try { real = realpathSync(join(userHome, name)); } catch { real = null; }
    if (!real || real === realHome || out.includes(real)) continue;
    out.push(real);
  }
  return out;
}

/**
 * The node binary a wall runs, as its real path, and whether the step's root already has it.
 *
 * A node install is never mounted as a DIRECTORY: only the binary itself is (at its own path). The
 * entry program and the step both run on that one file, and node needs nothing from its prefix that
 * the read-only `/usr` bind does not already provide.
 *
 * Refused (`bad_input`) is a binary that sits under, or above, a home a sandbox must never reach: the
 * Crow home, a `$HOME/.crow*` sibling of it, or another user's home. `withPrefix` also resolves the
 * install prefix and refuses one that is under or above any of those, for the warm-up, which really
 * does need its node install (npm lives in it) bound.
 *
 * @param {string} nodeBin
 * @param {{home?: string, withPrefix?: boolean}} [o]
 * @returns {{real: string, prefix: string|null, inSystemDirs: boolean}}
 * @throws {StepPlanRefused}
 */
export function nodeBinaryFor(nodeBin, { home = homedir(), withPrefix = false } = {}) {
  if (typeof nodeBin !== "string" || !isAbsolute(nodeBin)) refuse("bad_input", "nodeBin");
  let real = null;
  try {
    real = realpathSync(nodeBin);
    if (!statSync(real).isFile()) refuse("bad_input", "nodeBin");
  } catch (err) {
    if (err instanceof StepPlanRefused) throw err;
    refuse("bad_input", "nodeBin");
  }
  const resolvedHome = resolve(typeof home === "string" && home ? home : homedir());
  let realHome = null;
  try { realHome = realpathSync(resolvedHome); } catch { realHome = null; }
  const userHomes = [];
  const addUserHome = (p) => {
    if (typeof p === "string" && isAbsolute(p) && !userHomes.includes(p)) userHomes.push(p);
  };
  addUserHome(homedir());
  addUserHome(dirname(resolvedHome));
  if (realHome) addUserHome(dirname(realHome));
  // Everything that must never be inside a wall: this instance's home(s), and every co-hosted instance's.
  const closed = [resolvedHome];
  if (realHome && realHome !== resolvedHome) closed.push(realHome);
  for (const userHome of userHomes) for (const p of siblingInstanceHomes(userHome, realHome)) closed.push(p);

  const refusedIn = (p) => closed.some((x) => under(p, x) || under(x, p));
  if (refusedIn(real)) refuse("bad_input", "nodeBin");
  for (const userHome of userHomes) {
    const homesRoot = dirname(userHome);
    if (HOMES_ROOTS.includes(homesRoot) && under(real, homesRoot) && !under(real, userHome)) {
      refuse("bad_input", "nodeBin");
    }
  }

  let prefix = null;
  if (withPrefix) {
    try { prefix = realpathSync(dirname(dirname(real))); } catch { prefix = null; }
    if (!prefix) refuse("bad_input", "nodeBin");
    if (refusedIn(prefix)) refuse("bad_input", "nodeBin");
    for (const userHome of userHomes) {
      const homesRoot = dirname(userHome);
      if (HOMES_ROOTS.includes(homesRoot) && under(prefix, homesRoot) && !under(prefix, userHome)) {
        refuse("bad_input", "nodeBin");
      }
    }
  }
  return { real, prefix, inSystemDirs: under(real, "/usr") || under(real, "/opt") };
}

function idOf(value) {
  if (typeof value !== "string" || !PATH_ID_RE.test(value) || value === "." || value === "..") {
    refuse("bad_input", "reportId");
  }
  return value;
}

function keyOf(value) {
  if (typeof value !== "string" || !STEP_KEY_RE.test(value)) refuse("bad_input", "stepKey");
  return value;
}

/** A bundle file path, as `steps.js` writes one. */
function relativeFilePath(value) {
  if (typeof value !== "string" || !value || value.length > FILE_PATH_MAX) refuse("bad_input", "path");
  if (CONTROL_CHARS.test(value) || value.includes("\\") || value.startsWith("/") || value.endsWith("/")) {
    refuse("bad_input", "path");
  }
  for (const segment of value.split("/")) {
    if (!segment || segment === "." || segment === "..") refuse("bad_input", "path");
  }
  return value;
}

/** A directory that must exist, resolved to its real path. */
function realDir(value, label) {
  if (typeof value !== "string" || !isAbsolute(value)) refuse("bad_input", label);
  let real = null;
  try {
    real = realpathSync(value);
    if (!statSync(real).isDirectory()) refuse("bad_input", label);
  } catch (err) {
    if (err instanceof StepPlanRefused) throw err;
    refuse("bad_input", label);
  }
  return real;
}

/**
 * One asset file: a name with no path in it, and a file whose real path sits DIRECTLY in the report's
 * assets dir. A symlink out of that dir, a swapped file and a name that would escape `/assets` all keep
 * the plan from being built.
 */
function realAssetFile(bind, assetsDir) {
  if (!bind || typeof bind !== "object") refuse("bad_input", "asset");
  const name = bind.name;
  if (typeof name !== "string" || !ASSET_NAME_RE.test(name) || name === "." || name === "..") {
    refuse("bad_input", "asset name");
  }
  const declared = bind.path;
  if (typeof declared !== "string" || !isAbsolute(declared)) refuse("bad_input", "asset path");
  let real = null;
  try {
    real = realpathSync(declared);
    if (!statSync(real).isFile()) refuse("bad_input", "asset path");
  } catch (err) {
    if (err instanceof StepPlanRefused) throw err;
    refuse("bad_input", "asset path");
  }
  if (dirname(real) !== assetsDir) refuse("bad_input", "asset path");
  return { name, real };
}

/**
 * Build the plan for one custom step.
 *
 * `assetBinds` is `[{name, path}]`, the files the approved step binds (its `assets` rows, verified on
 * disk by the caller). `relaySock` is the socket path inside the relay dir the plan binds read-only at
 * `/run/crow-net`.
 *
 * `runtimeArgs` are arguments for the interpreter itself (the Node heap cap). `commandPrefix` runs
 * before the interpreter and is the address-space cap: `prlimit` takes BYTES (`--as=1048576` is one
 * mebibyte), with no unit suffix.
 *
 * @param {object} o
 *   reportId, stepKey, language, entry, envDir, bundleDir, assetsDir, assetBinds, relaySock,
 *   proxyPort, workDir, nodeBin, uvCacheDir, seccompFd, runtimeArgs, commandPrefix, injectHosts,
 *   connectHosts, home, exists
 * @returns {{args: string[], env: object}}
 * @throws {StepPlanRefused}
 */
export function buildStepPlan(o = {}) {
  const exists = typeof o.exists === "function" ? o.exists : existsSync;
  const reportId = idOf(o.reportId);
  const stepKey = keyOf(o.stepKey);
  const language = o.language;
  if (!LANGUAGES.includes(language)) refuse("bad_input", "language");
  const entry = relativeFilePath(o.entry);
  const home = resolve(typeof o.home === "string" && o.home ? o.home : homedir());
  const envDir = realDir(o.envDir, "envDir");
  const bundleDir = realDir(o.bundleDir, "bundleDir");
  const workDir = realDir(o.workDir, "workDir");
  const assetsDir = realDir(o.assetsDir, "assetsDir");

  // The env dir is the report's own, below `<home>/reports/<id>/env/`. Nothing above it is a mount
  // source: an env dir that is the Crow home (or an ancestor of it) would put the instance's tokens
  // and secrets inside the step.
  let realHome = null;
  try { realHome = realpathSync(home); } catch { realHome = null; }
  if (realHome && (under(realHome, envDir) || envDir === realHome)) refuse("bad_input", "envDir");
  const envRoots = [join(home, "reports", reportId, "env")];
  if (realHome) envRoots.push(join(realHome, "reports", reportId, "env"));
  if (!envRoots.some((root) => under(envDir, root))) refuse("bad_input", "envDir");
  // The bundle and the work dir are this run's own tmp dirs, never inside the Crow home.
  for (const [dir, label] of [[bundleDir, "bundleDir"], [workDir, "workDir"]]) {
    if (realHome && under(dir, realHome)) refuse("bad_input", label);
    if (under(dir, join(home, "reports"))) refuse("bad_input", label);
  }
  if (bundleDir === workDir) refuse("bad_input", "workDir");

  const binds = Array.isArray(o.assetBinds) ? o.assetBinds : [];
  const assets = [];
  const seen = new Set();
  for (const bind of binds) {
    const asset = realAssetFile(bind, assetsDir);
    if (seen.has(asset.name)) refuse("bad_input", "asset name");
    seen.add(asset.name);
    assets.push(asset);
  }

  if (typeof o.relaySock !== "string" || !isAbsolute(o.relaySock)) refuse("bad_input", "relaySock");
  const relaySock = o.relaySock;
  const proxyPort = Number.isInteger(o.proxyPort) && o.proxyPort > 0 && o.proxyPort < 65536 ? o.proxyPort : STEP_PROXY_PORT;
  const seccompFd = Number.isInteger(o.seccompFd) && o.seccompFd >= 3 ? o.seccompFd : null;
  const uvCacheDir = o.uvCacheDir ? realDir(o.uvCacheDir, "uvCacheDir") : null;
  const nodeBin = typeof o.nodeBin === "string" && o.nodeBin ? o.nodeBin : process.execPath;
  // The node every wall in this plan runs on, as the one file it is: its install prefix is never a
  // mount source and a binary that lives in a home a step must not see is refused.
  const node = nodeBinaryFor(nodeBin, { home });

  /** The interpreter and its own arguments, never a shell. */
  let command;
  let commandArgs;
  if (language === "python") {
    command = STEP_MOUNTS.env + "/bin/python";
    commandArgs = [STEP_MOUNTS.bundle + "/" + entry];
  } else {
    command = node.real;
    commandArgs = [STEP_MOUNTS.bundle + "/" + entry];
  }
  const runtimeArgs = Array.isArray(o.runtimeArgs) ? o.runtimeArgs : [];
  for (const arg of runtimeArgs) {
    if (typeof arg !== "string" || CONTROL_CHARS.test(arg)) refuse("bad_input", "runtimeArgs");
  }
  if (language === "python" && runtimeArgs.length) refuse("bad_input", "runtimeArgs");
  // A command prefix runs BEFORE the interpreter, inside the wall: `prlimit --as=<bytes> --` puts the
  // address-space cap on the step itself (the Node that runs the entry needs far more address space
  // than a step's cap, so the cap can never be applied to the wall's own processes). The number is a
  // byte count: util-linux `prlimit` has no unit suffix.
  const commandPrefix = Array.isArray(o.commandPrefix) ? o.commandPrefix : [];
  for (const arg of commandPrefix) {
    if (typeof arg !== "string" || !arg || CONTROL_CHARS.test(arg)) refuse("bad_input", "commandPrefix");
  }

  // ---- root and mounts ----
  const args = rootArgs({ exists, home });

  const extraEntries = [];
  extraEntries.push(["--ro-bind", envDir, STEP_MOUNTS.env]);
  extraEntries.push(["--ro-bind", bundleDir, STEP_MOUNTS.bundle]);
  for (const asset of assets) extraEntries.push(["--ro-bind", asset.real, STEP_MOUNTS.assets + "/" + asset.name]);
  if (uvCacheDir) extraEntries.push(["--ro-bind", uvCacheDir, STEP_MOUNTS.uvCache]);
  extraEntries.push(["--bind", workDir, STEP_MOUNTS.work]);

  // The engine: the in-namespace entry is a node program, so the node BINARY is bound read-only at its
  // own real path and nothing else of its install is. A prefix is a directory, and one can be an
  // ancestor of, or sit inside, a home (`nodeBinaryFor` refuses those); the binary itself needs only
  // the system libraries the root's read-only /usr already has.
  if (!node.inSystemDirs) extraEntries.push(["--ro-bind", node.real, node.real]);

  // The in-namespace entry is a single self-contained node program from this checkout, and the step's
  // root has none of the checkout: it is bound read-only at its own path, and nothing around it is.
  let entryReal = null;
  try { entryReal = realpathSync(STEP_NETNS_ENTRY); } catch { entryReal = null; }
  if (!entryReal) refuse("bad_input", "entry program");
  extraEntries.push(["--ro-bind", entryReal, STEP_NETNS_ENTRY]);

  // The relay socket dir, read-only at its fixed path: the plan's `/run` is a fresh tmpfs, so this is
  // the only thing in it.
  let realRelayDir = null;
  try { realRelayDir = realpathSync(dirname(relaySock)); } catch { realRelayDir = null; }
  if (!realRelayDir || under(relaySock, home)) refuse("bad_input", "relaySock");
  extraEntries.push(["--ro-bind", realRelayDir, "/run/crow-net"]);

  args.push(...assembleBindArgs({ ro: new Map(), rw: new Map(), masks: [], extraEntries }));
  args.push(
    "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
    "--unshare-net", "--cap-drop", "ALL", "--die-with-parent", "--new-session",
    "--chdir", STEP_MOUNTS.work,
  );
  if (seccompFd !== null) args.push("--seccomp", String(seccompFd));

  // ---- the command: the entry that makes the proxy port exist, then the step ----
  const sockInside = "/run/crow-net/" + basename(relaySock);
  args.push(
    "--",
    node.real,
    STEP_NETNS_ENTRY,
    "--sock", sockInside,
    "--proxy-port", String(proxyPort),
    "--fds", "0,1,2",
    "--",
    ...commandPrefix,
    command,
    ...runtimeArgs,
    ...commandArgs,
  );

  // ---- the env: an allowlist, built here ----
  const env = {
    PATH: STEP_PATH,
    LANG: STEP_LANG,
    TMPDIR: "/tmp",
  };
  if (language === "python") {
    env.PYTHONDONTWRITEBYTECODE = "1";
    if (uvCacheDir) env.UV_CACHE_DIR = STEP_MOUNTS.uvCache;
  } else {
    env.NODE_PATH = STEP_MOUNTS.env + "/node_modules";
  }
  const injectHosts = Array.isArray(o.injectHosts) ? o.injectHosts.filter((h) => typeof h === "string" && h) : [];
  const connectHosts = Array.isArray(o.connectHosts) ? o.connectHosts.filter((h) => typeof h === "string" && h) : [];
  const anyProxy = injectHosts.length > 0 || connectHosts.length > 0;
  if (anyProxy) {
    const proxy = "http://127.0.0.1:" + proxyPort;
    // The relay serves an absolute-form plain-HTTP request only for an inject host; a CONNECT tunnel
    // only for an approved plain host. A step gets the variable for the shape it really has.
    if (injectHosts.length > 0) {
      env.HTTP_PROXY = proxy;
      env.http_proxy = proxy;
    }
    if (connectHosts.length > 0) {
      env.HTTPS_PROXY = proxy;
      env.https_proxy = proxy;
    }
    env.NO_PROXY = "127.0.0.1,localhost,::1";
    env.no_proxy = "127.0.0.1,localhost,::1";
    if (language === "node") env.NODE_USE_ENV_PROXY = "1";
  }

  return { args, env };
}

/** The files a plan binds, for a status surface: mount, name and source. Never a secret. */
export function describeStepPlan(plan) {
  const out = { mounts: [], writable: [] };
  const args = plan && Array.isArray(plan.args) ? plan.args : [];
  for (let i = 0; i + 2 < args.length; i++) {
    const flag = args[i];
    if (flag !== "--ro-bind" && flag !== "--bind") continue;
    out.mounts.push({ flag, source: args[i + 1], dest: args[i + 2] });
    if (flag === "--bind") out.writable.push(args[i + 2]);
  }
  return out;
}