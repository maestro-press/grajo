// PR 3c: the file side of a report custom step. What one step may see (its env, its own bundle, the
// assets it binds, one writable work dir, and nothing else), which namespaces and caps hold it, and the
// env it gets: an allowlist with no secret-like name and no keychain path.
//
// The warm-up half is here too: uv is the only Python resolver, it is told never to download an
// interpreter, the interpreter is the system python, and the hosts a build may reach are exactly the
// three package registries.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { buildStepPlan, StepPlanRefused, STEP_MOUNTS, STEP_NETNS_ENTRY, SYSTEM_PYTHON } from "../scripts/report-steps/plan.mjs";
import { addressSpaceBytes, addressSpacePrefix, BYTES_PER_MB } from "../scripts/report-steps/runner.mjs";
import { buildWarmupPlan, warmupStepsFor, WARMUP_HOSTS } from "../scripts/report-steps/warmup.mjs";
import {
  parseNodeRequirements,
  parsePythonRequirements,
  requirementsHash,
  REQUIREMENTS_MAX_BYTES,
} from "../scripts/report-steps/env.mjs";
import { SECRET_NAME_RE } from "../servers/shared/bot-env.js";

const root = mkdtempSync(join(tmpdir(), "crow-report-steps-plan-"));
after(() => rmSync(root, { recursive: true, force: true }));

/** A node binary this file owns: a plan only needs an absolute path to a file, and no test host is
 * guaranteed to have `/usr/bin/node`. */
const NODE_BIN = join(root, "node-" + Math.random().toString(16).slice(2), "bin", "node");
mkdirSync(dirname(NODE_BIN), { recursive: true });
writeFileSync(NODE_BIN, "");

/** `p` is `parent` or inside it: segment-aware, so `/usr/local` is neither `/usr` nor under it. */
const under = (p, parent) => p === parent || p.startsWith(parent.endsWith("/") ? parent : parent + "/");

const REPORT_ID = "rpt-0123456789abcdef";
const STEP_KEY = "fetch";

/** One report's tree on this instance, and the tmp dirs a run owns. */
function fixture(over = {}) {
  const home = join(root, "home-" + Math.random().toString(16).slice(2));
  const reportRoot = join(home, "reports", REPORT_ID);
  const envDir = join(reportRoot, "env", "python");
  const assetsDir = join(reportRoot, "assets");
  const uvCacheDir = join(reportRoot, "env", ".cache", "uv");
  const bundleDir = join(root, "bundle-" + Math.random().toString(16).slice(2));
  const workDir = join(root, "work-" + Math.random().toString(16).slice(2));
  const relayDir = join(root, "net-" + Math.random().toString(16).slice(2));
  for (const dir of [join(envDir, "bin"), assetsDir, uvCacheDir, bundleDir, workDir, relayDir]) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(join(assetsDir, "a".repeat(64)), '[{"id":1}]');
  writeFileSync(join(bundleDir, "run.py"), "print('{}')\n");
  return {
    home, envDir, assetsDir, uvCacheDir, bundleDir, workDir,
    relaySock: join(relayDir, "relay.sock"),
    assetBinds: [{ name: "ways.json", path: join(assetsDir, "a".repeat(64)) }],
    ...over,
  };
}

const planOf = (f, over = {}) => buildStepPlan({
  reportId: REPORT_ID,
  stepKey: STEP_KEY,
  language: "python",
  entry: "run.py",
  envDir: f.envDir,
  bundleDir: f.bundleDir,
  assetsDir: f.assetsDir,
  assetBinds: f.assetBinds,
  relaySock: f.relaySock,
  workDir: f.workDir,
  uvCacheDir: f.uvCacheDir,
  nodeBin: NODE_BIN,
  home: f.home,
  seccompFd: 3,
  ...over,
});

/** Every `[flag, source, dest]` triple in an argv, so a bind can be found by its destination. */
function triples(args) {
  const out = [];
  for (let i = 0; i + 2 < args.length; i += 1) {
    if (args[i] === "--ro-bind" || args[i] === "--bind" || args[i] === "--ro-bind-try") {
      out.push([args[i], args[i + 1], args[i + 2]]);
      i += 2;
    }
  }
  return out;
}

test("the plan has --unshare-net and every namespace flag, and no crow.db, $HOME or workspace bind", () => {
  const f = fixture();
  const { args } = planOf(f);
  for (const flag of ["--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
    "--die-with-parent", "--new-session"]) {
    assert.ok(args.includes(flag), flag + " is in the plan: " + args.join(" "));
  }
  assert.deepEqual(args.slice(args.indexOf("--cap-drop"), args.indexOf("--cap-drop") + 2), ["--cap-drop", "ALL"]);
  assert.deepEqual(args.slice(args.indexOf("--seccomp"), args.indexOf("--seccomp") + 2), ["--seccomp", "3"]);
  assert.deepEqual(args.slice(args.indexOf("--chdir"), args.indexOf("--chdir") + 2), ["--chdir", STEP_MOUNTS.work]);

  const binds = triples(args);
  const dests = binds.map((b) => b[2]);
  const workspaceDir = join(f.home, "projects", "bird-count");
  // The mount list is EXACTLY this run's own sources and the engine: nothing of this instance, no
  // workspace, no DB.
  const systemSources = new Set(["/usr", "/etc", "/opt", "/run/systemd/resolve"]);
  const sources = binds.map((b) => b[1]).filter((src) => !systemSources.has(src));
  assert.deepEqual(sources.slice().sort(), [
    f.envDir, f.bundleDir, f.assetBinds[0].path, f.uvCacheDir, f.workDir,
    realpathSync(join(f.relaySock, "..")), STEP_NETNS_ENTRY,
    NODE_BIN, // a node outside /usr is bound as the one file it is
  ].map((p) => realpathSync(p)).sort());
  for (const source of sources) {
    assert.notEqual(source, f.home, "the home itself is never a bind source");
    assert.notEqual(source, workspaceDir, "a workspace is never a bind source");
    assert.equal(source.endsWith("crow.db"), false, "crow.db is never a bind source: " + source);
  }
  for (const dest of dests) {
    assert.notEqual(dest, f.home, "the home path is not a mount point");
    assert.notEqual(dest, workspaceDir, "a workspace is not a mount point");
  }

  // The one writable mount is the work dir.
  const writable = binds.filter((b) => b[0] === "--bind");
  assert.deepEqual(writable, [["--bind", f.workDir, STEP_MOUNTS.work]]);
  // Read-only: the env, the bundle and each named asset at /assets/<name>.
  assert.ok(binds.some(([flag, src, dest]) => flag === "--ro-bind" && src === f.envDir && dest === STEP_MOUNTS.env));
  assert.ok(binds.some(([flag, src, dest]) => flag === "--ro-bind" && src === f.bundleDir && dest === STEP_MOUNTS.bundle));
  assert.ok(binds.some(([flag, src, dest]) => flag === "--ro-bind"
    && src === f.assetBinds[0].path && dest === STEP_MOUNTS.assets + "/ways.json"));
  assert.ok(binds.some(([flag, src, dest]) => flag === "--ro-bind" && src === f.uvCacheDir && dest === STEP_MOUNTS.uvCache));
  // The relay dir is the only thing in the plan's /run.
  assert.equal(args.filter((a) => a === "/run/crow-net").length, 1);
  assert.ok(binds.some(([flag, src, dest]) => flag === "--ro-bind" && dest === "/run/crow-net"
    && src === realpathSync(join(f.relaySock, ".."))));
});

test("the plan env is an allowlist: no secret-like name, no keychain path, no HOME", () => {
  const f = fixture();
  const { env } = planOf(f, { injectHosts: ["api.example.com"], connectHosts: ["data.example.com"] });
  for (const name of Object.keys(env)) {
    assert.equal(SECRET_NAME_RE.test(name), false, name + " looks like a credential");
    assert.equal(name.startsWith("CROW_"), false, name + " is gateway state");
  }
  assert.equal(env.HOME, undefined, "no home is handed to a step");
  assert.equal(env.PATH, "/usr/local/bin:/usr/bin:/bin");
  assert.equal(env.LANG, "C.UTF-8");
  assert.equal(env.TMPDIR, "/tmp");
  assert.equal(env.UV_CACHE_DIR, STEP_MOUNTS.uvCache);
  assert.equal(env.PYTHONDONTWRITEBYTECODE, "1");
  assert.equal(env.NODE_PATH, undefined, "a python step is not told about node_modules");
  for (const value of Object.values(env)) {
    assert.equal(String(value).includes(join(f.home, "secrets")), false, "no keychain path in the env");
    assert.equal(String(value).includes(f.assetsDir), false, "no host path in the env");
  }
  // The proxy variables are set only for the shape the relay really serves.
  assert.equal(env.HTTP_PROXY, "http://127.0.0.1:39080");
  assert.equal(env.http_proxy, "http://127.0.0.1:39080");
  assert.equal(env.HTTPS_PROXY, "http://127.0.0.1:39080");
  assert.equal(env.NODE_USE_ENV_PROXY, undefined, "a python step gets no node switch");

  const injectOnly = planOf(f, { injectHosts: ["api.example.com"] }).env;
  assert.equal(injectOnly.HTTP_PROXY, "http://127.0.0.1:39080");
  assert.equal(injectOnly.HTTPS_PROXY, undefined, "no CONNECT tunnel exists without an approved plain host");

  const connectOnly = planOf(f, { connectHosts: ["data.example.com"] }).env;
  assert.equal(connectOnly.HTTP_PROXY, undefined, "no credential form exists without an inject host");
  assert.equal(connectOnly.HTTPS_PROXY, "http://127.0.0.1:39080");

  const none = planOf(f).env;
  assert.equal(none.HTTP_PROXY, undefined);
  assert.equal(none.HTTPS_PROXY, undefined);
  assert.equal(none.NO_PROXY, undefined);
});

test("a node step runs the engine with its heap cap and NODE_PATH, and the engine is the binary only", () => {
  const f = fixture();
  const nodeDir = join(root, "node-" + Math.random().toString(16).slice(2), "bin");
  mkdirSync(nodeDir, { recursive: true });
  const nodeBin = join(nodeDir, "node");
  writeFileSync(nodeBin, "");
  const { args, env } = planOf(f, { language: "node", nodeBin, runtimeArgs: ["--max-old-space-size=1024"] });
  assert.equal(env.NODE_PATH, STEP_MOUNTS.env + "/node_modules");
  assert.ok(!("UV_CACHE_DIR" in env), "a node step is not told about a uv cache");
  const binary = realpathSync(nodeBin);
  const prefix = dirname(dirname(binary));
  // The entry command: node, then its own argument, then the entry file inside the bundle.
  const sep = args.indexOf("--fds") + 2;
  assert.equal(args[sep], "--");
  assert.deepEqual(args.slice(sep + 1), [
    binary, "--max-old-space-size=1024", STEP_MOUNTS.bundle + "/run.py",
  ]);
  const binds = triples(args);
  // The BINARY at its own path is the engine mount, and nothing of its install prefix is.
  assert.ok(binds.some(([flag, src, dest]) => flag === "--ro-bind" && src === binary && dest === binary),
    "the node binary is bound read-only at its own path");
  assert.equal(binds.some(([flag, src]) => flag === "--ro-bind" && src === prefix), false,
    "the install prefix is never a bind source");
});

test("the address-space cap is a byte count: memoryMb*1048576 for python, four times it for node", () => {
  for (const memoryMb of [1, 512, 1024]) {
    assert.equal(addressSpaceBytes("python", memoryMb), memoryMb * 1048576);
    assert.equal(addressSpaceBytes("python", memoryMb), memoryMb * BYTES_PER_MB);
    assert.equal(addressSpaceBytes("node", memoryMb), 4 * memoryMb * 1048576);
    for (const language of ["python", "node"]) {
      const prefix = addressSpacePrefix({ language, memoryMb, prlimit: "/usr/bin/prlimit" });
      assert.equal(prefix.length, 3);
      assert.equal(prefix[0], "/usr/bin/prlimit");
      assert.equal(prefix[2], "--");
      const value = prefix[1].slice("--as=".length);
      assert.match(value, /^\d+$/, "prlimit takes plain bytes, with no unit suffix: " + prefix[1]);
      assert.equal(Number(value), language === "node" ? 4 * memoryMb * 1048576 : memoryMb * 1048576);
    }
  }
  assert.deepEqual(addressSpacePrefix({ language: "python", memoryMb: 64, prlimit: null }), [],
    "no prlimit on this computer, no prefix (and runCustomStep refuses a step at all: no cap is no wall)");
});

test("a command prefix runs before the interpreter, inside the wall", () => {
  const f = fixture();
  const memoryMb = 1024;
  const prefix = addressSpacePrefix({ language: "python", memoryMb, prlimit: "/usr/bin/prlimit" });
  const { args } = planOf(f, { commandPrefix: prefix });
  const sep = args.indexOf("--fds") + 2; // the "--" the entry's command follows
  assert.equal(args[sep], "--");
  assert.deepEqual(args.slice(sep + 1), [
    "/usr/bin/prlimit", "--as=" + memoryMb * 1048576, "--", "/env/bin/python", "/bundle/run.py",
  ]);
  // The wall's own processes are never under the step's cap: the prefix is inside the entry's command.
  assert.equal(args[0] !== "/usr/bin/prlimit", true);
  assert.throws(() => planOf(f, { commandPrefix: ["--as=1048576\n"] }), (err) => err.code === "bad_input");
});

test("no bind source is a directory above or containing a home a step must never see", () => {
  const f = fixture();
  // A node install outside the system dirs, and a co-hosted instance's home beside the Crow home: the
  // two things a prefix bind used to sweep into a plan.
  const install = join(root, "engine-" + Math.random().toString(16).slice(2), "versions", "node", "bin");
  mkdirSync(install, { recursive: true });
  const nodeBin = join(install, "node");
  writeFileSync(nodeBin, "");
  const sibling = join(root, ".crow-second");
  mkdirSync(join(sibling, "bin"), { recursive: true });
  writeFileSync(join(sibling, "bin", "node"), "");
  try {
    const homes = [f.home, homedir(), "/home", sibling];
    for (const plan of [planOf(f, { nodeBin }), planOf(f, { language: "node", nodeBin })]) {
      for (const [flag, source] of triples(plan.args)) {
        for (const home of homes) {
          // The report's own env and assets live under the Crow home by design; what may never be a
          // source is the home itself, or a DIRECTORY ABOVE IT (which would carry the whole tree in).
          assert.equal(under(home, source), false,
            flag + " source " + source + " is " + home + " or a directory containing it");
        }
      }
    }
  } finally {
    rmSync(sibling, { recursive: true, force: true });
  }
});

test("a nodeBin in the Crow home or a co-hosted instance's home is refused, never bound", () => {
  const f = fixture();
  const inHome = join(f.home, "tools", "bin", "node");
  mkdirSync(dirname(inHome), { recursive: true });
  writeFileSync(inHome, "");
  assert.throws(() => planOf(f, { nodeBin: inHome }),
    (err) => err instanceof StepPlanRefused && err.code === "bad_input", "the Crow home itself");

  const sibling = join(root, ".crow-r4");
  mkdirSync(join(sibling, "bin"), { recursive: true });
  const siblingBin = join(sibling, "bin", "node");
  writeFileSync(siblingBin, "");
  try {
    assert.throws(() => planOf(f, { nodeBin: siblingBin }),
      (err) => err instanceof StepPlanRefused && err.code === "bad_input", "a co-hosted instance's home");
  } finally {
    rmSync(sibling, { recursive: true, force: true });
  }
});

test("a plan that is not the thing it names is refused, never weakened", () => {
  const f = fixture();
  const cases = [
    [{ envDir: join(f.home, "reports", "rpt-ffffffffffffffff", "env", "python") }, "envDir outside this report"],
    [{ envDir: f.home }, "the home as the env"],
    [{ envDir: "/tmp" }, "an unrelated dir as the env"],
    [{ bundleDir: join(f.home, "reports", REPORT_ID) }, "the report tree as the bundle"],
    [{ workDir: f.bundleDir }, "the bundle as the work dir"],
    [{ assetBinds: [{ name: "ways.json", path: join(f.bundleDir, "run.py") }] }, "an asset outside the assets dir"],
    [{ assetBinds: [{ name: "../x", path: f.assetBinds[0].path }] }, "an asset name with a path in it"],
    [{ assetBinds: [{ name: "ways.json" }] }, "an asset without a path"],
    [{ language: "ruby" }, "an unknown language"],
    [{ entry: "../run.py" }, "an entry that escapes the bundle"],
    [{ entry: "/bundle/run.py" }, "an absolute entry"],
    [{ stepKey: "Bad key" }, "a step key that is not a slug"],
    [{ reportId: "../etc" }, "a report id with a path in it"],
    [{ seccompFd: null }, "no seccomp program"],
  ];
  for (const [over, label] of cases) {
    if (over.seccompFd === null) {
      // No seccomp fd is allowed (the tier without it), so the entry must be checked another way:
      // the plan simply carries no --seccomp.
      const { args } = planOf(f, over);
      assert.equal(args.includes("--seccomp"), false, label);
      continue;
    }
    assert.throws(() => planOf(f, over), (err) => err instanceof StepPlanRefused && err.code === "bad_input", label);
  }
});

test("uv runs with UV_PYTHON_DOWNLOADS=never and the system python, and only the three registries are reachable", () => {
  const python = warmupStepsFor({ language: "python", buildDir: "/build", uvBin: "/usr/bin/uv" });
  assert.equal(python.steps.length, 2);
  assert.deepEqual(python.steps[0].args.slice(0, 4), ["venv", "--quiet", "--python", SYSTEM_PYTHON]);
  assert.equal(python.steps[1].args.includes("--no-build"), true, "no source distribution is built");
  assert.equal(python.steps[1].args.includes("-r"), true);
  assert.equal(python.env.UV_PYTHON_DOWNLOADS, "never");
  assert.equal(python.env.PYTHONDONTWRITEBYTECODE, "1");
  assert.equal(python.env.UV_CACHE_DIR, "/cache/uv");

  assert.deepEqual([...WARMUP_HOSTS], ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]);

  // No uv: honest, and never a pip fallback.
  assert.deepEqual(warmupStepsFor({ language: "python", buildDir: "/build", uvBin: null }), { refused: "uv_missing" });

  const node = warmupStepsFor({ language: "node", buildDir: "/build", npmBin: "/usr/bin/npm" });
  assert.deepEqual(node.steps[0].args, ["ci", "--ignore-scripts", "--no-audit", "--no-fund"]);
  assert.equal(node.env.npm_config_ignore_scripts, "true");
});

test("the warm-up's own wall has the same namespaces, one writable build folder and a fixed env", () => {
  const f = fixture();
  const cacheDir = join(root, "cache-" + Math.random().toString(16).slice(2));
  mkdirSync(cacheDir, { recursive: true });
  const plan = buildWarmupPlan({
    buildDir: f.bundleDir,
    cacheDir,
    relaySock: f.relaySock,
    nodeBin: NODE_BIN,
    bwrap: "/usr/bin/bwrap",
    seccompFd: 3,
    home: f.home,
    command: "/usr/bin/uv",
    commandArgs: ["venv", "--quiet"],
    fixedEnv: { UV_PYTHON_DOWNLOADS: "never" },
  });
  for (const flag of ["--unshare-user", "--unshare-pid", "--unshare-net", "--die-with-parent", "--new-session"]) {
    assert.ok(plan.args.includes(flag), flag);
  }
  const binds = triples(plan.args);
  assert.deepEqual(binds.filter((b) => b[0] === "--bind"), [
    ["--bind", f.bundleDir, "/build"],
    ["--bind", cacheDir, "/cache"],
  ]);
  assert.equal(plan.env.UV_PYTHON_DOWNLOADS, "never");
  assert.equal(plan.env.HOME, f.home, "the build's home is the sandbox's empty tmpfs");
  assert.equal(plan.env.HTTPS_PROXY.startsWith("http://127.0.0.1:"), true);
  const sep = plan.args.lastIndexOf("--");
  assert.deepEqual(plan.args.slice(sep + 1), ["/usr/bin/uv", "venv", "--quiet"]);
  assert.equal(plan.cmd, "/usr/bin/bwrap", "the plan is run with the wall binary, not the node its argv carries");
});

test("the warm-up's node install is matched by segment, and one inside a home is refused", () => {
  const f = fixture();
  const cacheDir = join(root, "wcache-" + Math.random().toString(16).slice(2));
  mkdirSync(cacheDir, { recursive: true });
  const base = {
    buildDir: f.bundleDir, cacheDir, relaySock: f.relaySock, bwrap: "/usr/bin/bwrap",
    home: f.home, command: "/usr/bin/uv", commandArgs: [],
  };

  // `/usrlocal` is not `/usr`: a prefix that only STARTS with a system dir is still bound.
  const install = join(root, "usrlocal", "node", "bin");
  mkdirSync(install, { recursive: true });
  const nodeBin = join(install, "node");
  writeFileSync(nodeBin, "");
  const plan = buildWarmupPlan({ ...base, nodeBin });
  const prefix = realpathSync(dirname(dirname(nodeBin)));
  assert.ok(triples(plan.args).some(([flag, src, dest]) => flag === "--ro-bind" && src === prefix && dest === prefix),
    "a u-s-r-l-o-c-a-l install is bound, because the system check is a segment and not a prefix");
  assert.equal(plan.args.includes(realpathSync(nodeBin)), true, "the steps run on the resolved binary");

  // A binary in the Crow home is refused, and so is a binary whose install prefix CONTAINS the Crow
  // home: the warm-up binds a prefix, so the whole install has to be outside every home.
  const inHome = join(f.home, "tools", "bin", "node");
  mkdirSync(dirname(inHome), { recursive: true });
  writeFileSync(inHome, "");
  assert.throws(() => buildWarmupPlan({ ...base, nodeBin: inHome }), (err) => err.code === "bad_input");
  const aboveHome = join(root, "bin", "node");
  mkdirSync(dirname(aboveHome), { recursive: true });
  writeFileSync(aboveHome, "");
  assert.ok(planOf(f, { nodeBin: aboveHome }).args.includes(realpathSync(aboveHome)),
    "a plan binds the binary alone, so a file beside the Crow home is still a usable engine");
  assert.throws(() => buildWarmupPlan({ ...base, nodeBin: aboveHome }), (err) => err.code === "bad_input",
    "the warm-up binds the install, and that install contains the Crow home");
});

test("the requirements formats are parsed, and a text that is not one is refused", () => {
  assert.deepEqual(parsePythonRequirements("jinja2==3.1.4\nrequests[security]>=2.31,<3\n# a comment\n\n"), [
    { name: "jinja2", extras: null, specs: ["==3.1.4"], marker: null },
    { name: "requests", extras: "security", specs: [">=2.31", "<3"], marker: null },
  ]);
  assert.equal(parsePythonRequirements('pyyaml; python_version >= "3.9"')[0].marker, 'python_version >= "3.9"');
  for (const bad of ["", "   \n# only a comment\n", "jinja2 http://example.com/x.whl", "-r other.txt",
    "git+https://example.com/x", "jinja2====", "jinja2 >=", "[security]", "a b c"]) {
    assert.throws(() => parsePythonRequirements(bad), { code: "bad_requirements" }, JSON.stringify(bad));
  }
  assert.throws(() => parsePythonRequirements("a\n".repeat(REQUIREMENTS_MAX_BYTES)), { code: "bad_requirements" });

  const nodeText = JSON.stringify({
    "package.json": JSON.stringify({ name: "step", version: "1.0.0" }),
    "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: {} }),
  });
  const parsed = parseNodeRequirements(nodeText);
  assert.equal(JSON.parse(parsed.packageJson).name, "step");
  for (const bad of ["", "{}", "not json", JSON.stringify({ "package.json": "{}" }),
    JSON.stringify({ "package.json": "{}", "package-lock.json": "not json" }),
    JSON.stringify({ "package.json": "{}", "package-lock.json": "{}", extra: "{}" })]) {
    assert.throws(() => parseNodeRequirements(bad), { code: "bad_requirements" }, String(bad).slice(0, 40));
  }
});

test("the env's cache key is the requirements hash, and a different text is a different env", () => {
  assert.match(requirementsHash("jinja2==3.1.4\n"), /^[0-9a-f]{64}$/);
  assert.equal(requirementsHash("a"), requirementsHash("a"));
  assert.notEqual(requirementsHash("a"), requirementsHash("a\n"));
  assert.notEqual(requirementsHash(""), requirementsHash(" "));
});