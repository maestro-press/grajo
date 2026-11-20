// PR 3c: the walled step runner, run for real. A step is a small file bundle plus a per-report env,
// and everything it can do is bounded: it reads its bundle and its assets read-only, writes only its
// own work dir, has no network except the relay (which serves the report's approved hosts and nothing
// else), answers one JSON object on stdout, and dies at the time and memory caps.
//
// Gated on the host, like tests/pi-contain-net.test.js: without bubblewrap and an unprivileged user
// namespace this file skips with the reason the wall probe gave. Everything runs against a scratch home
// and a real relay on a unix socket; the TLS upstream in the inject case is a throwaway certificate
// generated here with node:crypto alone.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createServer as createHttpsServer } from "node:https";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  NO_WALL_TEXT, OUTPUT_MAX_BYTES, probeWall, relayOptionsFor, runCustomStep,
} from "../scripts/report-steps/runner.mjs";
import { STEP_PROXY_PORT } from "../scripts/report-steps/plan.mjs";
import { SECRET_NAME_RE } from "../servers/shared/bot-env.js";

const WALL = probeWall();
const SYSTEM_PYTHON = "/usr/bin/python3";

const root = realpathSync(mkdtempSync(join(tmpdir(), "crow-report-step-runner-")));
const REPORT_ID = "rpt-0123456789abcdef";
const HOME = join(root, "home");
const REPORT_ROOT = join(HOME, "reports", REPORT_ID);
const ASSETS = join(REPORT_ROOT, "assets");
const PY_ENV = join(REPORT_ROOT, "env", "python");
const NODE_ENV = join(REPORT_ROOT, "env", "node");
const ASSET_SHA = "b".repeat(64);

/* ---------------------------------------------------------------- the step sources */

/** Where the secret the tests echo is written, so one placeholder covers every step. */
const SECRET_SLOT = "rpt_step_placeholder_4Tb7Hn3VpLk9";
/** A strict JSON object on stdout, and nothing else. */
const emit = (body) => `import json\nprint(json.dumps(${body}))\n`;

/**
 * Every step this file runs, as source. They are module-level so the compile check below covers them
 * even on a host where every sandboxed case skips: a skip must mean "no sandbox", never "a typo".
 */
const STEPS = Object.freeze({
  /** Renders its own template file, and reads its bound asset. */
  template: [
    "import json",
    "template = open('/bundle/templates/report.html', encoding='utf-8').read()",
    "asset = json.load(open('/assets/ways.json', encoding='utf-8'))",
    "try:",
    "    import jinja2",
    "    rendered = jinja2.Template(template).render(title='Ways')",
    "except Exception:",
    "    rendered = template.replace('{{ title }}', 'Ways')",
    "print(json.dumps({'items': [{'title': rendered.strip(), 'ways': len(asset['ways'])}]}))",
    "",
  ].join("\n"),
  /** Tries to write each mount it is not allowed to write, and the one it is. */
  readonly: [
    "import json, os",
    "def attempt(fn):",
    "    try:",
    "        fn()",
    "        return 'wrote'",
    "    except Exception as err:",
    "        return type(err).__name__",
    "out = {}",
    "out['asset_write'] = attempt(lambda: open('/assets/ways.json', 'w').write('x'))",
    "out['asset_unlink'] = attempt(lambda: os.unlink('/assets/ways.json'))",
    "out['bundle_write'] = attempt(lambda: open('/bundle/run.py', 'a').write('x'))",
    "out['work_write'] = attempt(lambda: open('scratch.txt', 'w').write('x'))",
    "out['cwd'] = os.getcwd()",
    "print(json.dumps({'items': [out]}))",
    "",
  ].join("\n"),
  /** A node step: it starts at all under the caps, and V8 got the heap cap. */
  nodeHeap: [
    "const report = { items: [{ execArgv: process.execArgv, heap: typeof process.memoryUsage().rss }] };",
    "process.stdout.write(JSON.stringify(report));",
    "",
  ].join("\n"),
  /** A step that never finishes on its own. */
  sleep: "import time\nprint('started', flush=True)\ntime.sleep(60)\n",
  /** A step that answers with more than the 8 MB cap. */
  bigOutput: `import sys\nsys.stdout.write(' ' * (${OUTPUT_MAX_BYTES + 1024 * 1024}))\n`,
  /** A step that writes the credential to stderr and fails. */
  stderrSecret: [
    "import sys",
    `sys.stderr.write(${JSON.stringify(SECRET_SLOT)})`,
    "raise SystemExit(3)",
    "",
  ].join("\n"),
  /** A step that echoes the credential it was given into its answer. */
  echo: emit(`{'items': [{'note': ${JSON.stringify("the credential is " + SECRET_SLOT)}}]}`),
  /** A step that lists its own environment. */
  envList: [
    "import json, os",
    "print(json.dumps({'data': {'env': sorted(os.environ.items())}}))",
    "",
  ].join("\n"),
  /** A step that tries to read beyond its mounts. */
  noRead: [
    "import json, os",
    "def read(path):",
    "    try:",
    "        open(path, 'rb').read(16)",
    "        return 'read'",
    "    except Exception as err:",
    "        return type(err).__name__",
    `out = {'db': read(${JSON.stringify(join(HOME, ".crow", "crow.db"))})}`,
    `out['home_listing'] = sorted(os.listdir(${JSON.stringify(HOME)}))`,
    `out['report_tree'] = os.path.exists(${JSON.stringify(REPORT_ROOT)})`,
    "print(json.dumps({'items': [out]}))",
    "",
  ].join("\n"),
  /** A step that asks the proxy for a host nobody approved. */
  offAllow: [
    "import json, os, socket",
    "def ask(host):",
    "    proxy = os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY')",
    "    if not proxy:",
    "        return 'no proxy'",
    "    port = int(proxy.rsplit(':', 1)[1])",
    "    sock = socket.create_connection(('127.0.0.1', port), timeout=10)",
    "    sock.sendall(('GET http://%s/x HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n' % (host, host)).encode())",
    "    line = sock.recv(200).decode('latin1').split('\\r\\n')[0]",
    "    sock.close()",
    "    return line",
    "print(json.dumps({'items': [{'other': ask('other.example.com')}]}))",
    "",
  ].join("\n"),
  /** A step that asks an approved inject host for one path, and reports the body it got back. */
  inject: [
    "import json, os, socket",
    "proxy = os.environ['HTTP_PROXY']",
    "port = int(proxy.rsplit(':', 1)[1])",
    "sock = socket.create_connection(('127.0.0.1', port), timeout=15)",
    "sock.sendall(b'GET http://api.example.com/v1/items HTTP/1.1\\r\\nHost: api.example.com\\r\\n\\r\\n')",
    "raw = b''",
    "while True:",
    "    chunk = sock.recv(4096)",
    "    if not chunk:",
    "        break",
    "    raw += chunk",
    "sock.close()",
    "body = raw.split(b'\\r\\n\\r\\n', 1)[-1].decode('utf-8', 'replace')",
    "print(json.dumps({'items': [{'body': body}]}))",
    "",
  ].join("\n"),
});

const skip = wallSkipReason(WALL);

/**
 * The skip a wall-gated case gets, or false. `CROW_REQUIRE_WALL=1` turns a missing wall into a run
 * (and so a failure) instead of a skip: on a machine that is meant to have the sandbox, a silent
 * skip is a green run that tested nothing.
 */
function wallSkipReason(wall, requireWall = process.env.CROW_REQUIRE_WALL === "1") {
  if (wall.ok === true) return false;
  if (requireWall) return false;
  return "no usable sandbox on this host: " + wall.reason;
}

/** Inside a wall-gated case: with `CROW_REQUIRE_WALL=1`, no wall is a failure and not a skip. */
function requireWallPresent(wall, requireWall = process.env.CROW_REQUIRE_WALL === "1") {
  if (wall.ok === true) return;
  if (!requireWall) return;
  assert.fail("CROW_REQUIRE_WALL=1 and this host has no usable sandbox: " + wall.reason);
}

/** One wall-gated test: skipped with the probe's reason, or failed when the switch demands a wall. */
function walled(name, opts, fn) {
  return test(name, { skip, ...opts }, async (t) => {
    requireWallPresent(WALL);
    return fn(t);
  });
}

test("CROW_REQUIRE_WALL=1 makes a wall skip a failure, and is off by default", () => {
  assert.equal(wallSkipReason({ ok: false, reason: "no bubblewrap" }, false),
    "no usable sandbox on this host: no bubblewrap", "without the switch a gated case skips");
  assert.equal(wallSkipReason({ ok: false, reason: "no bubblewrap" }, true), false,
    "with the switch the case runs, so a missing wall is a failure");
  assert.equal(wallSkipReason({ ok: true }, true), false);
  assert.equal(wallSkipReason({ ok: true }, false), false);
  assert.throws(() => requireWallPresent({ ok: false, reason: "no bubblewrap" }, true), /CROW_REQUIRE_WALL=1/);
  assert.doesNotThrow(() => requireWallPresent({ ok: false, reason: "no bubblewrap" }, false));
  assert.doesNotThrow(() => requireWallPresent({ ok: true }, true));
});

for (const dir of [join(PY_ENV, "bin"), join(NODE_ENV, "node_modules"), ASSETS]) mkdirSync(dir, { recursive: true });
symlinkSync(SYSTEM_PYTHON, join(PY_ENV, "bin", "python"));
chmodSync(PY_ENV, 0o700);
writeFileSync(join(ASSETS, ASSET_SHA), '{"ways":[{"id":1,"name":"Kuykendahl"}]}\n');

const closers = [];
after(async () => {
  for (const c of closers.splice(0)) await c().catch(() => {});
  rmSync(root, { recursive: true, force: true });
});

let seq = 0;

/** One bundle dir per call, written fresh, as `custom-step.js` writes it into a tmp dir. */
function bundle(files) {
  const dir = join(root, "bundle-" + (++seq));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const [path, text] of Object.entries(files)) {
    const target = join(dir, path);
    mkdirSync(join(target, ".."), { recursive: true });
    writeFileSync(target, text);
  }
  return dir;
}

function stepDeps(over = {}) {
  return {
    language: "python",
    entry: "run.py",
    envDir: PY_ENV,
    assetsDir: ASSETS,
    assetBinds: [{ name: "ways.json", path: join(ASSETS, ASSET_SHA) }],
    egressAllow: [],
    injectRules: [],
    home: HOME,
    nodeBin: process.execPath,
    ...over,
  };
}

/** Run one step bundle. */
async function run(files, over = {}, runOpts = {}) {
  return runCustomStep({
    reportId: REPORT_ID,
    stepKey: "fetch",
    input: { week: 1 },
    state: null,
    params: {},
    ...runOpts,
    deps: stepDeps({ bundleDir: bundle(files), ...over }),
  });
}

/** The rule one inject host gets: one host, the `/v1` subtree, reads only. */
const injectRule = (secret, over = {}) => ({
  host: "api.example.com",
  header: "Authorization",
  format: "Bearer {}",
  pathPrefixes: ["/v1"],
  secret: () => secret,
  ...over,
});

/* ------------------------------------------------------------------- what a step can read */

walled("a python step bundle with a template file renders, and its bound asset is readable", { skip, timeout: 60_000 }, async () => {
  const result = await run({
    "run.py": STEPS.template,
    "templates/report.html": "<h1>{{ title }}</h1>\n",
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(result.output.items, [{ title: "<h1>Ways</h1>", ways: 1 }]);
});

walled("assets are bound read-only, and the work dir is the one writable place", { skip, timeout: 60_000 }, async () => {
  const result = await run({ "run.py": STEPS.readonly });
  assert.equal(result.ok, true, JSON.stringify(result));
  const out = result.output.items[0];
  assert.notEqual(out.asset_write, "wrote", "an asset never takes a write: " + JSON.stringify(out));
  assert.notEqual(out.asset_unlink, "wrote", "an asset cannot be removed");
  assert.notEqual(out.bundle_write, "wrote", "the step's own bundle is read-only");
  assert.equal(out.work_write, "wrote", "the work dir is writable");
  assert.equal(out.cwd, "/work");
});

/* ------------------------------------------------------------------------- the memory limits */

walled("a node step starts under the memory limits, and its heap cap is passed to V8", { skip, timeout: 60_000 }, async () => {
  // The cap is `runCustomStep`'s own option, so it is passed there and not through the deps: the
  // runner forwards it to the plan's V8 argument and to the address-space prefix.
  const result = await run(
    { "index.js": STEPS.nodeHeap },
    { language: "node", entry: "index.js", envDir: NODE_ENV },
    { memoryMb: 512 },
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  const items = result.output.items;
  assert.equal(items.length, 1);
  assert.deepEqual(items[0].execArgv, ["--max-old-space-size=512"], "the V8 heap cap is on the command line");
  assert.equal(items[0].heap, "number");
});

/* --------------------------------------------------------------------------- the time cap */

walled("the time cap kills the step's process group and answers timeout", { skip, timeout: 60_000 }, async () => {
  let spawnedPid = null;
  const started = Date.now();
  const result = await runCustomStep({
    reportId: REPORT_ID,
    stepKey: "fetch",
    input: {},
    state: null,
    params: {},
    timeoutMs: 2000,
    deps: stepDeps({
      bundleDir: bundle({ "run.py": STEPS.sleep }),
      spawn: (cmd, args, opts) => {
        const child = spawn(cmd, args, opts);
        spawnedPid = child.pid;
        return child;
      },
    }),
  });
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.code, "timeout");
  assert.ok(Date.now() - started < 30_000, "the run ended at the cap, not at the step's own end");
  assert.equal(typeof spawnedPid, "number", "the step was spawned once");
  // Only the pid this run made, and its own process group: nothing was killed by name.
  assert.throws(() => process.kill(spawnedPid, 0), /ESRCH/, "the step's own pid is gone");
  assert.throws(() => process.kill(-spawnedPid, 0), /ESRCH/, "and its whole process group with it");
});

/* ------------------------------------------------------------------------ the output rules */

walled("output over 8 MB is refused, and the step is killed rather than streamed past", { skip, timeout: 90_000 }, async () => {
  const result = await run({ "run.py": STEPS.bigOutput }, {}, { timeoutMs: 30_000 });
  assert.equal(result.ok, false);
  assert.equal(result.code, "output_too_large");
});

walled("stdout that is not one JSON object is bad_output", { skip, timeout: 60_000 }, async () => {
  const notJson = await run({ "run.py": "print('hello there')\n" });
  assert.equal(notJson.code, "bad_output");
  const unknownKey = await run({ "run.py": emit("{'items': [], 'surprise': 1}") });
  assert.equal(unknownKey.code, "bad_output", "a field outside the contract is refused");
  const notObject = await run({ "run.py": emit("[1, 2, 3]") });
  assert.equal(notObject.code, "bad_output");
});

walled("a step that exits non-zero is exit_nonzero, and the stderr it kept is redacted", { skip, timeout: 60_000 }, async () => {
  const result = await run({ "run.py": STEPS.stderrSecret }, { secrets: [SECRET_SLOT] });
  assert.equal(result.ok, false);
  assert.equal(result.code, "exit_nonzero");
  assert.equal(String(result.stderr || "").includes(SECRET_SLOT), false, "the credential is not in the kept stderr");
  assert.match(String(result.stderr || ""), /\[redacted\]/);
});

walled("step stdout echoing the secret is redacted before it is parsed", { skip, timeout: 60_000 }, async () => {
  const result = await run(
    { "run.py": STEPS.echo },
    {
      secrets: [SECRET_SLOT],
      egressAllow: ["api.example.com"],
      injectRules: [injectRule(SECRET_SLOT)],
    },
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.output.items[0].note, "the credential is [redacted]");
  assert.equal(JSON.stringify(result.output).includes(SECRET_SLOT), false);
});

/* ------------------------------------------------------------------- what the env shows */

walled("env listing inside the step shows no secret, no keychain path and no gateway env", { skip, timeout: 60_000 }, async () => {
  const result = await run(
    { "run.py": STEPS.envList },
    {
      secrets: [SECRET_SLOT],
      egressAllow: ["api.example.com"],
      injectRules: [injectRule(SECRET_SLOT)],
    },
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  const env = Object.fromEntries(result.output.data.env);
  for (const name of Object.keys(env)) {
    assert.equal(SECRET_NAME_RE.test(name), false, name + " looks like a credential");
    assert.equal(name.startsWith("CROW_"), false, name + " is gateway state");
    assert.equal(String(env[name]).includes(SECRET_SLOT), false, name + " carries the credential");
    assert.equal(String(env[name]).includes(join(HOME, "secrets")), false, name + " names the keychain");
  }
  assert.equal(env.HOME, undefined, "no home data is handed to a step");
  assert.equal(env.PATH, "/usr/local/bin:/usr/bin:/bin");
  assert.equal(env.TMPDIR, "/tmp");
});

walled("a step cannot read the gateway's crow.db or its home", { skip, timeout: 60_000 }, async () => {
  const result = await run({ "run.py": STEPS.noRead });
  assert.equal(result.ok, true, JSON.stringify(result));
  const out = result.output.items[0];
  assert.notEqual(out.db, "read", "crow.db is not readable inside a step");
  assert.deepEqual(out.home_listing, [], "the home path is an empty tmpfs");
  assert.equal(out.report_tree, false, "the report's own tree outside the mounts does not exist");
});

/* ------------------------------------------------------------------------- the network */

walled("a step cannot reach a host outside the report's allowlist", { skip, timeout: 60_000 }, async () => {
  const result = await run(
    { "run.py": STEPS.offAllow },
    { egressAllow: ["api.example.com"], injectRules: [injectRule(SECRET_SLOT)] },
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.match(result.output.items[0].other, /^HTTP\/1\.1 403/, "the relay refuses a host nobody approved");
});

walled("an approved inject host gets the credential upstream, and the step never sees it", { skip, timeout: 90_000 }, async () => {
  const secret = "rpt_step_inject_7Hn3VpLk9Xm2";
  const host = "api.example.com";
  const PUB = "93.184.216.34";
  const NO_LOCAL = { v4: [], v6: [], onLink4: [], onLink6: [], v4Failed: false, v6Failed: false, onLinkFailed: false };
  const pair = selfSigned(host);
  const seen = [];
  const upstream = await httpsUpstream(pair, (req, res) => {
    seen.push(req.headers);
    res.writeHead(200, { "content-type": "text/plain" });
    // The upstream echoes the credential straight back, which is exactly what the relay must not pass on.
    res.end("header=" + String(req.headers.authorization || ""));
  });
  const result = await run(
    { "run.py": STEPS.inject },
    {
      egressAllow: [host, "other.example.com"],
      injectRules: [injectRule(secret, { pathPrefixes: ["/v1"] })],
      // A harness's seams: the socket override and the trust anchor are read only with
      // `testSeams: true`, which is what marks this caller as a test and not a report run.
      testSeams: true,
      relayOptions: {
        local: NO_LOCAL,
        lookup: async () => [{ address: PUB, family: 4 }],
        _connectOverride: () => ({ host: "127.0.0.1", port: upstream.port }),
        _injectUpstreamTls: { ca: pair.cert },
      },
    },
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(seen.length, 1, "one request reached the upstream");
  assert.equal(seen[0].authorization, "Bearer " + secret, "the relay attached the credential");
  const body = result.output.items[0].body;
  // The relay redacts the formatted value and the bare secret, longest first, so the whole
  // `Bearer <secret>` collapses to one marker.
  assert.equal(body, "header=[redacted]");
  assert.equal(JSON.stringify(result.output).includes(secret), false,
    "the credential itself is nowhere in the step's answer: " + JSON.stringify(result.output));
});

/* ------------------------------------------------------------------ the relay option allowlist */

test("the same relay seams are ignored by the runner without testSeams", () => {
  const owned = async () => [{ address: "93.184.216.34", family: 4 }];
  const seams = {
    lookup: owned,
    local: { v4: [], v6: [], onLink4: [], onLink6: [], v4Failed: false, v6Failed: false, onLinkFailed: false },
    _connectOverride: () => ({ host: "127.0.0.1", port: 1 }),
    _injectUpstreamTls: { ca: "x" },
    addon: { id: "x" },
    doorFilter: false,
    egressAllow: ["evil.example.com"],
    inject: [{ host: "evil.example.com" }],
  };

  const plain = relayOptionsFor({ relayOptions: seams });
  assert.equal(plain.lookup, owned, "lookup is the one name-resolution seam a run carries");
  assert.deepEqual(plain.local, seams.local, "and local is the own-address view");
  for (const name of ["_connectOverride", "_injectUpstreamTls", "addon", "doorFilter", "egressAllow", "inject"]) {
    assert.equal(name in plain, false, name + " is dropped without testSeams");
  }

  const harness = relayOptionsFor({ relayOptions: seams, testSeams: true });
  for (const name of Object.keys(seams)) {
    assert.equal(harness[name], seams[name], name + " reaches the relay for a harness");
  }

  // The flag is exactly `true`: any other value is a caller's bag and not a harness's.
  for (const notTrue of ["true", 1, {}, undefined, null]) {
    const bag = relayOptionsFor({ relayOptions: { _connectOverride: seams._connectOverride }, testSeams: notTrue });
    assert.equal("_connectOverride" in bag, false, "testSeams=" + String(notTrue) + " is not a harness");
  }
  assert.deepEqual(relayOptionsFor({}), {}, "a run with no bag carries nothing");
  assert.deepEqual(relayOptionsFor(), {}, "and neither does a run with no deps at all");
});

/* ------------------------------------------------------------- the step sources themselves */

test("every step source this file runs parses, so a skip here is the sandbox and not a typo", () => {
  for (const [name, source] of Object.entries(STEPS)) {
    if (name === "nodeHeap") continue;
    const checked = spawnSync(SYSTEM_PYTHON, ["-c", "import sys; compile(sys.stdin.read(), 'step', 'exec')"], {
      input: source, encoding: "utf8", timeout: 20_000,
    });
    assert.equal(checked.status, 0, name + " does not compile: " + String(checked.stderr || ""));
  }
  const nodeChecked = spawnSync(process.execPath, ["--check", "-"], {
    input: STEPS.nodeHeap, encoding: "utf8", timeout: 20_000,
  });
  assert.equal(nodeChecked.status, 0, "the node step does not parse: " + String(nodeChecked.stderr || ""));
});

/* ------------------------------------------------------------- a throwaway TLS certificate */

function derLength(size) {
  if (size < 0x80) return Buffer.from([size]);
  const bytes = [];
  let value = size;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value = Math.floor(value / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const der = (tag, ...chunks) => Buffer.concat([
  Buffer.from([tag]), derLength(Buffer.concat(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c)))).length),
  ...chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c))),
]);
const derSequence = (...chunks) => der(0x30, ...chunks);
const derSet = (...chunks) => der(0x31, ...chunks);
const derOid = (...bytes) => der(0x06, Buffer.from(bytes));
const derTrue = der(0x01, Buffer.from([0xff]));
const derName = (value) => derSequence(derSet(derSequence(derOid(0x55, 0x04, 0x03), der(0x0c, Buffer.from(value, "utf8")))));
const derPem = (label, bytes) => `-----BEGIN ${label}-----\n${(bytes.toString("base64").match(/.{1,64}/g) ?? []).join("\n")}\n-----END ${label}-----\n`;

/** A self-signed certificate for one name, from node:crypto alone (no openssl, no key in the repo). */
function selfSigned(name) {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const subjectPublicKey = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const signatureAlgorithm = derSequence(derOid(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02));
  const extensions = der(0xa3, derSequence(
    derSequence(derOid(0x55, 0x1d, 0x13), derTrue, der(0x04, derSequence(derTrue))),
    derSequence(derOid(0x55, 0x1d, 0x11), der(0x04, derSequence(der(0x82, Buffer.from(name, "ascii"))))),
    derSequence(derOid(0x55, 0x1d, 0x25), der(0x04, derSequence(derOid(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01)))),
  ));
  const toBeSigned = derSequence(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, Buffer.from([1])),
    signatureAlgorithm,
    derName(name),
    derSequence(der(0x17, Buffer.from("240101000000Z", "ascii")), der(0x17, Buffer.from("491231235959Z", "ascii"))),
    derName(name),
    subjectPublicKey,
    extensions,
  );
  const signature = crypto.sign("sha256", toBeSigned, privateKey);
  return {
    cert: derPem("CERTIFICATE", derSequence(toBeSigned, signatureAlgorithm, der(0x03, Buffer.from([0]), signature))),
    key: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

function httpsUpstream(pair, handle) {
  return new Promise((resolve) => {
    const live = new Set();
    const srv = createHttpsServer({ key: pair.key, cert: pair.cert }, (req, res) => {
      req.resume();
      req.on("end", () => handle(req, res));
    });
    srv.on("connection", (c) => { live.add(c); c.on("close", () => live.delete(c)); });
    srv.listen(0, "127.0.0.1", () => {
      closers.push(() => {
        for (const c of live) { try { c.destroy(); } catch { /* gone */ } }
        try { srv.closeAllConnections?.(); } catch { /* gone */ }
        return new Promise((r) => srv.close(() => r()));
      });
      resolve({ port: srv.address().port });
    });
  });
}

/* ------------------------------------------------------------------------- the honest line */

test("the no-wall sentence and the proxy port are the plan's", () => {
  assert.equal(NO_WALL_TEXT, "Custom steps can't run on this Crow (no sandbox available)");
  assert.equal(STEP_PROXY_PORT, 39080);
  assert.equal(existsSync(join(PY_ENV, "bin", "python")), true, "the env is where the plan expects it");
  assert.equal(readFileSync(join(ASSETS, ASSET_SHA), "utf8").includes("Kuykendahl"), true);
});