// A contained bot spawn decides its provider doors synchronously, from the local-model
// vouch cache. In a process that is not the gateway (the pi-bots spawner) that cache
// starts empty, so the FIRST contained turn after a restart found a Docker-run model
// "not vouched" and was refused ("provider <id> has no door"). The spawners now await
// ensureLocalModelVouch() first: bounded, and failing closed when Docker cannot answer.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
import {
  ensureLocalModelVouch,
  isKnownLocalModelTargetCached,
  resetLocalModelVouchCache,
  COMPOSE_WORKING_DIR_LABEL,
} from "../servers/gateway/models/local-model-servers.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROOT = mkdtempSync(join(tmpdir(), "crow-vouch-prime-"));
after(() => rmSync(ROOT, { recursive: true, force: true }));

const PORT = 18093;
const URL_ = `http://127.0.0.1:${PORT}/v1`;

/** A home whose only vouch for PORT is a Docker container run from an AI bundle's
 *  directory (no compose file there, so nothing vouches without Docker). */
function dockerOnlyHome(name) {
  const home = join(ROOT, name);
  const dir = join(home, "bundles", "vllm-custom");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ id: "vllm-custom", category: "ai" }));
  const runner = async (_cmd, args) => {
    if (args[0] === "ps") return { stdout: "c0ffee\n" };
    return { stdout: JSON.stringify({ id: "c0ffee", name: "/c0ffee", running: true,
      labels: { [COMPOSE_WORKING_DIR_LABEL]: dir },
      ports: { [`${PORT}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(PORT) }] } }) + "\n" };
  };
  return { home, runner };
}

test("cold cache: the first sync decision is not-vouched; after ensureLocalModelVouch the same row has its door", async () => {
  resetLocalModelVouchCache();
  const { home, runner } = dockerOnlyHome("cold");
  // The sync predicate as doorRow's caller sees it: no Docker runner of its own, so
  // only the module cache can vouch. (A no-op runner keeps its background prime inert.)
  const idle = async () => new Promise(() => {});
  const cached = () => isKnownLocalModelTargetCached(URL_, { crowHome: home, uid: process.getuid?.() ?? 0, selfPid: -1, dockerRunner: idle });
  assert.deepEqual(cached(), { local: false, reason: "not-vouched" }, "RED: the cold first call refuses");
  resetLocalModelVouchCache();
  await ensureLocalModelVouch({ deps: { crowHome: home, dockerRunner: runner } });
  assert.deepEqual(cached(), { local: true, reason: "vouched" }, "the awaited prime fills the cache the sync decision reads");
});

test("a warm cache returns at once without asking Docker again", async () => {
  resetLocalModelVouchCache();
  const { home, runner } = dockerOnlyHome("warm");
  await ensureLocalModelVouch({ deps: { crowHome: home, dockerRunner: runner } });
  let asked = 0;
  const t0 = Date.now();
  await ensureLocalModelVouch({ deps: { crowHome: home, dockerRunner: async () => { asked++; return { stdout: "" }; } } });
  assert.equal(asked, 0);
  assert.ok(Date.now() - t0 < 50);
});

test("a Docker that never answers costs at most the time limit, and the decision fails closed", async () => {
  resetLocalModelVouchCache();
  const { home } = dockerOnlyHome("hung");
  const t0 = Date.now();
  await ensureLocalModelVouch({ timeoutMs: 150, deps: { crowHome: home, dockerRunner: () => new Promise(() => {}) } });
  const took = Date.now() - t0;
  assert.ok(took >= 100 && took < 1500, `bounded wait (${took} ms)`);
  const r = isKnownLocalModelTargetCached(URL_, { crowHome: home, selfPid: -1, dockerRunner: () => new Promise(() => {}) });
  assert.deepEqual(r, { local: false, reason: "not-vouched" });
  resetLocalModelVouchCache();
});

test("a Docker that fails is not an error: the wait returns and the decision fails closed", async () => {
  resetLocalModelVouchCache();
  const { home } = dockerOnlyHome("down");
  await ensureLocalModelVouch({ deps: { crowHome: home, dockerRunner: async () => { throw new Error("docker: command not found"); } } });
  assert.deepEqual(isKnownLocalModelTargetCached(URL_, { crowHome: home, selfPid: -1 }), { local: false, reason: "not-vouched" });
  resetLocalModelVouchCache();
});

test("every spawner goes through bridge.spawnPiRpc, and the bridge primes BEFORE its eval-seam checks", () => {
  const bridge = readFileSync(join(REPO, "scripts/pi-bots/bridge.mjs"), "utf8");
  const prime = bridge.indexOf("await primeSpawnVouch(spawnPrep.piRpcOpts)");
  assert.ok(prime > 0, "handleInbound primes the vouch cache");
  assert.ok(prime < bridge.indexOf("if (evalSeam !== null) {"), "before the eval-seam checks (nothing async may follow them)");
  const spawn = bridge.indexOf("const pi = await spawnPiRpc(Object.assign({}, spawnPrep.piRpcOpts");
  assert.ok(spawn > bridge.indexOf("if (evalSeam !== null) {"), "the spawn follows the checks");
  assert.match(bridge.slice(spawn, spawn + 400), /primed: true/, "and does not await anything before constructing");
  const review = readFileSync(join(REPO, "scripts/pi-bots/skill_review.mjs"), "utf8");
  assert.match(review, /await spawnPiRpc\(/);
  const jobs = readFileSync(join(REPO, "scripts/pi-bots/job_runner.mjs"), "utf8");
  assert.match(jobs, /await bridge\.spawnPiRpc\(/);
  const perch = readFileSync(join(REPO, "servers/gateway/perch-interactive.js"), "utf8");
  assert.match(perch, /S\.spawnPiRpc \? await S\.spawnPiRpc\(piOpts, \{ always: true/);
});

test("no PiRpc is constructed directly outside the spawnPiRpc helper (scripts/ and servers/)", () => {
  const { execFileSync } = require("node:child_process");
  const out = execFileSync("grep", ["-rlE", "--include=*.mjs", "--include=*.js", "--exclude-dir=node_modules", "PiRpc", "scripts", "servers", "bundles"], { cwd: REPO, encoding: "utf8" })
    .split("\n").filter(Boolean);
  const direct = out.filter((f) => /new (?:[A-Za-z_$][\w$]*\.)?PiRpc\(/.test(readFileSync(join(REPO, f), "utf8")));
  assert.deepEqual(direct, [], "construct through spawnPiRpc (scripts/pi-bots/bridge.mjs)");
  const bridge = readFileSync(join(REPO, "scripts/pi-bots/bridge.mjs"), "utf8");
  assert.equal([...bridge.matchAll(/new PiRpcClass\(/g)].length, 1, "the helper is the one construction site");
});
