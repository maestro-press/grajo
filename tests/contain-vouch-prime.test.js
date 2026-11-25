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

test("both spawners await the prime before new PiRpc (and the bridge before its eval-seam checks)", () => {
  const bridge = readFileSync(join(REPO, "scripts/pi-bots/bridge.mjs"), "utf8");
  const prime = bridge.indexOf("await ensureLocalModelVouch()");
  assert.ok(prime > 0, "the bridge awaits the prime");
  assert.ok(prime < bridge.indexOf("if (evalSeam !== null) {"), "before the eval-seam checks (nothing async may follow them)");
  assert.ok(prime < bridge.indexOf("const pi = new PiRpc(Object.assign({}, spawnPrep.piRpcOpts"), "before the turn's PiRpc");
  const review = readFileSync(join(REPO, "scripts/pi-bots/skill_review.mjs"), "utf8");
  const rp = review.indexOf("await ensureLocalModelVouch()");
  assert.ok(rp > 0 && rp < review.indexOf("const pi = new PiRpc("), "skill review awaits it before its PiRpc");
  const jobs = readFileSync(join(REPO, "scripts/pi-bots/job_runner.mjs"), "utf8");
  const jp = jobs.indexOf("await ensureLocalModelVouch()");
  assert.ok(jp > 0 && jp < jobs.indexOf("const pi = new bridge.PiRpc("), "a scheduled (goal) job awaits it before its own PiRpc");
  const perch = readFileSync(join(REPO, "servers/gateway/perch-interactive.js"), "utf8");
  const pp = perch.indexOf("await ensureLocalModelVouch()");
  assert.ok(pp > 0 && pp < perch.indexOf("const pi = new S.PiRpc("), "Perch awaits it before its PiRpc");
});

test("every production PiRpc construction is one of the four that await the prime", () => {
  const { execFileSync } = require("node:child_process");
  const out = execFileSync("grep", ["-rln", "--include=*.mjs", "--include=*.js", "PiRpc(", "scripts", "servers", "bundles"], { cwd: REPO, encoding: "utf8" })
    .split("\n").filter((f) => f && !f.includes("node_modules"));
  const spawners = out.filter((f) => /new (?:[A-Za-z_$][\w$]*\.)?PiRpc\(/.test(readFileSync(join(REPO, f), "utf8"))).sort();
  assert.deepEqual(spawners, ["scripts/pi-bots/bridge.mjs", "scripts/pi-bots/job_runner.mjs", "scripts/pi-bots/skill_review.mjs", "servers/gateway/perch-interactive.js"]);
});
