// (e) End to end: a process that already holds a stale snapshot, a container added after it, then the first
// contained turn (bridge.spawnPiRpc, the same helper every spawner uses) gets its provider door.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import Database from "better-sqlite3";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = mkdtempSync(join(tmpdir(), "crow-vouch-miss-spawn-"));
process.env.CROW_HOME = join(dir, "home");
process.env.CROW_DATA_DIR = join(dir, "data");
mkdirSync(process.env.CROW_HOME, { recursive: true });
mkdirSync(process.env.CROW_DATA_DIR, { recursive: true });
const skip = process.platform !== "linux" ? "linux only" : false;
const OLD = 18121, NEW = 18122;
const BUNDLE = "vllm-miss";
const bundleDir = join(process.env.CROW_HOME, "bundles", BUNDLE);
mkdirSync(bundleDir, { recursive: true });
writeFileSync(join(bundleDir, "manifest.json"), JSON.stringify({ id: BUNDLE, category: "ai" }));
const binDir = join(dir, "bin");
mkdirSync(binDir);
const LIVE = join(dir, "live.txt"); // one port per line; the fake docker reads it each call
writeFileSync(LIVE, `${OLD}\n`);
writeFileSync(join(binDir, "docker"), [
  "#!/bin/sh",
  `if [ "$1" = "ps" ]; then sed 's/^/c/' ${LIVE}; exit 0; fi`,
  `if [ "$1" = "inspect" ]; then for p in $(cat ${LIVE}); do echo '{"id":"c'$p'","name":"/c'$p'","running":true,"labels":{"com.docker.compose.project.working_dir":"${bundleDir}"},"ports":{"'$p'/tcp":[{"HostIp":"127.0.0.1","HostPort":"'$p'"}]}}'; done; exit 0; fi`,
  "exit 1", "",
].join("\n"));
chmodSync(join(binDir, "docker"), 0o755);
process.env.PATH = binDir + ":" + process.env.PATH;
const STUB = join(dir, "stub-pi.mjs");
writeFileSync(STUB, "process.exit(9);\n");
process.env.PIBOT_PI_CLI = STUB;
const BOT = "vouch-miss-bot";
process.env.CROW_PI_CONTAIN_BOTS = BOT;
delete process.env.CROW_PI_SANDBOX;

before(() => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });
  const c = new Database(join(process.env.CROW_DATA_DIR, "crow.db"));
  for (const [id, port] of [["old-prov", OLD], ["new-prov", NEW]]) {
    c.prepare("INSERT OR REPLACE INTO providers (id, base_url, models, host, disabled, bundle_id) VALUES (?, ?, ?, 'local', 0, ?)")
      .run(id, `http://127.0.0.1:${port}/v1`, JSON.stringify([{ id: "m1" }]), BUNDLE);
  }
  c.close();
});
after(() => rmSync(dir, { recursive: true, force: true }));

test("a stale snapshot + a container started later: the first contained spawn is not refused for 'no door'", { skip, timeout: 90000 }, async () => {
  const L = await import("../servers/gateway/models/local-model-servers.js");
  const bridge = await import("../scripts/pi-bots/bridge.mjs");
  await L.primeLocalModelVouch();                       // the long-lived process's snapshot: only OLD
  assert.equal(L.isKnownLocalModelTargetCached(`http://127.0.0.1:${NEW}/v1`).local, false);
  writeFileSync(LIVE, `${OLD}\n${NEW}\n`);              // a model started after the snapshot
  await new Promise((r) => setTimeout(r, L.VOUCH_MISS_REFRESH_MIN_AGE_MS + 200));
  const sessionDir = join(dir, "bots", BOT);
  mkdirSync(sessionDir, { recursive: true });
  const opts = { def: { tools: { pi_builtin: ["read"] }, permission_policy: { bash: "deny", write_paths: [sessionDir] } },
    botId: BOT, sessionDir, resolved: { provider: "new-prov", model: "m1", key: "new-prov/m1" }, selfAuthoringDir: null, piSessionId: null };
  assert.deepEqual(bridge.vouchTargetsFor(opts), [`http://127.0.0.1:${NEW}/v1`]);
  let pi;
  try {
    pi = await bridge.spawnPiRpc(opts);
  } catch (e) {
    assert.doesNotMatch(String(e && e.message), /no door/i, "refused for a missing door");
  }
  assert.equal(L.isKnownLocalModelTargetCached(`http://127.0.0.1:${NEW}/v1`).local, true, "the snapshot was refreshed on the miss");
  if (pi) { try { await pi.close(); } catch { /* stub exits */ } }
});
