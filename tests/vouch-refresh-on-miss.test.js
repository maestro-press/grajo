// A long-lived process (the gateway) holds a Docker snapshot older than a container started or pinned after it.
// The first contained turn then read "not vouched" and lost its door. ensureLocalModelVouch({targets}) refreshes
// on a MISS (never on age alone): all-vouched or non-own-host targets cost no Docker call.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ensureLocalModelVouch, isKnownLocalModelTargetCached, resetLocalModelVouchCache,
  VOUCH_MISS_REFRESH_MIN_AGE_MS, COMPOSE_WORKING_DIR_LABEL,
} from "../servers/gateway/models/local-model-servers.js";

const ROOT = mkdtempSync(join(tmpdir(), "crow-vouch-miss-"));
after(() => rmSync(ROOT, { recursive: true, force: true }));
const A = 18111, B = 18112;
const url = (p) => `http://127.0.0.1:${p}/v1`;

function fixture(name) {
  const home = join(ROOT, name);
  const dir = join(home, "bundles", "vllm-custom");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ id: "vllm-custom", category: "ai" }));
  const live = new Map(); // port -> true
  const calls = { n: 0 };
  const runner = async (_c, args) => {
    calls.n++;
    if (args[0] === "ps") return { stdout: [...live.keys()].map((p) => "c" + p).join("\n") + "\n" };
    const ids = args.filter((a) => /^c\d+$/.test(a));
    return { stdout: ids.map((id) => JSON.stringify({ id, name: "/" + id, running: true,
      labels: { [COMPOSE_WORKING_DIR_LABEL]: dir },
      ports: { [`${id.slice(1)}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: id.slice(1) }] } })).join("\n") + "\n" };
  };
  let clock = 1_000_000;
  const deps = { crowHome: home, uid: process.getuid?.() ?? 0, selfPid: -1, dockerRunner: runner, now: () => clock };
  return { live, calls, deps, advance: (ms) => { clock += ms; } };
}
const vouched = (u, deps) => isKnownLocalModelTargetCached(u, deps).local === true;

test("(a) a container started after the snapshot is vouched after the first ensure with targets", async () => {
  resetLocalModelVouchCache();
  const f = fixture("a");
  f.live.set(A, true);
  await ensureLocalModelVouch({ deps: f.deps });
  assert.ok(vouched(url(A), f.deps));
  f.live.set(B, true);               // started after the snapshot
  f.advance(VOUCH_MISS_REFRESH_MIN_AGE_MS + 500);
  assert.equal(vouched(url(B), f.deps), false, "RED before the fix: the stale snapshot misses it");
  await ensureLocalModelVouch({ deps: f.deps, targets: [url(B)] });
  assert.ok(vouched(url(B), f.deps));
  resetLocalModelVouchCache();
});

test("(b) all-vouched or non-own-host targets make no docker call", async () => {
  resetLocalModelVouchCache();
  const f = fixture("b");
  f.live.set(A, true);
  await ensureLocalModelVouch({ deps: f.deps });
  const before = f.calls.n;
  f.advance(5_000); // older than the min age, inside the TTL
  await ensureLocalModelVouch({ deps: f.deps, targets: [url(A), "https://api.example.com/v1", "http://192.0.2.7:8000/v1"] });
  assert.equal(f.calls.n, before);
  resetLocalModelVouchCache();
});

test("(c) a miss against a snapshot younger than the min age makes no refresh", async () => {
  resetLocalModelVouchCache();
  const f = fixture("c");
  f.live.set(A, true);
  await ensureLocalModelVouch({ deps: f.deps });
  const before = f.calls.n;
  f.live.set(B, true);
  f.advance(VOUCH_MISS_REFRESH_MIN_AGE_MS - 500);
  await ensureLocalModelVouch({ deps: f.deps, targets: [url(B)] });
  assert.equal(f.calls.n, before);
  assert.equal(vouched(url(B), f.deps), false);
  resetLocalModelVouchCache();
});

test("(d) a hung docker returns within the time limit and stays not-vouched", async () => {
  resetLocalModelVouchCache();
  const f = fixture("d");
  f.live.set(A, true);
  await ensureLocalModelVouch({ deps: f.deps });
  f.advance(VOUCH_MISS_REFRESH_MIN_AGE_MS + 500);
  const hung = { ...f.deps, dockerRunner: () => new Promise(() => {}) };
  const t0 = Date.now();
  await ensureLocalModelVouch({ timeoutMs: 150, deps: hung, targets: [url(B)] });
  const took = Date.now() - t0;
  assert.ok(took >= 100 && took < 1500, `bounded (${took} ms)`);
  assert.equal(vouched(url(B), hung), false);
  assert.ok(vouched(url(A), hung), "the last good snapshot still vouches what it did");
  resetLocalModelVouchCache();
});
