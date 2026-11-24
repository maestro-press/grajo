/**
 * MICRO-BENCHMARK for the own-host forward's added latency (L1).
 *
 * SKIPPED unless `CROW_BENCH=1`: it measures wall-clock time, so it must never
 * decide whether CI is green. Run it on the real host:
 *
 *     CROW_BENCH=1 node --test tests/local-model-perf-bench.test.js
 *
 * What it times, per iteration, against an in-process loopback listener (the shape
 * a `providers` row names for a model on this box):
 *
 *   1. `isKnownLocalModelTarget` — the vouch: a Docker publish vouches the port, the
 *      LISTEN row is this process's own socket. This is where the /proc tables are
 *      read and parsed (once per pass), and where the candidate pid is found.
 *   2. `openVerifiedSocket` — the accepted connection, verified before a byte is
 *      written: a fresh /proc read after the connect, then the accept wait.
 *
 * The two numbers an operator cares about are `p50`/`p95` of the TOTAL, which is
 * what an own-host request pays once per connection. The measured targets (on the
 * development host) are ≤10 ms p50 for loopback and ≤20 ms p50 for a Docker-NATed
 * tailnet target; this file asserts only a catastrophe bound, so a loaded test box
 * reports numbers rather than a failure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { isKnownLocalModelTarget } from "../servers/gateway/models/local-model-servers.js";
import { openVerifiedSocket } from "../servers/gateway/models/verified-connect.js";

const RUN = process.env.CROW_BENCH === "1";
/** Iterations thrown away before measuring (JIT, caches, page cache). */
const WARMUP = 10;
/** Measured iterations. */
const SAMPLES = 50;

/** The p-th percentile of an unsorted sample list (nearest-rank). */
function percentile(samples, p) {
  const sorted = [...samples].sort((a, b) => a - b);
  const rank = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[rank];
}

const summary = (label, samples) =>
  `${label}: p50 ${percentile(samples, 50).toFixed(2)} ms, p95 ${percentile(samples, 95).toFixed(2)} ms (n=${samples.length})`;

test("bench (L1): own-host vouch + verified connect against an in-process loopback listener", {
  skip: RUN ? false : "set CROW_BENCH=1 to run the micro-benchmark",
}, async (t) => {
  const home = mkdtempSync(join(tmpdir(), "crow-bench-home-"));
  const server = http.createServer((_req, res) => res.end("ok"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const url = `http://127.0.0.1:${port}/v1/embeddings`;
  // An EMPTY Crow home (no bundle compose vouch, no pins) plus the one Docker
  // publish that vouches the port: the listener half is then what decides, with
  // this process holding the listening socket.
  const deps = { crowHome: home, dockerEntries: [{ address: "127.0.0.1", port, running: true }] };
  const vouch = [];
  const connect = [];
  const total = [];
  try {
    for (let i = 0; i < WARMUP + SAMPLES; i++) {
      const t0 = performance.now();
      const verdict = await isKnownLocalModelTarget(url, deps);
      const t1 = performance.now();
      let socket = null;
      try { socket = await openVerifiedSocket({ address: "127.0.0.1", port, deps }); } finally { try { socket?.destroy(); } catch { /* gone */ } }
      const t2 = performance.now();
      assert.equal(verdict.local, true, `the vouch must accept this process's own listener: ${JSON.stringify(verdict)}`);
      if (i < WARMUP) continue;
      vouch.push(t1 - t0);
      connect.push(t2 - t1);
      total.push(t2 - t0);
    }
    const lines = [
      summary("vouch (isKnownLocalModelTarget)", vouch),
      summary("verified connect (openVerifiedSocket)", connect),
      summary("TOTAL added latency per own-host request", total),
    ];
    for (const line of lines) {
      t.diagnostic(line);
      console.log(line);
    }
    // A catastrophe bound only: a regression that reintroduces a full /proc scan or
    // a whole-box fd sweep per request lands far above this, and a loaded test box
    // still reports its numbers instead of failing on a tight threshold.
    assert.ok(percentile(total, 50) <= 250, `per-request p50 ${percentile(total, 50).toFixed(2)} ms is far above the ≤10 ms target`);
  } finally {
    await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
    rmSync(home, { recursive: true, force: true });
  }
});