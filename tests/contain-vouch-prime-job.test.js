// End-to-end regression for a JOB's first contained spawn with a COLD vouch cache.
//
// A contained spawn decides its provider doors synchronously inside `new PiRpc`, from the local-model
// vouch cache. In a fresh non-gateway process (the job runner) the Docker half of that cache is empty,
// so a model server only a Docker container vouches for read "not-vouched" on the FIRST spawn and the
// turn failed with `contain refused: provider <id> has no door`. handleInbound now awaits
// ensureLocalModelVouch() first. This file drives the real path (bridge.handleInbound with job_runner's card-job payload
// -> contained PiRpc -> stub pi) with a FAKE `docker` first on PATH, so the real default docker runner
// (execFile "docker") is what fills the cache. This test process is fresh: the cache is cold at start.
import "./helpers/pi-scratch-home.mjs";
import { markBotDefPreEra } from "./helpers/bot-def-pre-era.mjs";
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, realpathSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";
import { probePiSandbox, _resetPiSandboxForTest } from "../scripts/pi-bots/pi_sandbox.mjs";

const REPO = resolve(import.meta.dirname, "..");
_resetPiSandboxForTest();
const SANDBOX = probePiSandbox({ force: true });
const skip = SANDBOX.ok ? false : "bubblewrap unavailable: " + SANDBOX.reason;

const dir = realpathSync(mkdtempSync(join(tmpdir(), "contain-vouch-prime-job-")));
process.env.CROW_DATA_DIR = join(dir, "data");
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
mkdirSync(process.env.CROW_HOME, { recursive: true });
mkdirSync(process.env.CROW_DATA_DIR, { recursive: true });
markBotDefPreEra(process.env.CROW_HOME);
process.env.PIBOT_MAX_PI = "99";
process.env.PIBOT_WARM_GATEWAY_URL = "http://127.0.0.1:1";
process.env.PIBOT_WARM_TIMEOUT_MS = "1500";
process.env.PIBOT_PROMPT_ACK_TIMEOUT_MS = "4000";

const PORT = 18097;
const BUNDLE = "vouch-prime-llm";
const PROVIDER = "vouch-prime-prov";
const BOT = "vouch-prime-bot";
const bundleDir = join(process.env.CROW_HOME, "bundles", BUNDLE);
// An AI-category bundle dir with NO compose file: only a Docker container can vouch for its port.
mkdirSync(bundleDir, { recursive: true });
writeFileSync(join(bundleDir, "manifest.json"), JSON.stringify({ id: BUNDLE, category: "ai" }));

// A fake `docker` first on PATH: `ps -aq --no-trunc` lists one id, `inspect --format ...` answers one
// JSON line in the shape DOCKER_INSPECT_FORMAT produces. PATH is set BEFORE bridge/job_runner import.
const binDir = join(dir, "bin");
mkdirSync(binDir);
const record = JSON.stringify({
  id: "c0ffee", name: "/vouch-prime", running: true,
  labels: { "com.docker.compose.project.working_dir": bundleDir },
  ports: { [`${PORT}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(PORT) }] },
});
writeFileSync(join(binDir, "docker"), [
  "#!/bin/sh",
  'if [ "$1" = "ps" ]; then echo c0ffee; exit 0; fi',
  `if [ "$1" = "inspect" ]; then echo '${record}'; exit 0; fi`,
  "exit 1", "",
].join("\n"));
chmodSync(join(binDir, "docker"), 0o755);
process.env.PATH = binDir + ":" + process.env.PATH;

// Stub pi: proves it was spawned by writing a marker into the bot's one write path, then exits.
const OUT = join(dir, "out");
mkdirSync(OUT);
const STUB_PI = join(dir, "stub-pi.mjs");
writeFileSync(STUB_PI,
  'import { writeFileSync } from "node:fs";\n' +
  `try { writeFileSync(${JSON.stringify(join(OUT, "spawned.txt"))}, "yes"); } catch {}\n` +
  'console.error("stub pi: exiting");\nprocess.exit(9);\n');
process.env.PIBOT_PI_CLI = STUB_PI;
process.env.CROW_PI_CONTAIN_BOTS = BOT;
delete process.env.CROW_PI_SANDBOX;

const DB_FILE = join(process.env.CROW_DATA_DIR, "crow.db");
const raw = () => new Database(DB_FILE);

before(() => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });
  const c = raw();
  c.prepare("INSERT OR REPLACE INTO providers (id, base_url, models, host, disabled, bundle_id) VALUES (?, ?, ?, 'local', 0, ?)")
    .run(PROVIDER, `http://127.0.0.1:${PORT}/v1`, JSON.stringify([{ id: "m1" }]), BUNDLE);
  const def = {
    gateways: [{ type: "board" }],
    tools: { pi_builtin: ["read"], crow_mcp: [] },
    models: { default: `${PROVIDER}/m1` },
    permission_policy: { multi_agent: false, bash: "deny", write_paths: [OUT] },
    session_dir: join(dir, "bots", BOT),
  };
  c.prepare("INSERT OR REPLACE INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES (?,?,?,?)")
    .run(BOT, "Vouch Prime Bot", JSON.stringify(def), 1);
  c.close();
});
after(() => rmSync(dir, { recursive: true, force: true }));

test("a job's FIRST contained spawn with a cold vouch cache is not refused for 'has no door'", { skip, timeout: 90000 }, async () => {
  // Cold by construction: this test process has not touched the vouch cache (probing it here would itself
  // start a background Docker read and defeat the point).
  // job_runner's card branch calls bridge.handleInbound in-process (runCardExecute); driving runJob itself
  // needs the card tables of the tasks store, which this scratch instance does not carry, so this drives
  // handleInbound with the same payload shape (board gateway, card thread, job_id) directly.
  const { handleInbound } = await import("../scripts/pi-bots/bridge.mjs");
  const logs = [];
  const replies = [];
  let err = null;
  try {
    const r = await handleInbound({
      bot_id: BOT, gateway_type: "board", gateway_thread_id: "job-vouch-prime-thread",
      user_message: "do the job", job_id: "job-vouch-prime-1",
      log: (m) => logs.push(String(m)), sendReply: async (t) => { replies.push(String(t)); },
    });
    if (r && r.error) logs.push(String(r.error));
  } catch (e) { err = e; }
  const text = [err && err.message, ...logs, ...replies].filter(Boolean).join("\n");
  assert.doesNotMatch(text, /has no door/, "the first contained spawn was not refused: " + text);
  assert.ok(existsSync(join(OUT, "spawned.txt")), "the stub pi was actually spawned inside the contain tier: " + text);
});
