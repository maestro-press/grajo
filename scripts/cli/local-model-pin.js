#!/usr/bin/env node
/**
 * `local-model-pin` — the operator's OWN statement that a host address and port
 * is a model server Crow may forward to.
 *
 * The model door refuses an own-host provider row unless some source OUTSIDE
 * crow.db vouches for its address and port (servers/gateway/models/local-model-
 * servers.js): a Docker/compose publish, a live native-runtime reservation, or a
 * pin in this file. The file lives at
 * `<CROW_HOME>/secrets/local-model-endpoints.json`, a directory a bot sandbox is
 * never bound, is written 0600, and is the only thing a person has to touch when
 * they start a model server themselves (`llama-server --port 8004`, a vLLM in a
 * screen session, …).
 *
 * `exe` is the SERVER BINARY'S absolute path. It is not decoration: at forward
 * time the door also checks that the process holding the listening socket really
 * is running that executable in this gateway's own user namespace, so pinning a
 * path alone never blesses a bot's listener.
 *
 * A COMPOSE DIRECTORY pin (`add-compose`) is the other half: a Docker container
 * vouches a port only when its compose project directory is an AI-category Crow
 * bundle or a directory the operator pinned, and this is how a model the owner
 * runs from their own `docker compose` directory (not a Crow bundle) becomes one.
 * The directory must exist and is stored realpath'd; the container must carry
 * Docker compose's own `com.docker.compose.project.working_dir` label for it.
 *
 * A CONTAINER-NAME pin (`add-container`) is for a model container that carries no
 * compose label at all — a systemd unit running plain
 * `docker run --name flash-next-gufo -p 0.0.0.0:8030:8000 …`. Its published
 * bindings vouch exactly like an AI-bundle container's. The match is EXACT, against
 * Docker's name without the leading "/"; the listener half is unchanged (the
 * publish is what vouches the port, and docker-proxy is another uid). Container
 * names are not bot-controllable in the contain tier (no Docker API); the residual
 * is stated in LIMITS (local-model-servers.js): a docker-group bot in an
 * UNCONTAINED tier could remove a pinned container and reuse its NAME.
 *
 * Usage (run in the instance's own environment — CROW_HOME decides the file):
 *   node scripts/cli/local-model-pin.js add 127.0.0.1:8004 --exe /opt/llama.cpp/llama-server
 *   node scripts/cli/local-model-pin.js rm 127.0.0.1:8004
 *   node scripts/cli/local-model-pin.js add-compose /srv/models/my-own-vllm
 *   node scripts/cli/local-model-pin.js rm-compose /srv/models/my-own-vllm
 *   node scripts/cli/local-model-pin.js add-container flash-next-gufo
 *   node scripts/cli/local-model-pin.js rm-container flash-next-gufo
 *   node scripts/cli/local-model-pin.js --show
 *
 * --show prints `<address>:<port> <exe>` per endpoint pin, `compose <dir>` per
 * compose-directory pin and `container <name>` per container-name pin. `add`
 * replaces a pin for the same address and port; `add-compose` replaces a pin for
 * the same (realpath'd) directory; `add-container` replaces a pin for the same
 * name. There is no UI for this on purpose: it is a security decision, so it takes
 * a shell on the box.
 */
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { PIN_FILE, normalizeAddress, normalizeContainerName, pinFilePath } from "../../servers/gateway/models/local-model-servers.js";

const USAGE = `Usage:
  node scripts/cli/local-model-pin.js --show
  node scripts/cli/local-model-pin.js add <address:port> --exe <absolute server binary>
  node scripts/cli/local-model-pin.js rm <address:port>
  node scripts/cli/local-model-pin.js add-compose <absolute compose directory>
  node scripts/cli/local-model-pin.js rm-compose <absolute compose directory>
  node scripts/cli/local-model-pin.js add-container <docker container name>
  node scripts/cli/local-model-pin.js rm-container <docker container name>`;

/** `127.0.0.1:8004`, `100.64.20.5:8004`, `[::1]:8004` → `{address, port}` or null. */
export function parseEndpoint(text) {
  const raw = String(text ?? "").trim();
  if (!raw) return null;
  const v6 = /^\[([^\]]+)\]:(\d{1,5})$/.exec(raw);
  const v4 = /^([^:\s]+):(\d{1,5})$/.exec(raw);
  const m = v6 || v4;
  if (!m) return null;
  const address = normalizeAddress(m[1]);
  const port = Number(m[2]);
  if (!address || !Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { address, port };
}

const formatEndpoint = (e) => `${String(e.address).includes(":") ? `[${e.address}]` : e.address}:${e.port}`;

/**
 * A compose-directory argument as it may be STORED: the realpath of an existing
 * directory, or null (a relative path, a missing path, a file). The container's
 * `com.docker.compose.project.working_dir` label is a realpath'd project dir, so a
 * pin that is not one could never match.
 */
export function resolveComposeDir(text) {
  const raw = String(text ?? "").trim();
  if (!raw || !isAbsolute(raw)) return null;
  let real;
  try { real = realpathSync(raw); } catch { return null; }
  let st;
  try { st = statSync(real); } catch { return null; }
  if (!st || typeof st.isDirectory !== "function" || !st.isDirectory()) return null;
  return real;
}

/** The pins on disk, as an array (a malformed file reads as empty: never guessed at). */
function readPinFile(file) {
  let text;
  try { text = readFileSync(file, "utf8"); } catch { return []; }
  let parsed;
  try { parsed = JSON.parse(text); } catch { return []; }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.endpoints) ? parsed.endpoints : [];
  return list.filter((e) => e && typeof e === "object");
}

/** Write the pins atomically, 0600, in a 0700 secrets directory. */
function writePinFile(file, pins) {
  const dir = dirname(file);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.${PIN_FILE}.${process.pid}.tmp`);
  try {
    writeFileSync(tmp, `${JSON.stringify(pins, null, 2)}\n`, { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, file);
    chmodSync(file, 0o600);
  } catch (err) {
    try { rmSync(tmp, { force: true }); } catch { /* never written */ }
    throw err;
  }
}

/**
 * Run the CLI. Returns the exit code: 0 ok, 1 refused or bad input, 2 nothing
 * matched. Every dependency is a parameter so a test can run it in-process.
 */
export async function main({ argv = process.argv.slice(2), stdout = process.stdout, stderr = process.stderr } = {}) {
  const out = (s) => stdout.write(s);
  const fail = (s) => { stderr.write(`${s}\n`); return 1; };

  if (argv.includes("--help") || argv.includes("-h")) { out(`${USAGE}\n`); return 0; }

  // Fails with CROW_HOME_REQUIRED_IN_TESTS under `node --test` when this
  // instance's home would silently resolve to a real ~/.crow.
  const file = pinFilePath(resolveCrowHome());

  if (argv.length === 1 && argv[0] === "--show") {
    for (const e of readPinFile(file)) {
      if (typeof e.composeDir === "string") {
        const real = resolveComposeDir(e.composeDir);
        if (!real) continue;
        out(`compose ${real}\n`);
        continue;
      }
      const container = normalizeContainerName(e.container);
      if (container) { out(`container ${container}\n`); continue; }
      const parsed = { address: normalizeAddress(e.address), port: Number(e.port) };
      if (!parsed.address || !Number.isInteger(parsed.port)) continue;
      out(`${formatEndpoint(parsed)} ${typeof e.exe === "string" ? e.exe : ""}\n`.replace(/ \n$/, "\n"));
    }
    return 0;
  }

  const [verb, endpointArg, ...rest] = argv;

  // --- container-NAME pins (a plain `docker run` with no compose label) ---------
  if (verb === "add-container" || verb === "rm-container") {
    if (rest.length) return fail(`${verb} takes only a container name\n${USAGE}`);
    const name = normalizeContainerName(endpointArg);
    if (!name) return fail(`${verb} needs a docker container name (no "/", no spaces)\n${USAGE}`);
    const pins = readPinFile(file);
    const sameName = (e) => normalizeContainerName(e?.container) === name;
    if (verb === "rm-container") {
      const kept = pins.filter((e) => !sameName(e));
      if (kept.length === pins.length) return fail(`no container pin for ${name} (nothing was written)`);
      try { writePinFile(file, kept); } catch (err) { return fail(`could not write ${PIN_FILE}: ${err.message}`); }
      out(`unpinned container ${name}\n`);
      return 0;
    }
    const next = [...pins.filter((e) => !sameName(e)), { container: name }];
    try { writePinFile(file, next); } catch (err) { return fail(`could not write ${PIN_FILE}: ${err.message}`); }
    out(`container ${name}\n`);
    return 0;
  }

  // --- compose-directory pins (the other way a container may vouch) -------------
  if (verb === "add-compose" || verb === "rm-compose") {
    if (rest.length) return fail(`${verb} takes only an absolute compose directory\n${USAGE}`);
    const given = String(endpointArg ?? "").trim();
    if (!given || !isAbsolute(given)) return fail(`${verb} needs an absolute compose directory\n${USAGE}`);
    // `rm-compose` accepts a directory that has since been removed, so its pin can
    // still be taken away: the realpath is used when it resolves, the plain absolute
    // path otherwise.
    let real = resolveComposeDir(given);
    if (!real && verb === "add-compose") return fail(`${given} is not an existing directory (nothing was written)`);
    if (!real) real = given.replace(/\/+$/, "");
    const pins = readPinFile(file);
    const sameDir = (e) => typeof e?.composeDir === "string" && e.composeDir.trim().replace(/\/+$/, "") === real;
    if (verb === "rm-compose") {
      const kept = pins.filter((e) => !sameDir(e));
      if (kept.length === pins.length) return fail(`no compose pin for ${real} (nothing was written)`);
      try { writePinFile(file, kept); } catch (err) { return fail(`could not write ${PIN_FILE}: ${err.message}`); }
      out(`unpinned compose ${real}\n`);
      return 0;
    }
    const next = [...pins.filter((e) => !sameDir(e)), { composeDir: real }];
    try { writePinFile(file, next); } catch (err) { return fail(`could not write ${PIN_FILE}: ${err.message}`); }
    out(`compose ${real}\n`);
    return 0;
  }

  const endpoint = parseEndpoint(endpointArg);
  if (!verb || !endpoint || (verb !== "add" && verb !== "rm")) return fail(`give --show, add <address:port> --exe <path>, or rm <address:port>\n${USAGE}`);
  const pins = readPinFile(file);
  const sameEndpoint = (e) => normalizeAddress(e?.address) === endpoint.address && Number(e?.port) === endpoint.port;

  if (verb === "rm") {
    if (rest.length) return fail(`rm takes only <address:port>\n${USAGE}`);
    const kept = pins.filter((e) => !sameEndpoint(e));
    if (kept.length === pins.length) return fail(`no pin for ${formatEndpoint(endpoint)} (nothing was written)`);
    try { writePinFile(file, kept); } catch (err) { return fail(`could not write ${PIN_FILE}: ${err.message}`); }
    out(`unpinned ${formatEndpoint(endpoint)}\n`);
    return 0;
  }

  let exe = null;
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--exe") { exe = rest[i + 1]; i++; continue; }
    if (rest[i].startsWith("--exe=")) { exe = rest[i].slice("--exe=".length); continue; }
    return fail(`unexpected argument ${JSON.stringify(rest[i])}\n${USAGE}`);
  }
  if (typeof exe !== "string" || !exe.trim()) return fail(`add needs --exe <absolute path of the server binary> (nothing was written)`);
  if (!isAbsolute(exe.trim())) return fail(`--exe must be an absolute path (nothing was written)`);
  const entry = { address: endpoint.address, port: endpoint.port, exe: exe.trim() };
  const next = [...pins.filter((e) => !sameEndpoint(e)), entry];
  try { writePinFile(file, next); } catch (err) { return fail(`could not write ${PIN_FILE}: ${err.message}`); }
  if (!existsSync(entry.exe)) {
    // Not a refusal: an operator may pin before installing the binary. Said out
    // loud, because the forward will only pass once that file is what listens.
    stderr.write(`note: ${entry.exe} does not exist yet — the pin holds, but a forward needs that binary to be the listening process\n`);
  }
  out(`${formatEndpoint(entry)} ${entry.exe}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`FAIL: ${err?.message || err}`);
    process.exit(1);
  });
}