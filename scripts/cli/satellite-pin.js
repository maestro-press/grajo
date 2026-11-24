#!/usr/bin/env node
/**
 * `satellite-pin` — show or re-pin the ADDRESS this instance dials a satellite at.
 *
 * A satellite request carries an ed25519 management-key signature and a request BODY (an add-on's
 * env values, a bot's tool arguments, a whole encrypted backup), and it goes only to the host
 * recorded in <CROW_HOME>/secrets/satellite-pins.json at pairing. That store is hidden from bot
 * sandboxes, while `satellites.tailnet_host` is bot-writable and therefore never authorizes a
 * destination. When a satellite LEGITIMATELY moves (re-joined the tailnet under a new name), every
 * sender refuses with "satellite is not at its paired address" until the owner re-pins it here.
 *
 * Usage (run in this instance's own environment: CROW_HOME, and CROW_SATELLITE_PINS_PATH when the
 * store lives somewhere of its own):
 *   node scripts/cli/satellite-pin.js --show
 *   node scripts/cli/satellite-pin.js <satellite-id> <host>
 *
 * <host> is a BARE host only (a MagicDNS name or a tailnet address): a URL, a port, a path or
 * userinfo is refused, and the refusal never echoes the input. The id must be a satellite this
 * instance knows (a row in crow.db, or an existing pin); a pin never invents a satellite.
 *
 * --show prints one line per satellite known to the pin store or the db:
 *   <satellite-id> <pinned_host|none> [revoked] [row-differs]
 * `row-differs` means the row's tailnet_host does not normalize to the pin — the row's address is
 * NEVER printed, and no runnable command is built from it (a bot can write that row).
 *
 * This CLI NEVER writes crow.db: it opens it read-only (and only to decide whether an id is a
 * satellite this instance knows). It resolves Crow home through servers/shared/crow-home.js, so
 * under `node --test` with no CROW_HOME it refuses instead of touching a real ~/.crow.
 */
import { pathToFileURL } from "node:url";
import Database from "better-sqlite3";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { resolveDbPath } from "../../servers/db.js";
import { isSatelliteId } from "../../servers/shared/satellite-protocol.js";
import {
  getSatellitePin,
  listSatellitePins,
  normalizeSatelliteHost,
  pinSatelliteHost,
} from "../../servers/shared/satellite-pins.js";

const USAGE = `Usage:
  node scripts/cli/satellite-pin.js --show
  node scripts/cli/satellite-pin.js <satellite-id> <host>`;

const ROW_COLS = "id, status, tailnet_host";

/**
 * This instance's satellite rows, read through a READ-ONLY handle (a missing file or table is just
 * "no rows"). Never writes, never creates the database.
 */
function readRows() {
  let db = null;
  try {
    db = new Database(resolveDbPath(), { readonly: true, fileMustExist: true });
    db.pragma("busy_timeout = 5000");
    return db.prepare(`SELECT ${ROW_COLS} FROM satellites`).all();
  } catch {
    return [];
  } finally {
    try { db?.close(); } catch { /* gone */ }
  }
}

/**
 * Run the CLI. Returns the exit code: 0 ok, 1 refused or bad input.
 */
export async function main({ argv = process.argv.slice(2), stdout = process.stdout, stderr = process.stderr } = {}) {
  const out = (s) => stdout.write(s);
  const fail = (s) => { stderr.write(`${s}\n`); return 1; };

  if (argv.includes("--help") || argv.includes("-h")) { out(`${USAGE}\n`); return 0; }

  // Fails with CROW_HOME_REQUIRED_IN_TESTS under `node --test` when this instance's home would
  // silently resolve to a real ~/.crow.
  resolveCrowHome();

  const rows = readRows();
  const rowsById = new Map(rows.map((r) => [r.id, r]));

  if (argv.length === 1 && argv[0] === "--show") {
    const pins = new Map(listSatellitePins().map((p) => [p.id, p.host]));
    const ids = [...new Set([...pins.keys(), ...rowsById.keys()])].sort();
    for (const id of ids) {
      const pin = pins.get(id) || "none";
      const parts = [id, pin];
      const row = rowsById.get(id);
      if (row?.status === "revoked") parts.push("revoked");
      // A row that points somewhere else is named, but its address is not: a bot can write it.
      if (pin !== "none" && row && normalizeSatelliteHost(row.tailnet_host) !== pin) parts.push("row-differs");
      out(`${parts.join(" ")}\n`);
    }
    return 0;
  }

  const [satelliteId, host, ...rest] = argv;
  if (rest.length || !satelliteId || !host) return fail(`give --show, or <satellite-id> <host>\n${USAGE}`);
  if (!isSatelliteId(satelliteId)) return fail("that is not a valid satellite id; nothing was written");
  // A refusal never echoes what was typed: the input may itself be a bot-chosen address.
  const normalized = normalizeSatelliteHost(host);
  if (!normalized) return fail("that is not a usable satellite host (a bare MagicDNS name or tailnet address is required); nothing was written");

  if (!rowsById.has(satelliteId) && !getSatellitePin(satelliteId)) {
    return fail("this instance knows no such satellite; pair it first (nothing was written)");
  }
  if (!pinSatelliteHost(satelliteId, normalized)) return fail("could not write the pin; nothing was written");
  out(`${satelliteId}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`FAIL: ${err?.code || "error"}`);
    process.exit(1);
  });
}