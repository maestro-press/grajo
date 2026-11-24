// Fixture side of the satellite ADDRESS PIN (servers/shared/satellite-pins.js).
//
// A satellite row may only be dialled at the host pinned OUTSIDE crow.db, so every fixture row a
// test expects to reach its fake satellite needs a pin. This helper gives each test FILE its own
// pin store (per pid, under the file's scratch CROW_HOME) the first time a file pins a row, so a
// parallel test file can never see or overwrite these pins, and exposes one call to pin a row.
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { pinSatelliteHost } from "../../servers/shared/satellite-pins.js";

function ensureStorePath() {
  if (!process.env.CROW_SATELLITE_PINS_PATH) {
    const home = process.env.CROW_HOME;
    if (!home) throw new Error("a satellite fixture needs CROW_HOME (the suite sets a scratch one)");
    const dir = join(home, "secrets");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    process.env.CROW_SATELLITE_PINS_PATH = join(dir, `satellite-pins-fixture-${process.pid}.json`);
    if (!process.env.CROW_SATELLITE_PIN_BACKFILL_PATH) {
      process.env.CROW_SATELLITE_PIN_BACKFILL_PATH = join(dir, `satellite-pin-backfill-fixture-${process.pid}.json`);
    }
  }
  return process.env.CROW_SATELLITE_PINS_PATH;
}

/** Pin a fixture row's host (call it wherever a test creates a row it will dial). Returns the id. */
export function pinFixtureSatellite(satId, host) {
  ensureStorePath();
  if (!pinSatelliteHost(satId, host)) {
    throw new Error(`fixture pin refused for ${satId} (the fixture host is not a satellite address)`);
  }
  return satId;
}