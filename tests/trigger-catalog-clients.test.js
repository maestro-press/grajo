/**
 * THE TRIGGER READ MUST WORK ON BOTH DB CLIENTS (round I, item I2's read).
 *
 * `writeBotDef` (`servers/shared/bot-def-store.js`) refuses a write while `pi_bot_defs` carries a
 * trigger Crow did not install, and it decides that from one SELECT over `sqlite_master` and
 * `sqlite_temp_master` (`servers/shared/trigger-catalog.js` `readTriggerRows`). That read runs on the
 * handle the CALLER holds, and Crow writes bot definitions through two different clients:
 *
 *   - `createDbClient` (better-sqlite3, the gateway and every host path), and
 *   - `@libsql/client` (a bundle's own handle — `bundles/studio/server/give-tools.js` writes a
 *     definition through the seam with one).
 *
 * A client that could not answer this query would make the write refuse on every call ("cannot tell"
 * is fail-closed by design), so the two are pinned here, side by side, on the same schema.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";

import { createDbClient } from "../servers/db.js";
import {
  TRIGGER_ROWS_SQL, expectedTriggersOnTable, readTriggerRows, unexpectedTriggers,
} from "../servers/shared/trigger-catalog.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const roots = [];
after(() => {
  for (const root of roots) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** A scratch instance with the real schema, so `pi_bot_defs` and its history triggers are real. */
function scratch() {
  const home = mkdtempSync(join(tmpdir(), "crow-trigger-clients-"));
  roots.push(home);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "instance-id"), "0123456789abcdef0123456789abcdef", { mode: 0o600 });
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = join(dataDir, "crow.db");
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: process.env, cwd: ROOT, stdio: "pipe", timeout: 120_000,
  });
  return { home, dataDir, path: process.env.CROW_DB_PATH };
}

test("the trigger read answers on better-sqlite3 and on @libsql/client alike", async () => {
  const s = scratch();
  const sqlite = createDbClient(s.path);
  const libsql = createClient({ url: `file:${s.path}` });
  try {
    await sqlite.execute({ sql: "CREATE TRIGGER spy_ai AFTER INSERT ON pi_bot_defs BEGIN SELECT 1; END", args: [] });
    for (const [label, db] of [["better-sqlite3", sqlite], ["@libsql/client", libsql]]) {
      // eslint-disable-next-line no-await-in-loop -- one client at a time, same database
      const { rows, error } = await readTriggerRows(db);
      assert.equal(error, null, `${label} answered ${TRIGGER_ROWS_SQL}`);
      // eslint-disable-next-line no-await-in-loop
      const onTable = rows.filter((row) => String(row?.tbl_name ?? "") === "pi_bot_defs");
      assert.deepEqual(
        unexpectedTriggers(onTable, expectedTriggersOnTable("pi_bot_defs")).map((t) => t.name),
        ["spy_ai"],
        `${label} sees the foreign trigger on pi_bot_defs`,
      );
    }
  } finally {
    try { libsql.close(); } catch { /* closed */ }
    try { sqlite.close(); } catch { /* closed */ }
  }
});