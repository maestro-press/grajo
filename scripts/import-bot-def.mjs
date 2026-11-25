#!/usr/bin/env node
// import-bot-def.mjs — apply a version-controlled bots/<bot_id>.json snapshot
// back into pi_bot_defs (UPSERT). Inverse of export-bot-def.mjs. Re-stringifies
// the expanded `definition` object. created_at/updated_at default in-DB.
//
// Usage: node scripts/import-bot-def.mjs <bot_id> [--check]
import Database from "better-sqlite3";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { sqliteDbFacade, writeBotDef } from "../servers/shared/bot-def-store.js";

const DB_PATH = process.env.CROW_DB_PATH || join(homedir(), ".crow-mpa/data/crow.db");
const REPO = dirname(dirname(fileURLToPath(import.meta.url)));
const botId = process.argv[2];
const checkOnly = process.argv.includes("--check");
if (!botId) { console.error("Usage: node scripts/import-bot-def.mjs <bot_id> [--check]"); process.exit(1); }

const path = join(REPO, "bots", `${botId}.json`);
const data = JSON.parse(readFileSync(path, "utf8"));
const definition = typeof data.definition === "string" ? data.definition : JSON.stringify(data.definition);

if (checkOnly) {
  console.log(`Would upsert bot_id='${data.bot_id}' (definition ${definition.length} chars, enabled=${data.enabled}, project_id=${data.project_id ?? "null"}) into ${DB_PATH}`);
  process.exit(0);
}

const db = new Database(DB_PATH);
db.pragma("busy_timeout = 10000");
// The ONE write path (servers/shared/bot-def-store.js): the row carries a keyed MAC over its whole
// definition and a replay generation, so an import signs exactly like an owner save does. An
// upsert is an update when the row exists and an insert when it does not.
//
// `ownerFullReplace` is what makes an import able to REPLACE a row no key holder could verify: the
// file IS a complete definition (enabled and project_id included), supplied whole by the operator, so
// nothing is taken from the existing row. Without it the store refuses that write (BOT_DEF_UNVERIFIED)
// rather than re-sealing content it could not verify.
const existing = db.prepare("SELECT bot_id FROM pi_bot_defs WHERE bot_id=?").get(data.bot_id);
await writeBotDef(sqliteDbFacade(db), {
  bot_id: data.bot_id,
  display_name: data.display_name,
  definition,
  enabled: data.enabled ?? 1,
  project_id: data.project_id ?? null,
  mode: existing ? "update" : "insert",
  ownerFullReplace: true,
});
db.close();
console.log(`Imported ${botId} from ${path}`);
