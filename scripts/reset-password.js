#!/usr/bin/env node

/**
 * Reset the Crow's Nest dashboard password (self-hosted).
 *
 * Usage: npm run reset-password
 *   or:  node scripts/reset-password.js
 */

import { createInterface } from "node:readline";
import { scrypt, randomBytes } from "node:crypto";
import { createClient } from "@libsql/client";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolveCrowHome } from "../servers/shared/crow-home.js";
import { writePasswordSetMarker } from "../servers/gateway/dashboard/password-set-marker.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function resolveDbPath() {
  if (process.env.CROW_DB_PATH) return process.env.CROW_DB_PATH;
  const crowDataDir = resolve(homedir(), ".crow", "data");
  if (existsSync(resolve(crowDataDir, "crow.db"))) return resolve(crowDataDir, "crow.db");
  const localPath = resolve(__dirname, "..", "data", "crow.db");
  if (existsSync(localPath)) return localPath;
  console.error("Could not find crow.db. Set CROW_DB_PATH or run 'npm run init-db' first.");
  process.exit(1);
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = randomBytes(16).toString("hex");
    scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      else resolve(`${salt}:${key.toString("hex")}`);
    });
  });
}

function prompt(question, hidden = false) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    if (hidden && process.stdin.isTTY) {
      process.stdout.write(question);
      const stdin = process.stdin;
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding("utf8");
      let input = "";
      const onData = (ch) => {
        if (ch === "\n" || ch === "\r") {
          stdin.setRawMode(false);
          stdin.removeListener("data", onData);
          process.stdout.write("\n");
          rl.close();
          resolve(input);
        } else if (ch === "\u0003") {
          // Ctrl+C
          process.exit(0);
        } else if (ch === "\u007F" || ch === "\b") {
          // Backspace
          input = input.slice(0, -1);
        } else {
          input += ch;
        }
      };
      stdin.on("data", onData);
    } else {
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer);
      });
    }
  });
}

async function main() {
  console.log("Crow's Nest — Password Reset\n");

  const dbPath = resolveDbPath();
  console.log(`Database: ${dbPath}\n`);

  const password = await prompt("New password (12+ characters): ", true);
  if (!password || password.length < 12) {
    console.error("Password must be at least 12 characters.");
    process.exit(1);
  }

  const confirm = await prompt("Confirm password: ", true);
  if (password !== confirm) {
    console.error("Passwords don't match.");
    process.exit(1);
  }

  const hash = await hashPassword(password);

  await writePasswordRecord(dbPath, hash);
  console.log("\nPassword reset successfully. You can now log in.");
}

/**
 * Write the new password hash, then record it where crow.db cannot reach.
 *
 * A reset is a password being SET: the marker in <CROW_HOME>/secrets
 * (password-set-marker.js) is written right after the row. Without it a
 * deleted/never-written password row would make the dashboard look un-set-up
 * and re-open first-run setup. The home is resolved exactly as the gateway
 * resolves it (CROW_HOME → ~/.crow), so a reset run for another instance must
 * carry that instance's CROW_HOME.
 *
 * Exported so the write path can be tested without the interactive prompts.
 */
export async function writePasswordRecord(dbPath, hash) {
  const db = createClient({ url: `file:${dbPath}` });
  try {
    await db.execute({
      sql: "INSERT INTO dashboard_settings (key, value, updated_at) VALUES ('password_hash', ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')",
      args: [hash, hash],
    });
    writePasswordSetMarker({ crowHome: resolveCrowHome() });
  } finally {
    db.close();
  }
}

// Only run the prompts when this file IS the program (`npm run reset-password`),
// never when a test imports the write path above.
//
// Both sides are compared as REAL paths: Node resolves import.meta.url through
// symlinks, so resolving argv[1] alone (e.g. `node bin/reset-password.js` when
// bin/ or the script is a symlink) left the two unequal and the script exited 0
// having done nothing. If the comparison itself fails, run main(): argv[1] that
// cannot be resolved is this program being run in a way we cannot verify, and
// staying silent is the worse failure.
const invokedDirectly = (() => {
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return true;
  }
})();
if (invokedDirectly) {
  main().catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
}
