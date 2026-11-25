/**
 * `<CROW_HOME>/secrets` (or any secrets-shaped directory) made 0700, owner-only.
 *
 * SPLIT OUT OF `servers/shared/peer-credentials.js` ON PURPOSE. Two of the modules that keep a
 * key on disk — `token-mac.js` (the keyed-hash key) and `bot-def-mac.js` (the bot-definition
 * generations file, which lives beside that key) — only ever needed this one filesystem helper from
 * there. Importing the whole credential store from them put `peer-credentials.js` (which reads a
 * peer's bearer token) into the import graph of the SEPARATE bot host processes (`pibot-bridge@`,
 * `pibot-gateways@`), whose whole contract is that they never hold a peer key and never read that
 * store (`tests/no-peer-key-in-bot-process.test.js` walks the graph and fails on it). A tiny module
 * with no dependencies keeps that graph clean without weakening anything: the helper creates a
 * directory and tightens its mode.
 *
 * peer-credentials.js re-exports this, so every existing importer keeps working unchanged.
 */
import { chmodSync, mkdirSync, statSync } from "node:fs";

/** Create `<dir>` 0700 (or tighten an existing one we own). Never throws. */
export function ensureSecretsDir(dir) {
  try { mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { /* exists, or a read-only view */ }
  try {
    const st = statSync(dir);
    if (st.uid === process.getuid?.() && (st.mode & 0o777) !== 0o700) chmodSync(dir, 0o700);
  } catch { /* best effort; a read-only view (inside the pi sandbox) is fine */ }
}