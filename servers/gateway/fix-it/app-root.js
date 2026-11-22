/**
 * The app checkout the gateway runs from — the directory that holds `scripts/`.
 *
 * The Caddy detectors build the fix command the card shows from it, and so does
 * the view-time renderer (fix-it/card-copy.js): the card's `{fixCommand}` is
 * RECOMPUTED from code, never read from crow.db. One definition, so the command
 * a detector stores and the command a stored card renders can never disagree.
 */
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The repository root (this file lives at <root>/servers/gateway/fix-it/). */
export function appRoot() {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
}