/**
 * The uuid a NEW row gets at insert time.
 *
 * scripts/init-db.js adds `uuid` as a nullable column (addUuidColumn) and backfills the
 * rows that exist with `lower(hex(randomblob(16)))`, then puts a UNIQUE index on it.
 * SQLite cannot give the column a default expression of its own, so every runtime INSERT
 * that creates a row has to supply one — otherwise the row stays uuid-less until the next
 * init-db run, and sync / cross-peer sharing (which key on uuid) cannot see it.
 *
 * The format is init-db's: 16 random bytes as 32 lowercase hex characters.
 *
 * This is only for the case where the row has no uuid of its own. A uuid that arrives
 * WITH the row (a bundle source, a peer's copy) is that row's identity and must be kept
 * exactly as it came.
 */
import { randomBytes } from "node:crypto";

/** @returns {string} 32 lowercase hex characters, the shape init-db's backfill writes. */
export function newRowUuid() {
  return randomBytes(16).toString("hex");
}
