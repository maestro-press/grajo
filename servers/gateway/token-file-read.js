/**
 * ONE hardened reader for the raw token files the static-token families keep on disk
 * (`<CROW_HOME>/board-token`, `--phone-token`, `secrets/peer-relay-token`, the kiosk announce
 * token, …). Every path here is inside something a bot shell can write, so "read the file" is
 * never a plain `readFileSync`:
 *
 *   - it is OPENED with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`: a SYMLINK fails (ELOOP) instead of
 *     being followed, and a FIFO with no writer fails (ENXIO) instead of PARKING the caller — the
 *     caller of this module includes the pre-listen settings-token boot, so a planted FIFO would
 *     otherwise hang the gateway before it ever listened;
 *   - the fd itself is what is judged (`fstat`): anything that is not a regular file (a FIFO, a
 *     socket, a device, a directory) is refused BEFORE a single byte is read;
 *   - the read is CAPPED at 4 KiB (`MAX_TOKEN_FILE_BYTES`): a real token file holds 64 hex
 *     characters, so a bigger file is not one this instance wrote;
 *   - and the token is read FROM THAT SAME FD, so the bytes judged (owner, mode, kind, size) are
 *     the bytes returned — there is no check-then-read gap in which a racer could swap the path.
 *
 * A refusal is never an exception: callers get `{ ok: false, reason }`. What a refusal MEANS is
 * the caller's rule — the boot converter treats it as "no trustworthy proof" (the value is
 * refused, never converted), and `local-token.js` treats it as a DEFINITE mismatch (the family is
 * re-minted), which is separate from "the verifier could not answer" (`null`, never a re-mint).
 *
 * HOST-ONLY (it is reached from the boot converter and from `local-token.js`, beside the HMAC
 * key): `tests/bot-seed-import-guard.test.js` keeps that in step.
 */
import {
  closeSync, constants, fstatSync, openSync, readSync,
} from "node:fs";

/**
 * The largest file a raw token may live in. A 32-byte hex token is 64 characters, a stored `h1.`
 * MAC 87, so 4 KiB is already generous: anything larger is not a token file this instance wrote
 * and is refused unread.
 */
export const MAX_TOKEN_FILE_BYTES = 4096;

/**
 * Read `path` as a token file, hardened (see the module header).
 *
 * @param {string} path
 * @returns {{ok: true, token: string, stat: object}
 *          | {ok: false, reason: "open"|"not-regular"|"oversize"|"read"}}
 *          `token` is the file's trimmed contents; `stat` is the fstat of the very fd the token
 *          came from, so a caller that needs more (owner, mode, the parent directory) judges the
 *          bytes it is about to use. Never throws.
 */
export function readHardenedTokenFile(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    return { ok: false, reason: "open" }; // missing, a symlink (ELOOP), a FIFO (ENXIO), unreadable
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) return { ok: false, reason: "not-regular" };
    if (stat.size > MAX_TOKEN_FILE_BYTES) return { ok: false, reason: "oversize" };
    // One byte PAST the cap, so a file that grew after the fstat (a writer active mid-read) is
    // refused as oversized rather than silently truncated into a token.
    const buffer = Buffer.alloc(MAX_TOKEN_FILE_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const read = readSync(fd, buffer, total, buffer.length - total, null);
      if (read <= 0) break;
      total += read;
    }
    if (total > MAX_TOKEN_FILE_BYTES) return { ok: false, reason: "oversize" };
    return { ok: true, token: buffer.toString("utf8", 0, total).trim(), stat };
  } catch {
    return { ok: false, reason: "read" };
  } finally {
    try { closeSync(fd); } catch { /* already closed: nothing to do */ }
  }
}