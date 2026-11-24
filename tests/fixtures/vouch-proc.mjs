/**
 * A fake `/proc` for the VOUCH rules (`servers/gateway/models/local-model-servers.js`):
 * `net/tcp` LISTEN rows with a chosen uid and address, so a test can say "a Docker
 * container's docker-proxy holds this port as ROOT" (uid 0 — trusted without any
 * pid lookup) or "the gateway's own uid holds it" (not trusted without a pid that
 * Crow started) without a container and without touching the real /proc.
 *
 * Only IPv4 rows are produced; that is what every prod shape needs (a container
 * publishing `127.0.0.1:8004`, a wildcard `0.0.0.0:8880`, a tailnet
 * `100.64.20.x:8004`). `net/tcp6` is written with its header only.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HEADER4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const HEADER6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

/** The kernel's hex spelling of an IPv4 address (one 32-bit word, little-endian). */
export const v4Hex = (dotted) => String(dotted)
  .split(".")
  .reverse()
  .map((n) => Number(n).toString(16).padStart(2, "0"))
  .join("")
  .toUpperCase();

/** One `/proc/net/tcp` LISTEN row. */
function procRow({ address, port, uid, inode }) {
  const p = Number(port).toString(16).toUpperCase().padStart(4, "0");
  const hex = address === "0.0.0.0" ? "00000000" : v4Hex(address);
  return `   0: ${hex}:${p} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 ${String(uid).padStart(5)}        0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

/**
 * Write a fake proc root.
 * @param {{rows?: Array<{address:string, port:number, uid:number}>, base?:string}} opts
 * @returns {string} the root path (callers remove it in `after`)
 */
export function fakeProcRoot({ rows = [], base = tmpdir() } = {}) {
  const root = mkdtempSync(join(base, "crow-vouch-proc-"));
  mkdirSync(join(root, "net"), { recursive: true });
  writeFileSync(join(root, "net", "tcp"), HEADER4 + rows.map((r, i) => procRow({ inode: 9001 + i, ...r })).join("\n") + (rows.length ? "\n" : ""));
  writeFileSync(join(root, "net", "tcp6"), HEADER6);
  return root;
}

/** A resolver that answers one loopback address for every name it is asked about
 * (a test never wants the sandbox's DNS for `localhost`). */
export function loopbackLookup(host, options, cb) {
  const done = typeof options === "function" ? options : cb;
  return done(null, [{ address: "127.0.0.1", family: 4 }]);
}