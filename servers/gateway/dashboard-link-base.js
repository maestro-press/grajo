/**
 * The base URL a dashboard link in a mail or a push notification is built on.
 *
 * WHY THIS IS NOT `CROW_GATEWAY_URL`: that variable is this instance's PUBLIC address — on a Tailscale
 * install it is the Funnel origin on port 443, which serves only the paths in PUBLIC_FUNNEL_PREFIXES
 * (`servers/gateway/funnel.js`) and answers 404 for `/dashboard`. The dashboard lives on its own
 * tailnet-only HTTPS port (Tailscale Serve, e.g. `:8444`). A report email that says "open this report"
 * on the Funnel origin is a dead link, and so is a push notification's tap target.
 *
 * THE ORDER, first usable value wins:
 *   1. `CROW_DASHBOARD_URL` — the operator's explicit answer, when it is an http(s) URL with a host.
 *   2. this instance's own `crow_instances.gateway_url` — the address the instance advertises for
 *      browsers and peer calls. A wildcard bind (`0.0.0.0`, `[::]`) or a loopback address is skipped:
 *      a reader of the email is not on this machine, so loopback points at their own box.
 *   3. `CROW_GATEWAY_URL` — the public address, the right answer on a deployment whose public origin
 *      does serve the dashboard (no Funnel in front of it).
 *
 * An unusable value at one step falls through to the next; nothing here throws, and "" means "this
 * instance does not know an address a reader could open".
 */
import { getInstance, getOrCreateLocalInstanceId } from "./instance-registry.js";

/** The bind hosts that are never an address a reader can open. */
const WILDCARD_HOSTS = Object.freeze(["0.0.0.0", "[::]"]);

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** A hostname with its IPv6 brackets removed, lower-cased. */
function bareHost(hostname) {
  return text(hostname).replace(/^\[|\]$/g, "").toLowerCase();
}

/** Is this hostname a loopback address (useless in a mail: it reaches the READER's own machine)? */
function isLoopbackHost(hostname) {
  const host = bareHost(hostname);
  return host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127\./.test(host);
}

/**
 * The base a raw value names, or "" when it names none: an http(s) URL with a host, its origin and
 * path, no trailing slashes. `allowLoopback: false` also refuses loopback and wildcard bind hosts.
 *
 * @param {*} raw
 * @param {{allowLoopback?: boolean}} [opts]
 * @returns {string}
 */
function baseOf(raw, { allowLoopback = true } = {}) {
  const given = text(raw).trim();
  if (!given) return "";
  let parsed;
  try {
    parsed = new URL(given);
  } catch {
    return "";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
  if (!parsed.hostname) return "";
  if (WILDCARD_HOSTS.includes(parsed.hostname)) return "";
  if (!allowLoopback && isLoopbackHost(parsed.hostname)) return "";
  return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, "");
}

/** This instance's own registered `gateway_url`, or "" (no db, no row, an unreadable row, a bad value). */
async function ownRowBase(db, localInstanceId) {
  if (db == null) return "";
  try {
    const id = localInstanceId ?? getOrCreateLocalInstanceId();
    const row = await getInstance(db, id);
    return baseOf(row == null ? "" : row.gateway_url, { allowLoopback: false });
  } catch {
    return "";
  }
}

/**
 * The base URL a dashboard link is built on: `CROW_DASHBOARD_URL`, else this instance's own
 * `crow_instances.gateway_url`, else `CROW_GATEWAY_URL`. "" when none of them is usable.
 *
 * @param {object|null} db a libsql-shaped client (the instance registry's table)
 * @param {{env?: object, localInstanceId?: string}} [opts] `env` defaults to `process.env`;
 *   `localInstanceId` is the id of THIS instance's `crow_instances` row (the caller may pass it so a
 *   test never reads the instance-id file)
 * @returns {Promise<string>} a base with no trailing slash, or ""
 */
export async function resolveDashboardBase(db, { env = process.env, localInstanceId } = {}) {
  const fromEnv = (name) => baseOf((env == null ? "" : env)[name]);
  const explicit = fromEnv("CROW_DASHBOARD_URL");
  if (explicit) return explicit;
  const own = await ownRowBase(db, localInstanceId);
  if (own) return own;
  return fromEnv("CROW_GATEWAY_URL");
}

/**
 * The base a push notification's CLICK link is built on: `NTFY_CLICK_BASE_URL` when it is set and not
 * blank (trimmed, trailing slashes trimmed), else `resolveDashboardBase`.
 *
 * The override exists because a satellite instance publishes pushes for a phone paired with the home
 * instance: the tap has to land where the app's session lives, which is not necessarily this
 * instance's own dashboard address.
 *
 * @param {object|null} db a libsql-shaped client
 * @param {{env?: object}} [opts]
 * @returns {Promise<string>} a base with no trailing slash, or ""
 */
export async function resolveClickBase(db, { env = process.env } = {}) {
  const override = text((env == null ? "" : env).NTFY_CLICK_BASE_URL).trim();
  if (override) return override.replace(/\/+$/, "");
  return resolveDashboardBase(db, { env });
}

export default resolveDashboardBase;