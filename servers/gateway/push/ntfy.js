/**
 * ntfy Push — Self-hosted push notification sender
 *
 * Publishes notifications to a local ntfy server instance. Where it publishes comes from
 * resolveNtfyConfig() (ntfy-config.js): the NTFY_* environment when NTFY_TOPIC is set
 * (unchanged pre-autowire behavior), else the instance's autowired ntfy-push.json.
 * DB-free by design — the corruption/migration alerts call this directly.
 *
 * The CLICK link's base comes from `resolveClickBase` (../dashboard-link-base.js):
 * NTFY_CLICK_BASE_URL when set, else the dashboard address (`CROW_DASHBOARD_URL`, this
 * instance's own registered gateway_url, then CROW_GATEWAY_URL). A caller that has a
 * database hands it in (`db`); one that has none still gets the env answers.
 */
import { resolveNtfyConfig, recordNtfyStatus } from "./ntfy-config.js";
import { resolveClickBase } from "../dashboard-link-base.js";

const PRIORITY_MAP = {
  low: "2",
  normal: "3",
  high: "5",
};

const TAG_MAP = {
  peer: "incoming_envelope",
  reminder: "alarm_clock",
  system: "gear",
  media: "musical_note",
  // Track 3 Task 8: perch-interactive turn-end / ask-card / gated-result pushes.
  attention: "bird",
};

/**
 * Send a notification via ntfy.
 *
 * @param {object} opts
 * @param {string} opts.title - Notification title
 * @param {string} [opts.body] - Notification body text
 * @param {string} [opts.url] - Click action URL (relative or absolute)
 * @param {string} [opts.priority='normal'] - 'low', 'normal', 'high'
 * @param {string} [opts.type='system'] - Notification type for tag mapping
 * @param {object} [opts.db] - a libsql-shaped client, used only to resolve the click link's base
 *   (a caller with no database passes none and the base comes from the environment alone)
 */
/**
 * HTTP headers can only carry ISO-8859-1 bytes. Node's fetch throws
 * `Cannot convert argument to a ByteString because the character at index
 * N has a value of <codepoint> which is greater than 255` if X-Title
 * contains anything outside that range — em-dashes, curly quotes, emoji,
 * etc. ntfy's server accepts RFC 2047-encoded headers (`=?utf-8?B?...?=`)
 * for full UTF-8 round-tripping, which is what this helper emits.
 */
function encodeNtfyHeader(value) {
  if (!value) return value;
  // Fast path: pure ASCII (most titles) — avoids base64 overhead.
  if (/^[\x00-\x7F]*$/.test(value)) return value;
  const b64 = Buffer.from(value, "utf8").toString("base64");
  return `=?utf-8?B?${b64}?=`;
}

/**
 * @returns {Promise<{ok:boolean, status?:number, error?:string, skipped?:boolean}>} never throws
 */
export async function sendNtfyNotification({ title, body, url, priority = "normal", type = "system", db = null }) {
  let cfg;
  try { cfg = resolveNtfyConfig(); } catch { cfg = null; }
  if (!cfg) return { ok: false, skipped: true };

  const ntfyUrl = `http://${cfg.publishHost}:${cfg.publishPort}/${encodeURIComponent(cfg.topic)}`;

  const headers = {
    "X-Title": encodeNtfyHeader(title),
    "X-Priority": PRIORITY_MAP[priority] || "3",
  };

  // Build full click URL. Satellite instances (e.g. MPA) should set
  // NTFY_CLICK_BASE_URL to the home-instance's gateway URL — that is where
  // the user's paired Android app and browser sessions actually live, so
  // the tap destination has to match. Without this override, an MPA push
  // gets `X-Click: https://…:8447/…` (MPA's own URL) and the paired-to-
  // primary APK sees the prefix mismatch and falls back to
  // `/dashboard/nest` instead of opening the intended page. With no override
  // the base is the DASHBOARD address (resolveClickBase): CROW_DASHBOARD_URL,
  // then this instance's own registered gateway_url, then CROW_GATEWAY_URL —
  // because on a Tailscale install CROW_GATEWAY_URL is the public Funnel
  // origin, which serves only public paths and 404s /dashboard.
  if (url) {
    // Only a RELATIVE url needs a base: an absolute one is passed through, and a push with no url at
    // all costs no database read.
    headers["X-Click"] = url.startsWith("http") ? url : (await resolveClickBase(db)) + url;
  }

  const tag = TAG_MAP[type];
  if (tag) {
    headers["X-Tags"] = tag;
  }

  if (cfg.publishToken) {
    headers["Authorization"] = `Bearer ${cfg.publishToken}`;
  }

  // Bound the send (2c follow-up F2/C2a): createNotification awaits this
  // sender from the instance-sync apply path — an unbounded hang on a
  // half-open socket wedges boot or the live apply loop. A timed-out send
  // lands in the same catch as any other failed send (already tolerated).
  const timeoutMs = parseInt(process.env.CROW_PUSH_SEND_TIMEOUT_MS, 10) || 10_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let result;
  try {
    const res = await fetch(ntfyUrl, {
      method: "POST",
      headers,
      body: body || title,
      signal: controller.signal,
    });
    // A refused publish (401/403 from an auth-enabled server) used to vanish here.
    result = res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: `ntfy answered HTTP ${res.status}` };
    try { await res.body?.cancel?.(); } catch { /* nothing to drain */ }
  } catch (err) {
    // ntfy server not available or send timed out — never propagate
    result = { ok: false, error: err?.name === "AbortError" ? `timed out after ${timeoutMs} ms` : String(err?.message || err) };
  } finally {
    clearTimeout(timer);
  }
  recordNtfyStatus({
    lastPushAt: new Date().toISOString(),
    lastPushOk: result.ok,
    lastPushStatus: result.status ?? null,
    lastPushError: result.ok ? null : String(result.error).slice(0, 200),
    lastPushSource: cfg.source,
  });
  return result;
}

/**
 * The silent "something changed, refresh" ping a home-screen widget listens
 * for: same topic, same auth, but NO title, body or click URL. The phone app
 * keys off the tag and re-fetches the summary; there is nothing on screen to
 * read, so a locked phone learns nothing (design: widgets phase 1).
 *
 * Deliberately NOT recorded via recordNtfyStatus: the status file's "last
 * push" is what the Phone-notifications settings panel shows as the last
 * real notification, and background pings would overwrite it constantly.
 *
 * @param {object} [opts]
 * @param {string} [opts.tag='crow-widgets'] - X-Tags value the app matches on
 * @returns {Promise<{ok:boolean, status?:number, error?:string, skipped?:boolean}>} never throws
 */
export async function sendNtfySilent({ tag = "crow-widgets" } = {}) {
  let cfg;
  try { cfg = resolveNtfyConfig(); } catch { cfg = null; }
  if (!cfg) return { ok: false, skipped: true };

  const ntfyUrl = `http://${cfg.publishHost}:${cfg.publishPort}/${encodeURIComponent(cfg.topic)}`;

  // Exactly two headers plus auth: an empty publish with no title and no
  // click action. `body` is the empty string, never the title fallback
  // sendNtfyNotification uses (that would put content on the lock screen).
  const headers = {
    "X-Tags": tag,
    "X-Priority": "1",
  };
  if (cfg.publishToken) {
    headers["Authorization"] = `Bearer ${cfg.publishToken}`;
  }

  const timeoutMs = parseInt(process.env.CROW_PUSH_SEND_TIMEOUT_MS, 10) || 10_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let result;
  try {
    const res = await fetch(ntfyUrl, {
      method: "POST",
      headers,
      body: "",
      signal: controller.signal,
    });
    result = res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: `ntfy answered HTTP ${res.status}` };
    try { await res.body?.cancel?.(); } catch { /* nothing to drain */ }
  } catch (err) {
    result = { ok: false, error: err?.name === "AbortError" ? `timed out after ${timeoutMs} ms` : String(err?.message || err) };
  } finally {
    clearTimeout(timer);
  }
  return result;
}
