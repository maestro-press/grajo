/**
 * Piper HTTP adapter — self-hosted, low-latency, CPU-only.
 *
 * Expects either:
 *   - wyoming-piper's OpenAI-compatible HTTP wrapper, OR
 *   - rhasspy/wyoming-piper served via a simple HTTP shim
 *   - rhasspy/piper-http (POST /api/tts?voice=...&text=...)
 *
 * This adapter targets the common piper-http shape: GET or POST with
 * `text` and `voice` query/form params returning audio/wav.
 *
 * config.baseUrl     — e.g. http://server-b:5000
 * config.defaultVoice — e.g. en_US-amy-medium
 *
 * The profile is bot-writable, so both requests go through `guardedFetch`
 * (../../adapter-guard.js, `kind: "speech"`). `/api/tts` and `/api/voices` are
 * NOT among the reviewed own-host speech operations, so a Piper profile pointed
 * at this box is refused; a Piper server on another box of the tailnet/LAN is
 * reached as before.
 */

import { guardedFetch } from "../../adapter-guard.js";
import { TTS_TIMEOUT_MS, VOICELIST_TIMEOUT_MS } from "../../../../shared/http-timeout.js";

export default function createPiperTtsAdapter(config) {
  const baseUrl = (config.baseUrl || "http://localhost:5000").replace(/\/+$/, "");

  return {
    name: "piper",
    supportsStreaming: true,

    async *synthesize(text, voice, options = {}) {
      const v = voice || config.defaultVoice || "en_US-amy-medium";
      const params = new URLSearchParams({ text, voice: v });
      // piper-http supports both GET with query string and POST with form-encoded body.
      // POST is safer for long text.
      const res = await guardedFetch(`${baseUrl}/api/tts`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString(),
        signal: options.signal,
        timeoutMs: TTS_TIMEOUT_MS,
        guard: { ...config.guard, kind: "speech" },
      });
      if (!res.ok) {
        const err = await res.text().catch(() => "");
        throw Object.assign(new Error(`Piper ${res.status}: ${err.slice(0, 200)}`), { code: "provider_error" });
      }
      const reader = res.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value?.length) yield value;
        }
      } finally {
        reader.releaseLock();
      }
    },

    async listVoices() {
      try {
        const res = await guardedFetch(`${baseUrl}/api/voices`, {
          method: "GET",
          headers: { Accept: "application/json" },
          timeoutMs: VOICELIST_TIMEOUT_MS,
          guard: { ...config.guard, kind: "speech" },
        });
        if (!res.ok) return [];
        const data = await res.json();
        if (Array.isArray(data)) {
          return data.map(v => ({ id: v.key || v.id || v, name: v.name || v.key || v }));
        }
        if (data && typeof data === "object") {
          return Object.keys(data).map(id => ({ id, name: id }));
        }
        return [];
      } catch { return []; }
    },
  };
}
