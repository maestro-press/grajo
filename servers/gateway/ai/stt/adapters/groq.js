/**
 * Groq Whisper adapter — OpenAI-compatible schema, much faster + cheaper.
 *
 * Recommended models: `whisper-large-v3`, `whisper-large-v3-turbo`.
 * Batch-only.
 *
 * The profile's baseUrl/apiKey come from bot-writable `dashboard_settings`, so
 * the request goes through `guardedFetch` (../../adapter-guard.js, `kind:
 * "speech"`): a forbidden address is refused, an own-host server is allowed only
 * at `/v1/audio/transcriptions` and never receives the key, and a rebindable name
 * is pinned to the address that was vetted.
 */

import { guardedFetch } from "../../adapter-guard.js";
import { AI_TIMEOUT_MS } from "../../../../shared/http-timeout.js";

const DEFAULT_BASE_URL = "https://api.groq.com/openai/v1";

export default function createGroqSttAdapter(config) {
  const baseUrl = (config.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const apiKey = config.apiKey;

  return {
    name: "groq-stt",
    supportsStreaming: false,

    async transcribe(audioBuffer, options = {}) {
      const model = options.model || config.defaultModel || "whisper-large-v3-turbo";
      const filename = options.filename || "audio.wav";
      const contentType = options.contentType || "audio/wav";

      const form = new FormData();
      form.append("file", new Blob([audioBuffer], { type: contentType }), filename);
      form.append("model", model);
      if (options.language) form.append("language", options.language);
      if (options.prompt) form.append("prompt", options.prompt);
      form.append("response_format", "verbose_json");

      const res = await guardedFetch(`${baseUrl}/audio/transcriptions`, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}` },
        body: form,
        signal: options.signal,
        // The connect budget for the PINNED transport (a rebindable name); a
        // transcription uploads audio, so it gets the AI budget, not the TTS one.
        timeoutMs: AI_TIMEOUT_MS,
        guard: { ...config.guard, kind: "speech" },
      });
      if (!res.ok) {
        const err = await res.text().catch(() => "");
        throw Object.assign(new Error(`Groq STT ${res.status}: ${err.slice(0, 200)}`), { code: "provider_error" });
      }
      const data = await res.json();
      return {
        text: data.text || "",
        language: data.language,
        duration: data.duration,
      };
    },
  };
}