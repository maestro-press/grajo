/**
 * faster-whisper-server adapter — OpenAI-compatible self-host.
 *
 * https://github.com/fedirz/faster-whisper-server exposes an
 * /v1/audio/transcriptions endpoint with the same schema as OpenAI.
 * GPU-accelerated; great for the home server.
 *
 * config.baseUrl — e.g. http://server-b:8000/v1
 * config.defaultModel — e.g. "Systran/faster-whisper-large-v3"
 *
 * The profile comes from bot-writable `dashboard_settings`, so the request goes
 * through `guardedFetch` (../../adapter-guard.js, `kind: "speech"`). An own-host
 * faster-whisper server is one of the allowed speech operations, and it never
 * receives the profile's placeholder credential.
 */

import { guardedFetch } from "../../adapter-guard.js";
import { AI_TIMEOUT_MS } from "../../../../shared/http-timeout.js";

export default function createFasterWhisperAdapter(config) {
  const baseUrl = (config.baseUrl || "http://localhost:8000/v1").replace(/\/+$/, "");
  const apiKey = config.apiKey || "not-needed";

  return {
    name: "fasterwhisper",
    supportsStreaming: false,

    async transcribe(audioBuffer, options = {}) {
      const model = options.model || config.defaultModel || "Systran/faster-whisper-large-v3";
      const filename = options.filename || "audio.wav";
      const contentType = options.contentType || "audio/wav";

      const form = new FormData();
      form.append("file", new Blob([audioBuffer], { type: contentType }), filename);
      form.append("model", model);
      if (options.language) form.append("language", options.language);
      // The OpenAI `prompt` field (faster-whisper-server 0.5.0 accepts it): a bias toward names the speaker uses.
      if (options.prompt) form.append("prompt", options.prompt);
      // faster-whisper-server's `hotwords` (0.5.0's form has it): a few words to bias toward (kiosk call signs).
      if (options.hotwords) form.append("hotwords", options.hotwords);
      form.append("response_format", "verbose_json");

      const res = await guardedFetch(`${baseUrl}/audio/transcriptions`, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}` },
        body: form,
        signal: options.signal,
        // Connect budget for the PINNED transport (a rebindable name): a box on
        // the tailnet transcribing a long clip may take a while to answer.
        timeoutMs: AI_TIMEOUT_MS,
        guard: { ...config.guard, kind: "speech" },
      });
      if (!res.ok) {
        const err = await res.text().catch(() => "");
        throw Object.assign(new Error(`faster-whisper ${res.status}: ${err.slice(0, 200)}`), { code: "provider_error" });
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