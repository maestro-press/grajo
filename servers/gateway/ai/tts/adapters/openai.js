/**
 * OpenAI-compatible TTS adapter.
 *
 * Covers OpenAI (`tts-1`, `tts-1-hd`, `gpt-4o-mini-tts`) and any provider
 * implementing POST /v1/audio/speech with the same schema.
 *
 * The profile is bot-writable, so every request goes through `guardedFetch`
 * (../../adapter-guard.js, `kind: "speech"`): `/v1/audio/speech` is one of the
 * allowed own-host speech operations, and a request that lands on this box never
 * receives the profile's key.
 */

import { guardedFetch } from "../../adapter-guard.js";
import { TTS_TIMEOUT_MS } from "../../../../shared/http-timeout.js";

const DEFAULT_BASE_URL = "https://api.openai.com/v1";
const BUILTIN_VOICES = ["alloy", "echo", "fable", "onyx", "nova", "shimmer", "ash", "coral", "sage"];

export default function createOpenAITtsAdapter(config) {
  const baseUrl = (config.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const apiKey = config.apiKey;

  return {
    name: "openai-tts",
    supportsStreaming: true,

    async *synthesize(text, voice, options = {}) {
      const model = options.model || "tts-1";
      const format = options.format || "opus"; // opus, mp3, aac, flac, wav, pcm
      const body = {
        model,
        input: text,
        voice: voice || "alloy",
        response_format: format,
        speed: options.speed || 1.0,
        stream: true,
      };
      const res = await guardedFetch(`${baseUrl}/audio/speech`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
        },
        body: JSON.stringify(body),
        signal: options.signal,
        timeoutMs: TTS_TIMEOUT_MS,
        guard: { ...config.guard, kind: "speech" },
      });
      if (!res.ok) {
        const err = await res.text().catch(() => "");
        throw Object.assign(new Error(`OpenAI TTS ${res.status}: ${err.slice(0, 200)}`), { code: "provider_error" });
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
      return BUILTIN_VOICES.map(id => ({ id, name: id }));
    },
  };
}
