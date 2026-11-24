/**
 * Edge TTS adapter — Microsoft's unauthenticated Bing readaloud endpoint.
 *
 * WARNING: This uses a public, rate-limited, unauthenticated endpoint that
 * Microsoft does not officially support for third-party use. Appropriate for
 * self-hosted / personal deployments. For commercial use, prefer `azure`.
 *
 * The service is WebSocket-based with proprietary framing. Rather than
 * reimplement the protocol here, we exec the ubiquitous `edge-tts` CLI
 * (python package) via subprocess. The CLI must be installed on the host
 * running the gateway; we degrade gracefully if it isn't.
 *
 * WHAT THIS ADAPTER'S NETWORK LOOKS LIKE: synthesis is the `edge-tts`
 * SUBPROCESS talking to Microsoft — unlike Deepgram's live path there is no
 * socket of ours to judge, and no Crow credential goes with it (the CLI has
 * none). The one HTTP request this adapter makes is the voice list below, and
 * that goes through `guardedFetch` (../../adapter-guard.js, `kind: "speech"`)
 * like every other speech request: it is a fixed public Microsoft URL and carries
 * no header.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { guardedFetch } from "../../adapter-guard.js";
import { VOICELIST_TIMEOUT_MS } from "../../../../shared/http-timeout.js";

const VOICE_LIST_URL = "https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/voices/list?trustedclienttoken=6A5AA1D4EAFF4E9FB37E23D68491D6F4";

let _voiceCache = null;
let _voiceCacheTime = 0;
const VOICE_CACHE_TTL = 24 * 60 * 60 * 1000;

function findEdgeTtsBinary() {
  // edge-tts is typically installed via pip; check common locations.
  const candidates = [
    "/usr/local/bin/edge-tts",
    "/usr/bin/edge-tts",
    `${process.env.HOME || ""}/.local/bin/edge-tts`,
  ];
  for (const p of candidates) {
    if (p && existsSync(p)) return p;
  }
  return "edge-tts"; // fall through to PATH resolution
}

export default function createEdgeTtsAdapter(config) {
  const bin = findEdgeTtsBinary();
  const guard = config?.guard;

  return {
    name: "edge-tts",
    supportsStreaming: false, // edge-tts CLI writes a single MP3 file

    async *synthesize(text, voice, options = {}) {
      const v = voice || "en-US-JennyNeural";
      const rate = options.rate || "+0%";
      const volume = options.volume || "+0%";

      // Write audio to stdout (--write-media -) and read it as one buffer.
      const args = [
        "--voice", v,
        "--rate", rate,
        "--volume", volume,
        "--text", text,
        "--write-media", "/dev/stdout",
      ];

      const chunks = [];
      await new Promise((resolve, reject) => {
        const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
        let stderr = "";
        child.stdout.on("data", (c) => chunks.push(c));
        child.stderr.on("data", (c) => { stderr += c.toString(); });
        child.on("error", (err) => {
          reject(Object.assign(new Error(`edge-tts failed: ${err.message}. Install with: pip install edge-tts`), { code: "provider_error" }));
        });
        child.on("close", (code) => {
          if (code === 0) resolve();
          else reject(Object.assign(new Error(`edge-tts exited ${code}: ${stderr.slice(0, 200)}`), { code: "provider_error" }));
        });
      });

      // Yield the full buffer as a single chunk. Streaming would require
      // re-implementing the WSS protocol; not worth it for this adapter.
      yield Buffer.concat(chunks);
    },

    async listVoices() {
      if (_voiceCache && Date.now() - _voiceCacheTime < VOICE_CACHE_TTL) return _voiceCache;
      try {
        const res = await guardedFetch(VOICE_LIST_URL, {
          method: "GET",
          timeoutMs: VOICELIST_TIMEOUT_MS,
          guard: { ...guard, kind: "speech" },
        });
        if (!res.ok) return _voiceCache || [];
        const raw = await res.json();
        _voiceCache = raw.map(v => ({
          id: v.ShortName,
          name: v.FriendlyName?.split(" - ")[0] || v.ShortName,
          locale: v.Locale,
          gender: v.Gender,
        }));
        _voiceCacheTime = Date.now();
        return _voiceCache;
      } catch {
        return _voiceCache || [];
      }
    },
  };
}
