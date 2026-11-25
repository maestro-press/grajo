// Tests that seed raw (unsealed) pi_bot_defs rows run in a home that predates
// sealing: the host-side era record says "pre-era". Tests ABOUT sealing/era
// behaviour (bot-def-*.test.js) make their own setup and never use this.
// Same shape as writeBotDefEraState in servers/shared/bot-def-mac.js.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export function markBotDefPreEra(crowHome) {
  const secrets = join(crowHome, "secrets");
  mkdirSync(secrets, { recursive: true, mode: 0o700 });
  writeFileSync(
    join(secrets, "bot-def-era.json"),
    JSON.stringify({ v: 1, state: "pre-era", at: new Date().toISOString() }) + "\n",
    { mode: 0o600 },
  );
}
