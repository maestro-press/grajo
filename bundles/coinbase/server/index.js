#!/usr/bin/env node

/**
 * The Coinbase bundle's MCP server — stdio entry point.
 *
 * It checks the engine's address first, then reads the engine's bearer token from the installed
 * bundle's `.env` (through the engine client, which owns that file), points the client at the
 * engine on this computer, and serves the tools over stdio. No key material of the owner's is
 * read here, and nothing else is taken from the environment.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createEngineClient, readEngineToken } from "./engine-client.js";
import { createCoinbaseServer } from "./server.js";

const DEFAULT_ENGINE_URL = "http://127.0.0.1:3062";
const MISSING_TOKEN = "Coinbase engine token not found";
const ENGINE_URL_SENTENCE = "The engine address must be a plain http address on this computer.";

/** An IPv4 address in 127.0.0.0/8, which is this computer's own loopback. */
function isLoopbackAddress(hostname) {
  const parts = String(hostname ?? "").split(".");
  if (parts.length !== 4) return false;
  const octets = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const value = Number(part);
    if (value > 255) return false;
    octets.push(value);
  }
  return octets[0] === 127;
}

/**
 * The engine's address, if it is a plain http address on this computer; otherwise null.
 *
 * Only the `http:` scheme, no userinfo, and a loopback host — `localhost`, an address in
 * 127.0.0.0/8, or `[::1]` — is accepted. Nothing else is: not https, not another host, not a
 * name that only looks like an address. The refused value is never repeated back.
 */
function checkedEngineBaseUrl(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:") return null;
  if (parsed.username !== "" || parsed.password !== "") return null;
  const host = parsed.hostname;
  if (host === "localhost" || host === "[::1]" || isLoopbackAddress(host)) return raw;
  return null;
}

// The address is settled before the token is read and before any request could be made.
const baseUrl = checkedEngineBaseUrl(process.env.CROW_COINBASE_ENGINE_URL || DEFAULT_ENGINE_URL);
if (baseUrl === null) {
  // One plain sentence on stderr, and no stack: the operator has a setting to fix, not a trace.
  process.stderr.write(`${ENGINE_URL_SENTENCE}\n`);
  process.exit(1);
}

let token;
try {
  token = readEngineToken();
} catch {
  // One plain sentence on stderr, and no stack: the operator needs to install, not read a trace.
  process.stderr.write(`${MISSING_TOKEN}\n`);
  process.exit(1);
}

const projectId = process.env.CROW_COINBASE_PROJECT_ID || null;

// No key provider: this client can make every bearer-only call, and the engine is the
// one that refuses a privileged call it cannot verify.
const client = createEngineClient({ baseUrl, token, source: "mcp" });
const server = createCoinbaseServer({ client, projectId });
const transport = new StdioServerTransport();
await server.connect(transport);