#!/usr/bin/env node

/**
 * Crow Storage MCP Server — stdio transport
 *
 * S3-compatible file storage (Garage, or any S3 endpoint).
 * For HTTP transport, see servers/gateway/index.js.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createStorageServer } from "./server.js";
import { createDbClient, verifyDb } from "../db.js";
import { initStorageFromInstance } from "./s3-client.js";
import { generateInstructions } from "../shared/instructions.js";

const db = createDbClient();
try {
  await verifyDb(db);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}

// Follow the instance's storage settings. A BOT child carries CROW_STORAGE_FROM_HOST, so
// initStorageFromInstance takes the bot storage key the engine piped and never opens the DB or
// the identity; an OWNER's own spawn opens the DB settings exactly like the gateway
// (boot/admin-api.js initStorage), with the S3_* / MINIO_* env as the fallback.
await initStorageFromInstance(db);

const instructions = await generateInstructions({ deviceId: process.env.CROW_DEVICE_ID });
const server = createStorageServer(undefined, { instructions });
const transport = new StdioServerTransport();
await server.connect(transport);
