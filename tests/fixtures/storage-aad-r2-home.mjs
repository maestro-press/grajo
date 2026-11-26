// Imported FIRST by tests/storage-shared-aad-r2.test.js: gives that test process its own
// CROW_HOME, so the era state file it writes can never be seen by another test file (the suite
// shares one scratch CROW_HOME across files).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
process.env.CROW_HOME = mkdtempSync(join(tmpdir(), "crow-storage-aad-r2-home-"));
delete process.env.CROW_DATA_DIR;
delete process.env.CROW_DB_PATH;
