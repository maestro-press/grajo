// The Extensions page's Running/Stopped badge comes from `docker compose ps`
// run per installed bundle. Bundles whose compose file requires
// `${CROW_HOME:?…}` (workspace, browser) make that `ps` fail when the env lacks
// CROW_HOME, and a failed `ps` is read as "stopped" — so the page said Stopped
// while every Workspace container ran (2026-10-03). The status probe must pass
// the same CROW_HOME the installer passes.
//
// Runs with a fake `docker` on PATH that behaves like compose: it refuses
// unless CROW_HOME is set, and otherwise reports one running container.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

const scratch = mkdtempSync(join(tmpdir(), "ext-status-"));
const fakeBin = join(scratch, "bin");
mkdirSync(fakeBin);
writeFileSync(join(fakeBin, "docker"), `#!/bin/sh
# "docker compose version" -> ok; "docker compose ps --format json" -> needs CROW_HOME
case "$2" in
  version) exit 0 ;;
  ps)
    [ -n "$CROW_HOME" ] || { echo "required variable CROW_HOME is missing a value" >&2; exit 1; }
    printf '%s\\n' '{"Service":"nextcloud","State":"running"}'
    ;;
  *) exit 1 ;;
esac
`);
chmodSync(join(fakeBin, "docker"), 0o755);

const home = join(scratch, "home");
const crowHome = join(home, ".crow"); // the module's fallback when CROW_HOME is unset
mkdirSync(join(crowHome, "bundles", "workspace"), { recursive: true });
writeFileSync(join(crowHome, "bundles", "workspace", "docker-compose.yml"), "name: x\nservices: {}\n");

test.after(() => rmSync(scratch, { recursive: true, force: true }));

test("status probe passes CROW_HOME so `${CROW_HOME:?}` bundles are not reported stopped", () => {
  // Child process whose CROW_HOME names exactly what the module's fallback would
  // have resolved to, and HOME pointed at scratch: the primary crow-gateway unit
  // runs with no CROW_HOME and the module falls back to <HOME>/.crow, so this IS
  // that home. It is named explicitly only because the child inherits
  // NODE_TEST_CONTEXT from the test runner and servers/shared/crow-home.js refuses
  // the IMPLICIT default there. The fake docker still fails unless the probe
  // itself puts CROW_HOME into the `docker compose ps` env (composeEnv's allowlist
  // is built from scratch, so nothing is inherited).
  const script = `
    import { fetchBundleStatus } from ${JSON.stringify(join(process.cwd(), "servers/gateway/dashboard/panels/extensions/data-queries.js"))};
    const { bundleStatus } = fetchBundleStatus({ workspace: { version: "0.1.2" } });
    process.stdout.write(JSON.stringify(bundleStatus));
  `;
  const out = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== "CROW_HOME")),
      CROW_HOME: crowHome,
      PATH: `${fakeBin}:${process.env.PATH}`, HOME: home,
    },
    encoding: "utf8",
  });
  assert.deepEqual(JSON.parse(out), { workspace: { running: true, containers: 1 } });
});
