// The shared fake-browser trace reader (tests/fixtures/read-trace.mjs): a read that lands mid-append must
// still return every complete record, not none.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readTrace } from "./fixtures/read-trace.mjs";

test("a torn last line is left out and the complete records before it are kept", () => {
  const dir = mkdtempSync(join(tmpdir(), "read-trace-"));
  try {
    const p = join(dir, "chromium.log");
    assert.deepEqual(readTrace(p), [], "a missing file has no records");
    writeFileSync(p, '{"t":"create-target","targetId":"P7"}\n{"t":"recv","meth');
    assert.deepEqual(readTrace(p), [{ t: "create-target", targetId: "P7" }]);
    writeFileSync(p, '{"t":"recv","meth');
    assert.deepEqual(readTrace(p), [], "only a torn line: nothing yet");
    writeFileSync(p, '{"t":"a"}\n{"t":"b"}\n');
    assert.deepEqual(readTrace(p).map((r) => r.t), ["a", "b"]);
    writeFileSync(p, '{"t":"a"}\nnot json\n');
    assert.throws(() => readTrace(p), "a complete line that is not JSON is a fixture bug, not a race");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
