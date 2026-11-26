// The fake browser's trace is a JSON-lines file that it appends to while a test reads it. A read can land
// in the middle of an append, so the last line may be incomplete; parsing the whole file in one try made
// a single torn line return NO records at all (a record written before the reply that a test was checking
// "vanished"). Only complete, newline-terminated lines are parsed; an incomplete tail is left for the next
// read. A complete line that is not JSON is still a fixture bug and throws.
import { readFileSync } from "node:fs";

export function readTrace(path) {
  let text;
  try { text = readFileSync(path, "utf8"); } catch { return []; }
  const end = text.lastIndexOf("\n");
  if (end < 0) return [];
  return text.slice(0, end).split("\n").filter(Boolean).map((l) => JSON.parse(l));
}
