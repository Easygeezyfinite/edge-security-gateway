import assert from "node:assert/strict";
import { test } from "node:test";
import { loadConfig } from "../src/config.ts";

const ORIGIN_URL = "https://origin.example";

for (const [setting, property, fallback] of [
  ["MAX_BODY_BYTES", "maxBodyBytes", 1_048_576],
  ["ORIGIN_TIMEOUT_MS", "originTimeoutMs", 10_000],
] as const) {
  test(`${setting} uses the default when unset or blank`, () => {
    assert.equal(loadConfig({ ORIGIN_URL })[property], fallback);
    assert.equal(loadConfig({ ORIGIN_URL, [setting]: " " })[property], fallback);
  });

  test(`${setting} accepts only positive whole numbers`, () => {
    assert.equal(loadConfig({ ORIGIN_URL, [setting]: "25" })[property], 25);
    for (const value of ["0", "-1", "1.5", "abc"]) {
      assert.throws(() => loadConfig({ ORIGIN_URL, [setting]: value }), {
        message: new RegExp(`^${setting} must be a positive whole number`),
      });
    }
  });
}
