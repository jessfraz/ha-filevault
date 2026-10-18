import assert from "node:assert/strict";
import { submitOnce } from "../web/recovery.js";

const input = {value: "DUMMY_SENTINEL"};
let calls = 0;
let capturedBody;
const request = (_path, options) => {
  calls++;
  assert.equal(input.value, "");
  assert.equal(new TextDecoder().decode(options.body), "DUMMY_SENTINEL");
  capturedBody = options.body;
  return Promise.resolve({ok: true, json: async () => ({outcome: "running"})});
};
assert.equal(await submitOnce(input, "a".repeat(64), request), "running");
assert.equal(calls, 1);
assert.equal(input.value, "");
assert.ok(capturedBody.every((byte) => byte === 0));
input.value = "DUMMY_SENTINEL";
calls = 0;
assert.equal(await submitOnce(input, "a".repeat(64), () => { calls++; throw new Error("fixture network failure"); }), "unknown");
assert.equal(calls, 1);
assert.equal(input.value, "");
console.log("Ephemeral field clearing, buffer clearing and no-retry checks passed");
