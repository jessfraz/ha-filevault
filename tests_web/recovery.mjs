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

input.value = "DUMMY_SENTINEL";
let manualCalls = 0;
assert.equal(await submitOnce(input, "b".repeat(64), (path, options) => {
  manualCalls++;
  assert.equal(path, "v1/manual/attempt");
  assert.equal(options.headers["X-FileVault-Confirm"], "manual_ssh");
  assert.equal(input.value, "");
  return Promise.resolve({ok: true, json: async () => ({outcome: "authenticated"})});
}, "manual"), "authenticated");
assert.equal(manualCalls, 1);
input.value = "DUMMY_SENTINEL";
assert.equal(await submitOnce(input, "b".repeat(64), () => Promise.resolve({ok: true,
  json: async () => ({outcome: "running"})}), "manual"), "running");
for (const error_code of ["cooldown", "busy", "ssh_timeout", "ssh_unavailable"]) {
  input.value = "DUMMY_SENTINEL";
  let requests = 0;
  assert.equal(await submitOnce(input, "b".repeat(64), () => {
    requests++;
    return Promise.resolve({ok:false,json:async()=>({error_code})});
  }, "manual"),error_code);
  assert.equal(requests,1);
  assert.equal(input.value,"");
}
console.log("Manual recovery preserves verified running outcomes and typed failures without retrying");
