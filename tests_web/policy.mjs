import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { presentation } from "../web/policy.js";

for (const state of ["running", "unreachable", "unknown", "unrecognized", null]) {
  assert.equal(presentation({decision: {state, unlock_available: true}, transport_ready: true}).canUnlock, false);
}
assert.equal(presentation({decision: {state: "verified_preboot", unlock_available: true}, transport_ready: false}).canUnlock, false);
assert.equal(presentation({decision: {state: "verified_preboot", unlock_available: true}, transport_ready: true}).canUnlock, true);
assert.equal(presentation(null).label, "Unknown");
const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
assert.match(html, /id="unlock"[^>]*hidden disabled/);
assert.match(html, /id="password" type="password" autocomplete="off"/);
const js = await readFile(new URL("../web/app.js", import.meta.url), "utf8");
assert.doesNotMatch(js, /localStorage|sessionStorage|indexedDB|console\./);
console.log("UI state policy and masked-field checks passed");
