import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { presentation, connectionChecksPassed } from "../web/policy.js";

for (const state of ["running", "ssh_reachable", "unreachable", "unknown", "unrecognized", null]) {
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

for (const runtime_check of ["unavailable", "timed_out"]) {
  const view = presentation({decision:{state:"ssh_reachable"},runtime_check});
  assert.equal(view.label,"Locked");
  assert.match(view.explanation,/LAN SSH is reachable and Tailscale is offline/);
  assert.equal(view.statusState,"verified_preboot");
  assert.equal(view.canUnlock,false);
}
assert.equal(presentation({decision:{state:"ssh_reachable"},runtime_check:"stale"}).label,"SSH online");
assert.equal(presentation({decision:{state:"verified_preboot",unlock_available:false}}).label,"Locked");
assert.equal(presentation({decision:{state:"unknown"},runtime_check:"unavailable"}).label,"Unavailable");
assert.match(presentation({decision:{state:"running"},runtime_check:"verified"}).explanation,/responded now.*Tailscale/);
assert.match(presentation({decision:{state:"unknown"},runtime_check:"identity_needed"}).explanation,/stop before entering a password/);
const connection={host:"mac.example.invalid",tailscale_host:"100.64.0.2"};
const success={dns:"resolved",tcp:"connected",ssh:"trusted",error:null};
const run={state:"complete",finished_at:1000,lan:success,tailscale:success};
assert.equal(connectionChecksPassed(run,connection,1029),true);
assert.equal(connectionChecksPassed(run,connection,1030),false);
assert.equal(connectionChecksPassed(run,connection,999),false);
assert.equal(connectionChecksPassed(null,connection,1000),false);
for (const bad of [{...success,ssh:"identity_needed"},{...success,dns:"failed"},{...success,tcp:"unreachable"},
  {...success,error:"interrupted"},null]) {
  assert.equal(connectionChecksPassed({...run,tailscale:bad},connection,1001),false);
}
assert.equal(connectionChecksPassed({...run,tailscale:null},{...connection,tailscale_host:""},1001),true);
assert.equal(connectionChecksPassed({...run,state:"interrupted"},connection,1001),false);
assert.equal(connectionChecksPassed({...run,finished_at:null},connection,1001),false);
assert.match(presentation({decision:{state:"unknown"},runtime_check:"name_unavailable"}).explanation,/internal DNS forwarding/);
