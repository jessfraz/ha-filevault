import assert from "node:assert/strict";
class Element {
  value = ""; hidden = true; disabled = true; open = false; checked = false;
  textContent = ""; dataset = {}; listeners = new Map();
  children = []; parentElement = null;
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  async fire(name, values = {}) {
    const event = {target:this, defaultPrevented:false, preventDefault() {this.defaultPrevented=true;}, ...values};
    await this.listeners.get(name)?.(event);
    return event;
  }
  showModal() { this.open = true; }
  close() { this.open = false; }
  focus() { document.activeElement = this; }
  getBoundingClientRect() { return {left:100,top:100,right:500,bottom:500}; }
  append(...children) { children.forEach(child => this.insertBefore(child,null)); }
  insertBefore(child, before) {
    if (child.parentElement) child.parentElement.children = child.parentElement.children.filter(other => other !== child);
    const index = before ? this.children.indexOf(before) : -1;
    if (index < 0) this.children.push(child); else this.children.splice(index,0,child);
    child.parentElement = this;
  }
  replaceChildren(...children) { this.children.forEach(child => child.parentElement=null); this.children=[]; this.append(...children); }
  contains(child) { return this === child || this.children.some(item=>item.contains(child)); }
}
const elements = new Map();
const element = (name) => {
  if (!elements.has(name)) elements.set(name, new Element());
  return elements.get(name);
};
const visibility = new Element();
const windowEvents = new Element();
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const cadenceTimers = new Set();
let clockNow = Date.now();
Date.now = () => clockNow;
globalThis.setTimeout = (callback, delay, ...args) => {
  if (![250, 1_000].includes(delay)) return realSetTimeout(callback, delay, ...args);
  const timer = {delay, callback: () => callback(...args), unref() {}};
  cadenceTimers.add(timer);
  return timer;
};
globalThis.clearTimeout = timer => { if (!cadenceTimers.delete(timer)) realClearTimeout(timer); };
const tick = async delay => {
  const timer = [...cadenceTimers].find(timer => timer.delay === delay);
  assert.ok(timer, `Expected a ${delay} ms UI timer`);
  cadenceTimers.delete(timer);
  await timer.callback();
};
globalThis.document = {hidden: false, documentElement: {dataset: {}},
  createElement: () => new Element(),
  getElementById: element, addEventListener: visibility.addEventListener.bind(visibility)};
globalThis.window = {addEventListener: windowEvents.addEventListener.bind(windowEvents)};
let state = "unknown";
let runtimeCheck = null;
const connection = {host:"mac.example.invalid",port:22,username:"fixture-user",tailscale_host:"100.64.0.2"};
let trust = "trusted";
let failStatus = false;
let deferred = null;
let attempts = 0;
let trusts = 0;
let checks = 0;
let checkDeferred = null;
let historyRuns = [];
let attemptDeferred = null;
let sessionError = null;
let recoveryReport = {busy:false,retry_after_ms:0,activity:null};
const target = () => ({host: "mac.example.invalid", port: 22, username: "fixture-user",
  host_key_fingerprint: "SHA256:" + "a".repeat(43), trust_status: trust, trusted: trust === "trusted"});
globalThis.fetch = async (path, options) => {
  if (path === "v1/recovery") {
    assert.equal(options.method,undefined);
    assert.equal(options.body,undefined);
    return {ok:true,json:async()=>recoveryReport};
  }
  if (path.startsWith("v1/connectivity/history")) return {ok:true,json:async()=>({connection,results:historyRuns,
    next:null,last_success:{lan:{reachable_at:null,verified_at:null},tailscale:{reachable_at:null,verified_at:null}}})};
  if (path === "v1/connectivity") {
    checks++;
    assert.equal(options.method, "POST");
    assert.equal(options.body, undefined);
    if (checkDeferred) return checkDeferred;
    const lan={dns:"resolved",tcp:"connected",ssh:"identity_needed",error:null};
    const tailscale={dns:"failed",tcp:"not_checked",ssh:"not_checked",error:"dns_failed"};
    const now=Math.floor(Date.now()/1000);
    const run={sequence:checks,started_at:now,finished_at:now,state:"complete",lan,tailscale};
    historyRuns.unshift(run);
    return {ok:true,json:async()=>({lan:{...lan,host:connection.host,port:22},
      tailscale:{...tailscale,host:connection.tailscale_host,port:22},run,nameservers:["192.0.2.53"]})};
  }
  if (path === "v1/system") return {ok: true, json: async () => ({manual_ready: true,
    connection, configuration_errors: [], configuration_notes:["FileVault preboot detection has not been learned."]})};
  if (path === "v1/status") {
    if (failStatus) throw new Error("Synthetic unavailable status");
    return {ok: true, json: async () => ({decision: {state, unlock_available: true},
      runtime_check: runtimeCheck, transport_ready: true, manual_ready: true, connection, configuration_errors: [], configuration_notes:[]})};
  }
  if (path === "v1/session" || path === "v1/manual/session") {
    if (sessionError) return {ok:false,status:sessionError.status,json:async()=>({error_code:sessionError.code})};
    if (deferred) return deferred;
    return {ok: true, json: async () => ({nonce: "a".repeat(64), expires_in: 60, target: target()})};
  }
  if (path === "v1/manual/trust") {
    trusts++;
    assert.equal(options.headers["X-FileVault-Confirm"], "verified_host_identity");
    assert.equal(options.body, undefined);
    trust = "trusted";
    return {ok: true, json: async () => ({trusted: true})};
  }
  assert.ok(["v1/unlock", "v1/manual/attempt"].includes(path));
  attempts++;
  assert.equal(element("password").value, "");
  assert.equal(new TextDecoder().decode(options.body), "DUMMY_SENTINEL");
  if (path === "v1/manual/attempt") assert.equal(options.headers["X-FileVault-Confirm"], "manual_ssh");
  if (attemptDeferred) return attemptDeferred;
  return {ok: true, json: async () => ({outcome: path === "v1/unlock" ? "booting" : "authenticated"})};
};
await import("../web/app.js");
assert.equal(element("unlock").hidden, true);
assert.equal(element("manual-ssh").hidden, false);
assert.equal(element("shared-target").textContent,"fixture-user@mac.example.invalid:22");
assert.equal(element("shared-runtime").textContent,"100.64.0.2:22");
await element("check-connections").fire("click");
assert.equal(checks,1);
assert.match(element("check-lan").textContent,/identity needs verification/);
assert.match(element("check-tailscale").textContent,/DNS resolution failed/);
assert.match(element("check-resolver").textContent,/192.0.2.53/);
assert.equal(attempts,0);
assert.equal(trusts,0);
assert.equal(element("recovery").open,false);
assert.equal(element("state").textContent,"Unknown");

// Cooldown is a timed limit, not a failed connection, and expires without a click.
sessionError={status:429,code:"cooldown"};
recoveryReport={busy:false,retry_after_ms:62_000,activity:null};
await element("manual-ssh").fire("click");
assert.match(element("notice").textContent,/cooldown is active/);
assert.match(element("recovery-availability").textContent,/1:02 remaining/);
assert.equal(element("manual-ssh").disabled,true);
assert.equal(element("recovery").open,false);
const exactRetry = new Date(clockNow + 62_000).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});
assert.ok(element("recovery-availability").textContent.includes(exactRetry));
clockNow += 1_000;
await tick(250);
assert.match(element("recovery-availability").textContent,/1:01 remaining/);
clockNow += 61_000;
await tick(250);
assert.match(element("recovery-availability").textContent,/cooldown is over/);
assert.match(element("notice").textContent,/cooldown is over/);
assert.equal(element("manual-ssh").disabled,false);
assert.equal(attempts,0);

sessionError={status:502,code:"ssh_unavailable"};
recoveryReport={busy:false,retry_after_ms:0,activity:null};
await element("manual-ssh").fire("click");
assert.match(element("notice").textContent,/Could not connect.*SSH server/);
assert.doesNotMatch(element("notice").textContent,/cooldown/);
assert.equal(element("manual-ssh").disabled,false);
sessionError=null;

await element("manual-ssh").fire("click");
assert.equal(element("recovery").open, true);
assert.equal(element("password").disabled, false);
assert.equal(element("submit-recovery").disabled, true);
element("password").value = "DUMMY_SENTINEL";
await element("recovery-form").fire("submit");
assert.equal(attempts, 0);
assert.equal(element("password").value, "");
element("manual-confirm").checked = true;
await element("manual-confirm").fire("change");
element("password").value = "DUMMY_SENTINEL";
await element("recovery-form").fire("submit");
assert.equal(attempts, 1);
assert.equal(element("password").value, "");
assert.equal(element("recovery").open, false);
assert.match(element("notice").textContent, /not confirmed/);
assert.equal(element("ssh-activity").hidden,false);
assert.match(element("activity-summary").textContent,/SSH accepted the password/);
assert.equal(element("state").textContent,"Unknown");
await element("recovery-form").fire("submit");
assert.equal(attempts, 1);

trust = "new";
await element("manual-ssh").fire("click");
assert.equal(element("password").disabled, true);
assert.equal(element("host-trust").hidden, false);
assert.equal(element("trust-host").disabled, true);
assert.equal(trusts, 0);
element("manual-confirm").checked = true;
element("password").value = "DUMMY_SENTINEL";
await element("recovery-form").fire("submit");
assert.equal(attempts, 1);
assert.equal(element("password").value, "");
element("host-confirm").checked = true;
await element("host-confirm").fire("change");
await element("trust-host").fire("click");
assert.equal(trusts, 1);
assert.equal(element("password").disabled, false);
element("password").value = "DUMMY_SENTINEL";
await element("recovery-form").fire("submit");
assert.equal(attempts, 2);

trust = "changed";
await element("manual-ssh").fire("click");
assert.match(element("host-trust-status").textContent, /identity has changed/);
assert.equal(element("password").disabled, true);
assert.equal(trusts, 1);
element("host-confirm").checked = true;
await element("host-confirm").fire("change");
await element("trust-host").fire("click");
assert.equal(trusts, 2);
assert.equal(element("password").disabled, false);
element("manual-confirm").checked = true;
await element("manual-confirm").fire("change");
element("password").value = "DUMMY_SENTINEL";
await element("recovery-form").fire("submit");
assert.equal(attempts, 3);
assert.equal(element("password").value, "");
assert.equal(element("recovery").open, false);

state = "verified_preboot";
await element("refresh").fire("click");
assert.equal(element("unlock").hidden, false);
await element("unlock").fire("click");
element("password").value = "DUMMY_SENTINEL";
await element("recovery-form").fire("submit");
assert.equal(attempts, 4);
assert.match(element("notice").textContent, /Waiting/);

// Interior clicks and drags never act as backdrop dismissal.
await element("manual-ssh").fire("click");
element("password").value="DUMMY_SENTINEL";
for (const values of [{target:element("recovery-form"),clientX:200,clientY:200},{clientX:200,clientY:200}]) {
  await element("recovery").fire("pointerdown",values);
  await element("recovery").fire("click",values);
  assert.equal(element("recovery").open,true);
  assert.equal(element("password").value,"DUMMY_SENTINEL");
}
await element("recovery").fire("pointerdown",{clientX:200,clientY:200});
await element("recovery").fire("click",{clientX:10,clientY:10});
assert.equal(element("recovery").open,true);
await element("recovery").fire("pointerdown",{clientX:10,clientY:10});
await element("recovery").fire("click",{clientX:10,clientY:10});
assert.equal(element("recovery").open,false);
assert.equal(element("password").value,"");
assert.equal(document.activeElement,element("manual-ssh"));
assert.equal(attempts,4);
await element("manual-ssh").fire("click");
element("password").value="DUMMY_SENTINEL";
assert.equal((await element("recovery").fire("cancel")).defaultPrevented,true);
assert.equal(element("password").value,"");
assert.equal(element("recovery").open,false);
assert.equal(document.activeElement,element("manual-ssh"));

// Escape and backdrop cannot hide, cancel or duplicate a submitted attempt.
let finishAttempt;
attemptDeferred=new Promise(done=>{finishAttempt=done;});
await element("manual-ssh").fire("click");
element("manual-confirm").checked=true;
element("password").value="DUMMY_SENTINEL";
const submitting=element("recovery-form").fire("submit");
assert.equal(attempts,5);
assert.equal(element("dialog-activity").hidden,false);
assert.equal(element("recovery-credentials").hidden,true);
assert.match(element("recovery-status").textContent,/Waiting for authentication and macOS startup/);
recoveryReport={busy:true,retry_after_ms:30_000,activity:{active:true,outcome:null,events:[
  {elapsed_ms:0,message:"SSH password authentication started."},
  {elapsed_ms:2_000,message:"SSH accepted the password. Waiting for macOS over Tailscale."},
]}};
await tick(1_000);
assert.equal(element("activity-log").children.length,2);
assert.equal(element("dialog-log").children.length,2);
assert.equal(element("dialog-log").children[1].children[0].textContent,"00:02");
assert.match(element("recovery-status").textContent,/SSH accepted the password.*Waiting/);
assert.doesNotMatch(element("activity-log").children.map(row=>row.children[1].textContent).join(" "),/DUMMY_SENTINEL/);
clockNow += 30_000;
recoveryReport.retry_after_ms=0;
await tick(250);
assert.match(element("recovery-availability").textContent,/cooldown is over.*still running/);
assert.doesNotMatch(element("recovery-availability").textContent,/connect again now/);
assert.equal(element("manual-ssh").disabled,true);
await element("recovery-form").fire("submit");
assert.equal(attempts,5);
await element("recovery").fire("cancel");
await element("recovery").fire("pointerdown",{clientX:10,clientY:10});
await element("recovery").fire("click",{clientX:10,clientY:10});
assert.equal(element("recovery").open,true);
assert.equal(element("password").value,"");
assert.equal(attempts,5);
assert.match(element("recovery-status").textContent,/in progress/);
state="running";
recoveryReport={busy:false,retry_after_ms:15_000,activity:{active:false,outcome:"running",events:[
  ...recoveryReport.activity.events,{elapsed_ms:15_000,message:"macOS responded over Tailscale. The Mac is running."},
]}};
finishAttempt({ok:true,json:async()=>({outcome:"running"})});
await submitting;
attemptDeferred=null;
assert.equal(element("recovery").open,false);
assert.match(element("notice").textContent,/Mac is running/);
assert.equal(element("state").textContent,"Running");
assert.equal(element("ssh-activity").hidden,false);
assert.equal(element("activity-log").children.length,3);
assert.equal(element("manual-ssh").disabled,true);
clockNow += 15_000;
await tick(250);
assert.equal(element("manual-ssh").disabled,false);
recoveryReport={...recoveryReport,retry_after_ms:0};

// A recovered in-flight trace can disappear after an app restart. Stop polling
// the stale activity and clearly retain an unconfirmed result without retrying.
recoveryReport={busy:true,retry_after_ms:0,activity:{active:true,outcome:null,events:[
  {elapsed_ms:0,message:"Waiting for macOS to finish starting."},
]}};
await element("refresh").fire("click");
assert.equal(element("manual-ssh").disabled,true);
recoveryReport={busy:false,retry_after_ms:0,activity:null};
await tick(1_000);
assert.match(element("activity-summary").textContent,/no longer available.*unconfirmed/);
assert.equal(element("activity-state").textContent,"Complete");
assert.equal(element("manual-ssh").disabled,false);
assert.equal([...cadenceTimers].some(timer=>timer.delay===1_000),false);
assert.equal(attempts,5);

const good={dns:"resolved",tcp:"connected",ssh:"trusted",error:null};
state="unknown";
const now=Math.floor(Date.now()/1000);
historyRuns=[{sequence:100,started_at:now,finished_at:now,state:"complete",lan:good,tailscale:good}];
await element("refresh").fire("click");
assert.equal(element("connection-checks").parentElement,element("checks-bottom"));
assert.equal(element("state").textContent,"Unknown");
assert.equal(attempts,5);
historyRuns=[{...historyRuns[0],started_at:now-60,finished_at:now-31}];
await element("refresh").fire("click");
assert.equal(element("connection-checks").parentElement,element("checks-top"));
assert.match(element("connectivity-status").textContent,/stale/);
historyRuns=[];
await element("refresh").fire("click");
assert.equal(element("connection-checks").parentElement,element("checks-top"));
assert.match(element("connectivity-status").textContent,/No saved/);

// Tailscale can remain offline after FileVault unlock while desktop login is
// pending. LAN SSH stays usable without claiming the Mac is locked.
state = "ssh_reachable";
for (runtimeCheck of ["unavailable", "timed_out"]) {
  await element("refresh").fire("click");
  assert.equal(element("state").textContent,"SSH online");
  assert.equal(element("status-card").dataset.state,"ssh_reachable");
  assert.equal(element("unlock").hidden,true);
  assert.equal(element("manual-ssh").hidden,false);
  assert.equal(element("manual-ssh").disabled,false);
  await element("manual-ssh").fire("click");
  assert.equal(element("recovery").open,true);
  await element("cancel-recovery").fire("click");
}
runtimeCheck = null;
assert.equal(attempts,5);

state = "running";
await element("refresh").fire("click");
assert.equal(element("unlock").hidden, true);
assert.equal(element("manual-ssh").hidden, false);
failStatus = true;
trust = "trusted";
await element("refresh").fire("click");
assert.equal(element("manual-ssh").hidden, false);
assert.equal(element("configuration").hidden, true);
assert.match(element("setup-note").textContent, /has not been learned/);
await element("manual-ssh").fire("click");
assert.equal(element("recovery").open, true);
await element("cancel-recovery").fire("click");

let resolve;
let finishCheck;
checkDeferred = new Promise(done => {finishCheck = done;});
const checking = element("check-connections").fire("click");
await element("check-connections").fire("click");
assert.equal(checks,2);
await element("manual-ssh").fire("click");
assert.equal(element("recovery").open,true);
finishCheck({ok:true,json:async()=>({lan:{host:"other.example.invalid"}})});
await checking;
assert.match(element("connectivity-status").textContent,/Stopped waiting/);
await element("cancel-recovery").fire("click");
checkDeferred = null;
deferred = new Promise((done) => { resolve = done; });
const opening = element("manual-ssh").fire("click");
document.hidden = true;
await visibility.fire("visibilitychange");
resolve({ok: true, json: async () => ({nonce: "b".repeat(64), expires_in: 60, target: target()})});
await opening;
assert.equal(element("recovery").open, false);
assert.equal(element("password").value, "");
assert.equal(attempts, 5);
await element("theme").fire("click");
assert.equal(document.documentElement.dataset.theme, "light");
await element("theme").fire("click");
assert.equal(document.documentElement.dataset.theme, "dark");
console.log("Manual override, separate identity trust, field clearing, status failure and UI race checks passed");
