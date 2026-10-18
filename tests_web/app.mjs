import assert from "node:assert/strict";
class Element {
  value = ""; hidden = true; disabled = true; open = false; checked = false;
  textContent = ""; dataset = {}; listeners = new Map();
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  async fire(name) { await this.listeners.get(name)?.({preventDefault() {}}); }
  showModal() { this.open = true; }
  close() { this.open = false; }
  focus() {}
}
const elements = new Map();
const element = (name) => {
  if (!elements.has(name)) elements.set(name, new Element());
  return elements.get(name);
};
const visibility = new Element();
const windowEvents = new Element();
globalThis.document = {hidden: false, documentElement: {dataset: {}},
  getElementById: element, addEventListener: visibility.addEventListener.bind(visibility)};
globalThis.window = {addEventListener: windowEvents.addEventListener.bind(windowEvents)};
let state = "unknown";
const connection = {host:"mac.example.invalid",port:22,username:"fixture-user",tailscale_host:"100.64.0.2"};
let trust = "trusted";
let failStatus = false;
let deferred = null;
let attempts = 0;
let trusts = 0;
const target = () => ({host: "mac.example.invalid", port: 22, username: "fixture-user",
  host_key_fingerprint: "SHA256:" + "a".repeat(43), trust_status: trust, trusted: trust === "trusted"});
globalThis.fetch = async (path, options) => {
  if (path === "v1/system") return {ok: true, json: async () => ({manual_ready: true,
    connection, configuration_errors: [], configuration_notes:["FileVault preboot detection has not been learned."]})};
  if (path === "v1/status") {
    if (failStatus) throw new Error("Synthetic unavailable status");
    return {ok: true, json: async () => ({decision: {state, unlock_available: true},
      transport_ready: true, manual_ready: true, connection, configuration_errors: [], configuration_notes:[]})};
  }
  if (path === "v1/session" || path === "v1/manual/session") {
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
  return {ok: true, json: async () => ({outcome: path === "v1/unlock" ? "booting" : "authenticated"})};
};
await import("../web/app.js");
assert.equal(element("unlock").hidden, true);
assert.equal(element("manual-ssh").hidden, false);
assert.equal(element("shared-target").textContent,"fixture-user@mac.example.invalid:22");
assert.equal(element("shared-runtime").textContent,"100.64.0.2:22");
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
deferred = new Promise((done) => { resolve = done; });
const opening = element("manual-ssh").fire("click");
document.hidden = true;
await visibility.fire("visibilitychange");
resolve({ok: true, json: async () => ({nonce: "b".repeat(64), expires_in: 60, target: target()})});
await opening;
assert.equal(element("recovery").open, false);
assert.equal(element("password").value, "");
assert.equal(attempts, 4);
await element("theme").fire("click");
assert.equal(document.documentElement.dataset.theme, "light");
await element("theme").fire("click");
assert.equal(document.documentElement.dataset.theme, "dark");
console.log("Manual override, separate identity trust, field clearing, status failure and UI race checks passed");
