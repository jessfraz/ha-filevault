import assert from "node:assert/strict";

// A small event-driven DOM fixture. Only dummy values enter the input.
class Element {
  value = "";
  hidden = true;
  disabled = true;
  open = false;
  textContent = "";
  listeners = new Map();
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
globalThis.document = {
  hidden: false,
  getElementById: element,
  addEventListener: visibility.addEventListener.bind(visibility),
};
globalThis.window = {addEventListener: windowEvents.addEventListener.bind(windowEvents)};
let state = "unknown";
let deferred = null;
let attempts = 0;
globalThis.fetch = async (path, options) => {
  if (path === "v1/status") {
    return {ok: true, json: async () => ({
      decision: {state, unlock_available: true}, transport_ready: true,
    })};
  }
  if (path === "v1/session") {
    if (deferred) return deferred;
    return {ok: true, json: async () => ({nonce: "a".repeat(64), expires_in: 60})};
  }
  assert.equal(path, "v1/unlock");
  attempts++;
  assert.equal(element("password").value, "");
  assert.equal(new TextDecoder().decode(options.body), "DUMMY_SENTINEL");
  return {ok: true, json: async () => ({outcome: "booting"})};
};
await import("../web/app.js");
assert.equal(element("unlock").hidden, true);
assert.equal(element("recovery").open, false);

state = "verified_preboot";
await element("refresh").fire("click");
assert.equal(element("unlock").hidden, false);
await element("unlock").fire("click");
assert.equal(element("recovery").open, true);
element("password").value = "DUMMY_SENTINEL";
await element("recovery-form").fire("submit");
assert.equal(attempts, 1);
assert.equal(element("password").value, "");
assert.equal(element("recovery").open, false);
assert.equal(element("unlock").hidden, true);
assert.match(element("notice").textContent, /Waiting/);
await element("recovery-form").fire("submit");
assert.equal(attempts, 1);

await element("refresh").fire("click");
await element("unlock").fire("click");
element("password").value = "DUMMY_SENTINEL";
await element("cancel-recovery").fire("click");
assert.equal(element("password").value, "");
assert.equal(element("recovery").open, false);

let resolve;
deferred = new Promise((done) => { resolve = done; });
const opening = element("unlock").fire("click");
document.hidden = true;
await visibility.fire("visibilitychange");
resolve({ok: true, json: async () => ({nonce: "b".repeat(64), expires_in: 60})});
await opening;
assert.equal(element("recovery").open, false);
assert.equal(element("unlock").hidden, true);
assert.equal(element("password").value, "");

document.hidden = false;
deferred = null;
state = "running";
await visibility.fire("visibilitychange");
// The listener starts a refresh without returning it.
await new Promise((done) => setImmediate(done));
assert.equal(element("unlock").hidden, true);
assert.equal(attempts, 1);
console.log("UI gating, one submission, cancellation and hidden-page race checks passed");
