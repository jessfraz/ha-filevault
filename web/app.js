import { presentation } from "./policy.js";
import { submitOnce } from "./recovery.js";

const byId = (id) => document.getElementById(id);
const unlock = byId("unlock");
let pending = false;
let canUnlock = false;
let nonce = null;
let expiry = null;
let preparation = null;
const dialog = byId("recovery");
const password = byId("password");

function clearGrant() {
  preparation?.abort();
  preparation = null;
  nonce = null;
  password.value = "";
  clearTimeout(expiry);
  if (dialog.open) dialog.close();
}

function render(report) {
  const view = presentation(report);
  byId("state").textContent = view.label;
  byId("explanation").textContent = view.explanation;
  canUnlock = view.canUnlock;
  unlock.hidden = !canUnlock;
  unlock.disabled = !canUnlock;
  if (!canUnlock) clearGrant();
  byId("app-version").textContent = report?.version ?? "";
  byId("transport").textContent = report?.transport_ready === true
    ? (canUnlock ? "The verified Mac is ready for one recovery attempt." : "Recovery is available only while the Mac is verified as locked.")
    : "Unlock is disabled in this development build.";
}

async function refresh() {
  if (pending) return;
  pending = true;
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), 5_000);
  try {
    const response = await fetch("v1/status", {
      cache: "no-store", credentials: "same-origin", signal: timeout.signal,
    });
    if (!response.ok) throw new Error("Status unavailable");
    const report = await response.json();
    render(report);
    byId("service-status").textContent = "Connected";
    byId("last-checked").textContent = `Checked ${new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})}`;
    byId("notice").textContent = "";
  } catch {
    render(null);
    byId("service-status").textContent = "Disconnected";
    byId("last-checked").textContent = "No recent observation";
    byId("notice").textContent = "Status unavailable. Refresh to try again.";
  } finally {
    clearTimeout(timer);
    pending = false;
  }
}

byId("refresh").addEventListener("click", refresh);
unlock.addEventListener("click", async () => {
  if (!canUnlock || pending || document.hidden) return;
  clearGrant();
  const abort = new AbortController();
  preparation = abort;
  unlock.disabled = true;
  const timer = setTimeout(() => abort.abort(), 12_000);
  try {
    const response = await fetch("v1/session", {
      method: "POST", cache: "no-store", credentials: "same-origin", signal: abort.signal,
    });
    if (!response.ok) throw new Error("Unavailable");
    const grant = await response.json();
    if (abort.signal.aborted || preparation !== abort || document.hidden || !canUnlock) return;
    if (!/^[0-9a-f]{64}$/.test(grant?.nonce) || grant?.expires_in !== 60) throw new Error("Invalid grant");
    nonce = grant.nonce;
    expiry = setTimeout(clearGrant, 60_000);
    byId("recovery-status").textContent = "";
    dialog.showModal();
    password.focus();
  } catch {
    if (preparation === abort) {
      clearGrant();
      byId("notice").textContent = "Unlock is unavailable. Refresh the status.";
    }
  } finally {
    clearTimeout(timer);
    if (preparation === abort) preparation = null;
    unlock.disabled = !canUnlock;
  }
});
byId("recovery-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!canUnlock || !nonce || pending) { clearGrant(); return; }
  pending = true;
  const grant = nonce;
  nonce = null;
  clearTimeout(expiry);
  canUnlock = false;
  unlock.hidden = true;
  unlock.disabled = true;
  byId("submit-recovery").disabled = true;
  const outcome = await submitOnce(password, grant);
  clearGrant();
  byId("submit-recovery").disabled = false;
  pending = false;
  render(null);
  const notices = {
    running: "The Mac is running.",
    booting: "The attempt completed. Waiting for the Mac to become available.",
    rejected: "The attempt was not accepted. No retry was made.",
    timed_out: "The attempt timed out. No retry was made.",
    unknown: "The result is unknown. No retry was made.",
  };
  byId("notice").textContent = notices[outcome];
});
byId("cancel-recovery").addEventListener("click", clearGrant);
dialog.addEventListener("cancel", clearGrant);
window.addEventListener("pagehide", clearGrant);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) { clearGrant(); render(null); }
  else refresh();
});
await refresh();
