import { presentation } from "./policy.js";
import { submitOnce } from "./recovery.js";

const byId = (id) => document.getElementById(id);
const unlock = byId("unlock");
const manual = byId("manual-ssh");
const dialog = byId("recovery");
const password = byId("password");
const confirmation = byId("manual-confirm");
let pending = false;
let refreshing = false;
let canUnlock = false;
let canManual = false;
let nonce = null;
let expiry = null;
let preparation = null;
let mode = null;
let refreshAbort = null;
let epoch = 0;
let theme = "auto";
let hostTrusted = false;
let sharedConnection = null;
let checkAbort = null;

function cancelChecks() {
  if (checkAbort) byId("connectivity-status").textContent = "Connection check canceled. No login was attempted.";
  checkAbort?.abort();
  checkAbort = null;
}

function configuration(report) {
  const errors = Array.isArray(report?.configuration_errors)
    ? report.configuration_errors.filter((value) => typeof value === "string") : [];
  byId("configuration").textContent = errors.join(" ");
  byId("configuration").hidden = !errors.length;
  const notes = Array.isArray(report?.configuration_notes)
    ? report.configuration_notes.filter((value) => typeof value === "string") : [];
  byId("setup-note").textContent = notes.join(" ");
  byId("setup-note").hidden = !notes.length;
  const target = report?.connection;
  if (target && typeof target.host === "string" && typeof target.username === "string"
      && Number.isInteger(target.port) && typeof target.tailscale_host === "string") {
    if (sharedConnection && (target.host !== sharedConnection.host
        || target.tailscale_host !== sharedConnection.tailscale_host || target.port !== sharedConnection.port)) {
      cancelChecks();
      byId("connectivity-results").hidden = true;
      byId("check-resolver").hidden = true;
      byId("connectivity-status").textContent = "Connection settings changed. Check again.";
    }
    sharedConnection = target;
    byId("shared-target").textContent = target.host
      ? `${target.username || "Set username"}@${target.host}:${target.port}` : "Not configured";
    byId("shared-runtime").textContent = target.tailscale_host
      ? `${target.tailscale_host}:${target.port}` : "Optional, not configured";
  }
}

function buttons() {
  unlock.hidden = !canUnlock;
  unlock.disabled = !canUnlock || pending || !!preparation;
  manual.hidden = !canManual;
  manual.disabled = !canManual || pending || !!preparation;
  byId("check-connections").disabled = !sharedConnection || !!checkAbort || pending || !!preparation || dialog.open;
}

function endpointResult(result, host, port) {
  if (!result || result.host !== host || result.port !== port) throw new Error("Connection changed");
  const dns = {not_configured: "Not configured", resolved: "DNS resolved", failed: "DNS resolution failed",
    timed_out: "DNS timed out", rejected: "Address is invalid or outside the Tailscale network"};
  const tcp = {not_checked: "TCP not checked", connected: "TCP connected", unreachable: "TCP port unreachable", timed_out: "TCP timed out"};
  const ssh = {not_checked: "SSH not checked", trusted: "SSH identity recognized", identity_needed: "SSH reached; server identity needs verification",
    unavailable: "SSH identity could not be checked", timed_out: "SSH handshake timed out"};
  if (!Object.hasOwn(dns, result.dns) || !Object.hasOwn(tcp, result.tcp) || !Object.hasOwn(ssh, result.ssh)) throw new Error("Invalid check");
  if (result.dns !== "resolved") return dns[result.dns];
  if (result.tcp !== "connected") return `${dns[result.dns]}; ${tcp[result.tcp]}`;
  return `${dns[result.dns]}; ${tcp[result.tcp]}; ${ssh[result.ssh]}`;
}

async function checkConnections() {
  if (!sharedConnection || checkAbort || pending || preparation || dialog.open || document.hidden) return;
  const target = {...sharedConnection};
  const abort = new AbortController();
  checkAbort = abort;
  buttons();
  byId("connectivity-results").hidden = true;
  byId("check-resolver").hidden = true;
  byId("connectivity-status").textContent = "Checking both addresses from FileVault…";
  const timer = setTimeout(() => abort.abort(), 12_000);
  try {
    const response = await fetch("v1/connectivity", {method: "POST", cache: "no-store", credentials: "same-origin", signal: abort.signal});
    if (!response.ok) throw new Error("Check unavailable");
    const report = await response.json();
    if (checkAbort !== abort || document.hidden) return;
    if (abort.signal.aborted) throw new Error("Check timed out");
    const lan = endpointResult(report.lan, target.host, target.port);
    const tailscale = endpointResult(report.tailscale, target.tailscale_host, target.port);
    byId("check-lan").textContent = lan;
    byId("check-tailscale").textContent = tailscale;
    byId("connectivity-results").hidden = false;
    byId("connectivity-status").textContent = `Checked ${new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})}. No login was attempted. These results do not establish the Mac's boot phase.`;
    const resolvers = Array.isArray(report.nameservers) ? report.nameservers : [];
    if (resolvers.length && resolvers.length <= 3 && resolvers.every(value => typeof value === "string" && value.length <= 64)) {
      byId("check-resolver").textContent = `FileVault DNS servers: ${resolvers.join(", ")}`;
      byId("check-resolver").hidden = false;
    }
  } catch {
    if (checkAbort === abort) byId("connectivity-status").textContent = "Connection check unavailable. No login was attempted. Check again explicitly.";
  } finally {
    clearTimeout(timer);
    if (checkAbort === abort) checkAbort = null;
    buttons();
  }
}
function clearGrant() {
  preparation?.abort();
  preparation = null;
  nonce = null;
  mode = null;
  password.value = "";
  confirmation.checked = false;
  byId("host-confirm").checked = false;
  hostTrusted = false;
  password.disabled = false;
  clearTimeout(expiry);
  if (dialog.open) dialog.close();
  buttons();
}
function render(report) {
  const view = presentation(report);
  byId("state").textContent = view.label;
  byId("explanation").textContent = view.explanation;
  byId("status-card").dataset.state = view.statusState;
  canUnlock = view.canUnlock;
  if (typeof report?.manual_ready === "boolean") canManual = report.manual_ready;
  if (report) configuration(report);
  if ((mode === "automatic" && !canUnlock) || (mode === "manual" && !canManual)) clearGrant();
  buttons();
  if (report?.version) byId("app-version").textContent = report.version;
  byId("transport").textContent = sharedConnection?.tailscale_host
    ? "A fresh response from this Mac's Tailscale address checks whether its normal runtime is available. No login password is used. A failed check does not prove it is locked."
    : "Add the Mac's optional Tailscale address to the same connection profile for automatic running checks. No saved login password or client key is needed.";
  byId("manual-availability").textContent = canManual
    ? "Password login is ready. New or changed servers require your confirmation first."
    : "Set the shared Mac connection in app settings. Enter a password only when connecting.";
}
async function refresh() {
  if (pending || refreshing || preparation) return;
  refreshing = true;
  const current = ++epoch;
  const abort = new AbortController();
  refreshAbort = abort;
  const timer = setTimeout(() => abort.abort(), 25_000);
  const options = {cache: "no-store", credentials: "same-origin", signal: abort.signal};
  const capabilities = (async () => {
    try {
      const response = await fetch("v1/system", options);
      if (!response.ok) return;
      const report = await response.json();
      if (current !== epoch || abort.signal.aborted) return;
      if (typeof report.manual_ready === "boolean") canManual = report.manual_ready;
      configuration(report);
      buttons();
      byId("manual-availability").textContent = canManual
        ? "Password login is ready. New or changed servers require your confirmation first."
        : "Set the shared Mac connection in app settings. Enter a password only when connecting.";
    } catch { /* Existing capability remains usable; the server is authoritative. */ }
  })();
  try {
    const response = await fetch("v1/status", options);
    if (!response.ok) throw new Error("Status unavailable");
    const report = await response.json();
    if (current !== epoch || abort.signal.aborted) return;
    render(report);
    byId("service-status").textContent = "App connected";
    byId("last-checked").textContent = `Checked ${new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})}`;
    byId("notice").textContent = "";
  } catch {
    if (current !== epoch) return;
    render(null);
    byId("service-status").textContent = "App disconnected";
    byId("last-checked").textContent = "No recent observation";
    byId("notice").textContent = "Status unavailable. Manual SSH remains available when configured.";
  } finally {
    await capabilities;
    clearTimeout(timer);
    if (refreshAbort === abort) refreshAbort = null;
    refreshing = false;
  }
}
async function prepare(selectedMode) {
  const allowed = selectedMode === "manual" ? canManual : canUnlock;
  if (!allowed || pending || preparation || document.hidden) return;
  if (checkAbort) {
    cancelChecks();
    byId("connectivity-status").textContent = "Connection check canceled. No login was attempted.";
  }
  refreshAbort?.abort();
  epoch++;
  clearGrant();
  const abort = new AbortController();
  preparation = abort;
  mode = selectedMode;
  buttons();
  const timer = setTimeout(() => abort.abort(), 25_000);
  try {
    const response = await fetch(selectedMode === "manual" ? "v1/manual/session" : "v1/session", {
      method: "POST", cache: "no-store", credentials: "same-origin", signal: abort.signal,
    });
    if (!response.ok) throw new Error("Unavailable");
    const grant = await response.json();
    if (abort.signal.aborted || preparation !== abort || document.hidden) return;
    if (!/^[0-9a-f]{64}$/.test(grant?.nonce) || grant?.expires_in !== 60) throw new Error("Invalid grant");
    if (selectedMode === "manual") {
      const target = grant.target;
      if (typeof target?.host !== "string" || target.host.length > 253
          || typeof target.username !== "string" || target.username.length > 255
          || !Number.isInteger(target.port) || target.port < 1 || target.port > 65535
          || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(target.host_key_fingerprint)) throw new Error("Invalid target");
      if (sharedConnection && (target.host !== sharedConnection.host
          || target.port !== sharedConnection.port || target.username !== sharedConnection.username)) {
        throw new Error("Connection changed; refresh status");
      }
      byId("manual-target").textContent = `${target.username}@${target.host}:${target.port}`;
      byId("manual-key").textContent = target.host_key_fingerprint;
      if (!["new", "trusted", "changed"].includes(target.trust_status)
          || target.trusted !== (target.trust_status === "trusted")) throw new Error("Invalid identity status");
      hostTrusted = target.trusted;
      byId("host-trust").hidden = hostTrusted;
      byId("trust-host").disabled = true;
      byId("trust-host").textContent = target.trust_status === "changed"
        ? "Trust verified new identity" : "Trust this SSH server";
      byId("host-trust-status").textContent = target.trust_status === "changed"
        ? "The server identity has changed. Verify the fingerprint independently before trusting this identity. No password has been sent."
        : hostTrusted ? "Recognized SSH server. Sign in with your account password below; no client key is needed."
          : "First connection to this server. Verify the fingerprint before trusting it. No password has been sent.";
      password.disabled = !hostTrusted;
    }
    nonce = grant.nonce;
    expiry = setTimeout(clearGrant, 60_000);
    byId("manual-details").hidden = selectedMode !== "manual";
    byId("recovery-title").textContent = selectedMode === "manual" ? "Manual SSH unlock" : "Unlock FileVault";
    byId("attempt-help").textContent = selectedMode === "manual"
      ? "Confirm the server before sending one password login. Boot phase may be unknown. Authentication alone does not prove FileVault is unlocked; this does not open a terminal."
      : "Enter the password for this attempt. The field clears as soon as you submit.";
    byId("submit-recovery").textContent = selectedMode === "manual" ? "Send one SSH attempt" : "Unlock";
    byId("submit-recovery").disabled = selectedMode === "manual";
    byId("recovery-status").textContent = "";
    dialog.showModal();
    if (selectedMode === "manual") (hostTrusted ? confirmation : byId("host-confirm")).focus();
    else password.focus();
  } catch {
    if (preparation === abort) {
      clearGrant();
      byId("notice").textContent = selectedMode === "manual"
        ? "No SSH connection is ready. Check the target or cooldown, then connect again explicitly. No password was sent."
        : "Suggested recovery is unavailable. You can choose manual SSH when configured.";
    }
  } finally {
    clearTimeout(timer);
    if (preparation === abort) preparation = null;
    buttons();
  }
}
byId("refresh").addEventListener("click", refresh);
byId("check-connections").addEventListener("click", checkConnections);
unlock.addEventListener("click", () => prepare("automatic"));
manual.addEventListener("click", () => prepare("manual"));
confirmation.addEventListener("change", () => {
  byId("submit-recovery").disabled = mode === "manual" && (!confirmation.checked || !hostTrusted);
});
byId("host-confirm").addEventListener("change", () => {
  byId("trust-host").disabled = !byId("host-confirm").checked || pending;
});
byId("trust-host").addEventListener("click", async () => {
  if (mode !== "manual" || !nonce || hostTrusted || pending || !byId("host-confirm").checked) return;
  const grant = nonce;
  pending = true;
  buttons();
  byId("trust-host").disabled = true;
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 25_000);
  try {
    const response = await fetch("v1/manual/trust", {
      method: "POST", cache: "no-store", credentials: "same-origin", signal: abort.signal,
      headers: {"X-FileVault-Nonce": grant, "X-FileVault-Confirm": "verified_host_identity"},
    });
    if (!response.ok || (await response.json()).trusted !== true) throw new Error("Unconfirmed");
    if (nonce !== grant || mode !== "manual" || document.hidden) return;
    hostTrusted = true;
    byId("host-trust").hidden = true;
    byId("host-trust-status").textContent = "Server identity remembered. Enter a password for one attempt, or cancel to use automatic checks without a password.";
    password.disabled = false;
    byId("submit-recovery").disabled = !confirmation.checked;
    password.focus();
  } catch {
    clearGrant();
    byId("notice").textContent = "Server identity confirmation did not complete. Connect again explicitly; no password was sent.";
  } finally {
    clearTimeout(timer);
    pending = false;
    buttons();
  }
});
byId("recovery-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!nonce || pending || !mode) { password.value = ""; return; }
  if (mode === "manual" && (!confirmation.checked || !hostTrusted)) {
    password.value = "";
    byId("recovery-status").textContent = "Confirm this target before sending a password.";
    return;
  }
  if ((mode === "automatic" && !canUnlock) || (mode === "manual" && !canManual)) { clearGrant(); return; }
  pending = true;
  const grant = nonce;
  const selectedMode = mode;
  nonce = null;
  clearTimeout(expiry);
  epoch++;
  canUnlock = false;
  buttons();
  byId("submit-recovery").disabled = true;
  const outcome = await submitOnce(password, grant, fetch, selectedMode);
  clearGrant();
  pending = false;
  render(null);
  const notices = {
    running: "The verified normal SSH runtime is reachable. Check required applications separately.",
    booting: "The attempt completed. Waiting for the Mac to become available.",
    authenticated: "SSH accepted the password. FileVault unlock and macOS startup are not confirmed. Refresh status to check.",
    unconfirmed: "SSH disconnected; the result is unconfirmed. No retry was made. Refresh status and check required services.",
    rejected: "The attempt was not accepted. No retry was made.",
    timed_out: "The attempt timed out. No retry was made.",
    unknown: "The result is unknown. No retry was made.",
  };
  byId("notice").textContent = notices[outcome];
});
byId("cancel-recovery").addEventListener("click", clearGrant);
dialog.addEventListener("cancel", clearGrant);
window.addEventListener("pagehide", () => { cancelChecks(); clearGrant(); });
document.addEventListener("visibilitychange", () => {
  if (document.hidden) { cancelChecks(); refreshAbort?.abort(); epoch++; clearGrant(); render(null); }
  else refresh();
});
byId("theme").addEventListener("click", () => {
  theme = theme === "auto" ? "light" : theme === "light" ? "dark" : "auto";
  document.documentElement.dataset.theme = theme;
  byId("theme").textContent = `Theme: ${theme === "auto" ? "Auto" : theme === "light" ? "Light" : "Dark"}`;
});
await refresh();
