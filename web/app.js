import { presentation, connectionChecksPassed, CHECK_FRESHNESS_SECONDS } from "./policy.js";
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
let historyAbort = null;
let historyBefore = null;
let lastRun = null;
let freshnessTimer = null;
let dialogOpener = null;
let backdropPointer = false;
let checkFailed = false;

function sameConnection(a, b) {
  return a && b && a.host === b.host && a.port === b.port && a.tailscale_host === b.tailscale_host;
}
function placeChecks() {
  clearTimeout(freshnessTimer);
  const passed = !checkAbort && !checkFailed && connectionChecksPassed(lastRun, sharedConnection);
  const card = byId("connection-checks");
  const parent = byId(passed ? "checks-bottom" : "checks-top");
  if (card.parentElement !== parent) {
    const focused = document.activeElement;
    const restore = focused && card.contains(focused);
    parent.insertBefore(card, null);
    if (restore) focused.focus({preventScroll:true});
  }
  card.dataset.checks = passed ? "passed" : "attention";
  if (!checkFailed && lastRun?.finished_at) {
    const age = Date.now() / 1000 - lastRun.finished_at;
    if (age >= CHECK_FRESHNESS_SECONDS || age < 0) {
      byId("connectivity-status").textContent = `Saved check from ${dateLabel(lastRun.finished_at)} is stale. Check again for current connection results. Saved results do not establish Running.`;
    } else {
      freshnessTimer = setTimeout(placeChecks, (CHECK_FRESHNESS_SECONDS - age) * 1000 + 10);
      freshnessTimer.unref?.();
    }
  }
}
function dateLabel(seconds) {
  return Number.isSafeInteger(seconds) && seconds > 0 ? new Date(seconds * 1000).toLocaleString() : "never";
}
function historyRunValid(run) {
  return Number.isSafeInteger(run?.sequence) && run.sequence > 0
    && Number.isSafeInteger(run.started_at) && run.started_at > 0
    && (run.finished_at === null || (Number.isSafeInteger(run.finished_at) && run.finished_at >= run.started_at))
    && ["checking", "complete", "interrupted"].includes(run.state);
}
async function loadHistory(append = false) {
  if (!sharedConnection || document.hidden || (append && !historyBefore)) return;
  historyAbort?.abort();
  const abort = new AbortController();
  historyAbort = abort;
  const target = {...sharedConnection};
  const timer = setTimeout(() => abort.abort(), 10_000);
  byId("history-more").disabled = true;
  try {
    const response = await fetch(`v1/connectivity/history${append ? `?before=${historyBefore}` : ""}`, {
      cache: "no-store", credentials: "same-origin", signal: abort.signal,
    });
    if (!response.ok) throw new Error("History unavailable");
    const page = await response.json();
    if (historyAbort !== abort || abort.signal.aborted || !sameConnection(target, sharedConnection)) return;
    if (!sameConnection(target, page.connection) || !Array.isArray(page.results)
        || page.results.length > 100 || !page.results.every(historyRunValid)) throw new Error("Invalid history");
    const rows = page.results.map(run => {
      const row = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = `${dateLabel(run.started_at)} · ${run.state === "checking" ? "In progress" : run.state === "interrupted" ? "Interrupted by app restart" : "Saved result"}`;
      row.append(title);
      for (const [key, label, host] of [["lan", "LAN", target.host], ["tailscale", "Tailscale", target.tailscale_host]]) {
        const description = document.createElement("p");
        description.textContent = `${label}: ${endpointResult({...run[key], host, port: target.port}, host, target.port)}`;
        row.append(description);
      }
      return row;
    });
    if (!append) {
      byId("history-list").replaceChildren();
      lastRun = page.results[0] ?? null;
      if (lastRun) {
        byId("check-lan").textContent = endpointResult({...lastRun.lan,host:target.host,port:target.port},target.host,target.port);
        byId("check-tailscale").textContent = endpointResult({...lastRun.tailscale,host:target.tailscale_host,port:target.port},target.tailscale_host,target.port);
        byId("connectivity-results").hidden = false;
      } else byId("connectivity-results").hidden = true;
      if (!checkFailed) {
        if (lastRun) byId("connectivity-status").textContent = `Last checked ${dateLabel(lastRun.finished_at ?? lastRun.started_at)}. Saved connection results do not establish the Mac's current boot phase.`;
        else byId("connectivity-status").textContent = "No saved connection check for these settings. Check connections to begin.";
      }
      const success = page.last_success;
      byId("history-last-success").textContent = ["lan", "tailscale"].map(key => {
        const result = success?.[key];
        return `${key === "lan" ? "LAN" : "Tailscale"}: last SSH reached ${dateLabel(result?.reachable_at)}, last identity verified ${dateLabel(result?.verified_at)}`;
      }).join(". ") + ". Within retained history only.";
    }
    byId("history-list").append(...rows);
    historyBefore = Number.isSafeInteger(page.next) && page.next > 0 ? page.next : null;
    byId("history-more").hidden = !historyBefore;
    byId("history-status").textContent = "Historical results only. Up to 1,000 checks for 30 days; only matching endpoint settings are shown. No login credentials or raw diagnostic messages are saved.";
    placeChecks();
  } catch {
    if (historyAbort === abort) {
      byId("history-status").textContent = "Saved history unavailable. Check again explicitly; recovery remains available when configured.";
      if (!append) { lastRun = null; byId("history-list").replaceChildren(); placeChecks(); }
    }
  } finally {
    clearTimeout(timer);
    if (historyAbort === abort) historyAbort = null;
    byId("history-more").disabled = false;
  }
}

function cancelChecks() {
  if (checkAbort) {
    checkFailed = true;
    byId("connectivity-status").textContent = "Stopped waiting for the connection check. An accepted check can finish and save its result. No login was attempted.";
  }
  checkAbort?.abort();
  checkAbort = null;
  placeChecks();
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
  if (report && Object.hasOwn(report, "connection") && target === null) {
    cancelChecks();
    sharedConnection = null;
    historyAbort?.abort();
    historyBefore = null;
    lastRun = null;
    byId("shared-target").textContent = "Not configured";
    byId("shared-runtime").textContent = "Optional, not configured";
    byId("history-list").replaceChildren();
    byId("history-last-success").textContent = "";
    byId("history-more").hidden = true;
    byId("history-status").textContent = "Configure the Mac connection to see matching history.";
    byId("connectivity-results").hidden = true;
    byId("check-resolver").hidden = true;
    placeChecks();
  }
  if (target && typeof target.host === "string" && typeof target.username === "string"
      && Number.isInteger(target.port) && typeof target.tailscale_host === "string") {
    if (sharedConnection && (target.host !== sharedConnection.host
        || target.tailscale_host !== sharedConnection.tailscale_host || target.port !== sharedConnection.port)) {
      cancelChecks();
      byId("connectivity-results").hidden = true;
      byId("check-resolver").hidden = true;
      byId("connectivity-status").textContent = "Connection settings changed. Check again.";
      historyAbort?.abort();
      historyBefore = null;
      lastRun = null;
      checkFailed = false;
      byId("history-list").replaceChildren();
      byId("history-last-success").textContent = "";
      byId("history-more").hidden = true;
    }
    sharedConnection = target;
    byId("shared-target").textContent = target.host
      ? `${target.username || "Set username"}@${target.host}:${target.port}` : "Not configured";
    byId("shared-runtime").textContent = target.tailscale_host
      ? `${target.tailscale_host}:${target.port}` : "Optional, not configured";
    placeChecks();
  }
}

function buttons() {
  unlock.hidden = !canUnlock;
  unlock.disabled = !canUnlock || pending || !!preparation;
  manual.hidden = !canManual;
  manual.disabled = !canManual || pending || !!preparation;
  byId("check-connections").disabled = !sharedConnection || !!checkAbort || pending || !!preparation || dialog.open;
  byId("cancel-recovery").disabled = pending;
}

function endpointResult(result, host, port) {
  if (!result || result.host !== host || result.port !== port) throw new Error("Connection changed");
  const dns = {not_checked: "DNS not checked", not_configured: "Not configured", resolved: "DNS resolved", failed: "DNS resolution failed",
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
  checkFailed = false;
  lastRun = null;
  placeChecks();
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
    if (historyRunValid(report.run)) lastRun = report.run;
    byId("connectivity-status").textContent = `Checked ${new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})}. No login was attempted. These results do not establish the Mac's boot phase.`;
    const resolvers = Array.isArray(report.nameservers) ? report.nameservers : [];
    if (resolvers.length && resolvers.length <= 3 && resolvers.every(value => typeof value === "string" && value.length <= 64)) {
      byId("check-resolver").textContent = `FileVault DNS servers: ${resolvers.join(", ")}`;
      byId("check-resolver").hidden = false;
    }
  } catch {
    if (checkAbort === abort) {
      checkFailed = true;
      byId("connectivity-status").textContent = "Connection check unavailable. An accepted check may still finish and save its result. No login was attempted. Check again explicitly.";
    }
  } finally {
    clearTimeout(timer);
    if (checkAbort === abort) checkAbort = null;
    buttons();
    placeChecks();
    await loadHistory();
  }
}
function clearGrant() {
  const wasOpen = dialog.open;
  const opener = dialogOpener;
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
  backdropPointer = false;
  buttons();
  if (wasOpen) {
    dialogOpener = null;
    if (!document.hidden && opener) {
      ((!opener.hidden && !opener.disabled) ? opener : byId("refresh")).focus();
    }
  }
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
    await loadHistory();
  }
}
async function prepare(selectedMode) {
  const allowed = selectedMode === "manual" ? canManual : canUnlock;
  if (!allowed || pending || preparation || document.hidden) return;
  if (checkAbort) {
    cancelChecks();
    byId("connectivity-status").textContent = "Stopped waiting for the connection check. An accepted check can finish and save its result. No login was attempted.";
  }
  refreshAbort?.abort();
  epoch++;
  clearGrant();
  dialogOpener = selectedMode === "manual" ? manual : unlock;
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
byId("history-more").addEventListener("click", () => loadHistory(true));
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
  pending = false;
  clearGrant();
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
function dismissRecovery() {
  password.value = "";
  if (pending) {
    byId("recovery-status").textContent = "The submitted operation is in progress. Wait for its result; no retry will be made.";
    return;
  }
  clearGrant();
}
function outsideDialog(event) {
  if (event.target !== dialog || !Number.isFinite(event.clientX) || !Number.isFinite(event.clientY)) return false;
  const box = dialog.getBoundingClientRect();
  return event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom;
}
byId("cancel-recovery").addEventListener("click", dismissRecovery);
dialog.addEventListener("cancel", event => { event.preventDefault(); dismissRecovery(); });
dialog.addEventListener("pointerdown", event => { backdropPointer = outsideDialog(event); });
dialog.addEventListener("pointercancel", () => { backdropPointer = false; });
dialog.addEventListener("click", event => {
  const dismiss = backdropPointer && outsideDialog(event);
  backdropPointer = false;
  if (dismiss) dismissRecovery();
});
window.addEventListener("pagehide", () => { cancelChecks(); historyAbort?.abort(); clearGrant(); });
document.addEventListener("visibilitychange", () => {
  if (document.hidden) { cancelChecks(); historyAbort?.abort(); refreshAbort?.abort(); epoch++; clearGrant(); render(null); }
  else refresh();
});
byId("theme").addEventListener("click", () => {
  theme = theme === "auto" ? "light" : theme === "light" ? "dark" : "auto";
  document.documentElement.dataset.theme = theme;
  byId("theme").textContent = `Theme: ${theme === "auto" ? "Auto" : theme === "light" ? "Light" : "Dark"}`;
});
await refresh();
