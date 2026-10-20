export function presentation(report) {
  const state = report?.decision?.state;
  const labels = {
    running: ["Running", "The configured Mac is running."],
    ssh_reachable: ["SSH online", "The trusted SSH server is reachable. Boot phase and FileVault state are not confirmed; you can use manual SSH."],
    verified_preboot: ["Locked", "A trusted FileVault preboot environment was identified."],
    unreachable: ["Unreachable", "The Mac cannot be reached. Its power state is unknown."],
    unknown: ["Unknown", "No verified status observation is available."],
  };
  let [label, explanation] = labels[state] ?? labels.unknown;
  let statusState = state ?? "unknown";
  if (state === "running" && report?.runtime_check === "verified") {
    explanation = "Your Mac responded now at its Tailscale address with its verified server identity. No login password was used.";
  } else if (state === "unknown") {
    if (["unavailable", "stale", "timed_out"].includes(report?.runtime_check)) {
      label = "Unavailable";
      explanation = "No fresh Tailscale response. The Mac may need unlocking, or its network connection may be unavailable. You can still connect with SSH over the LAN.";
      statusState = "unreachable";
    } else if (report?.runtime_check === "identity_needed") {
      label = "Verify Mac identity";
      explanation = "The Mac responded over Tailscale. Use Connect with SSH to verify its server fingerprint once; you can stop before entering a password. Automatic checks never need your login password.";
      statusState = "unknown";
    } else if (report?.runtime_check === "name_unavailable") {
      label = "Tailscale name unavailable";
      explanation = "FileVault could not resolve the Mac's Tailscale name. Check Home Assistant's internal DNS forwarding to the Tailscale app's MagicDNS proxy. Keep the Mac's full tailnet hostname in the shared connection. Manual LAN SSH remains available.";
      statusState = "unknown";
    }
  }
  return {
    label,
    explanation,
    statusState,
    canUnlock: state === "verified_preboot"
      && report?.decision?.unlock_available === true
      && report?.transport_ready === true,
  };
}

export const CHECK_FRESHNESS_SECONDS = 30;
export function connectionChecksPassed(run, connection, now = Date.now() / 1000) {
  if (!connection?.host || run?.state !== "complete" || !Number.isSafeInteger(run.finished_at)
      || run.finished_at > now || now - run.finished_at >= CHECK_FRESHNESS_SECONDS) return false;
  return ["lan", ...(connection.tailscale_host ? ["tailscale"] : [])].every(key => {
    const result = run[key];
    return result?.dns === "resolved" && result.tcp === "connected" && result.ssh === "trusted" && !result.error;
  });
}
