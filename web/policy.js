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
  } else if (["unknown", "ssh_reachable"].includes(state)) {
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
      explanation = "The Mac's Tailscale name could not be resolved. Use its numeric Tailscale address in the shared Mac connection. Manual LAN SSH remains available.";
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
