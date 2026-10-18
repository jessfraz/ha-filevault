export function presentation(report) {
  const state = report?.decision?.state;
  const labels = {
    running: ["Running", "The configured Mac is running."],
    ssh_reachable: ["SSH online", "The trusted SSH server is reachable. Boot phase and FileVault state are not confirmed; you can use manual SSH."],
    verified_preboot: ["Locked", "A trusted FileVault preboot environment was identified."],
    unreachable: ["Unreachable", "The Mac cannot be reached. Its power state is unknown."],
    unknown: ["Unknown", "No verified status observation is available."],
  };
  const [label, explanation] = labels[state] ?? labels.unknown;
  return {
    label,
    explanation,
    canUnlock: state === "verified_preboot"
      && report?.decision?.unlock_available === true
      && report?.transport_ready === true,
  };
}
