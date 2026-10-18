// Each call makes at most one POST. No storage, logging, retries, or serialization.
export async function submitOnce(input, nonce, request = fetch, mode = "automatic") {
  const bytes = new TextEncoder().encode(input.value);
  input.value = "";
  if (!nonce || !bytes.length || bytes.length > 1024 || !["automatic", "manual"].includes(mode)) {
    bytes.fill(0);
    return "rejected";
  }
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 165_000);
  try {
    const headers = { "Content-Type": "application/octet-stream", "X-FileVault-Nonce": nonce };
    if (mode === "manual") headers["X-FileVault-Confirm"] = "manual_ssh";
    const pending = request(mode === "manual" ? "v1/manual/attempt" : "v1/unlock", {
      method: "POST", cache: "no-store", credentials: "same-origin",
      headers,
      body: bytes, signal: abort.signal,
    });
    // Fetch copies BufferSource bodies. This does not erase browser/network copies.
    bytes.fill(0);
    const response = await pending;
    if (!response.ok) return "rejected";
    const result = await response.json();
    const allowed = mode === "manual"
      ? ["authenticated", "unconfirmed", "rejected", "timed_out"]
      : ["running", "booting", "rejected", "timed_out"];
    return allowed.includes(result?.outcome)
      ? result.outcome : "rejected";
  } catch {
    return "unknown";
  } finally {
    clearTimeout(timer);
    bytes.fill(0);
    input.value = "";
  }
}
