// Each call makes at most one POST. No storage, logging, retries, or serialization.
export async function submitOnce(input, nonce, request = fetch) {
  const bytes = new TextEncoder().encode(input.value);
  input.value = "";
  if (!nonce || !bytes.length || bytes.length > 1024) {
    bytes.fill(0);
    return "rejected";
  }
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 165_000);
  try {
    const pending = request("v1/unlock", {
      method: "POST", cache: "no-store", credentials: "same-origin",
      headers: { "Content-Type": "application/octet-stream", "X-FileVault-Nonce": nonce },
      body: bytes, signal: abort.signal,
    });
    // Fetch copies BufferSource bodies. This does not erase browser/network copies.
    bytes.fill(0);
    const response = await pending;
    if (!response.ok) return "rejected";
    const result = await response.json();
    return ["running", "booting", "rejected", "timed_out"].includes(result?.outcome)
      ? result.outcome : "rejected";
  } catch {
    return "unknown";
  } finally {
    clearTimeout(timer);
    bytes.fill(0);
    input.value = "";
  }
}
