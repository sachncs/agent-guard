/** Probe the PDP's readiness endpoint with a strict request deadline. */
export async function checkPdpReady(
  pdpUrl: string,
  bearer: string | undefined,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 2_000,
): Promise<void> {
  let response: Response;
  try {
    response = await fetchImpl(`${pdpUrl}/readyz`, {
      method: "GET",
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
    });
  } catch {
    throw new Error("PDP readiness probe failed");
  }
  if (!response.ok) throw new Error(`PDP is not ready (HTTP ${response.status})`);
}
