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
      redirect: "error",
    });
  } catch {
    throw new Error("PDP readiness probe failed");
  }
  const status = response.status;
  // The health contract is the HTTP status alone. Release the unused body so
  // repeated readiness probes do not hold response streams or connections.
  await response.body?.cancel().catch(() => undefined);
  if (!response.ok) throw new Error(`PDP is not ready (HTTP ${status})`);
}
