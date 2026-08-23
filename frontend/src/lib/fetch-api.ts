"use client";

/**
 * Client fetch wrapper: on session expiry (401) bounce to /login instead
 * of surfacing a raw error. Full page navigation is intentional — the
 * entire app state is dead once the session is gone.
 */
export async function fetchApi(input: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(input, { ...init, credentials: "same-origin" });
  if (res.status === 401) {
    // Hard navigation, not a route transition: the whole app state is dead
    // once the session is gone, and this runs outside React event flow.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- deliberate full reload on session expiry
    window.location.assign(`/login?from=${encodeURIComponent(window.location.pathname)}`);
    // Throw so callers stop processing the dead request.
    throw new Error("session expired; redirecting to sign-in");
  }
  return res;
}
