/** Validate a Redis-compatible REST endpoint before attaching credentials. */
export function validateSharedStoreUrl(
  value: string,
  production = process.env.NODE_ENV === "production",
): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "must be an absolute URL";
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && !production)) {
    return production
      ? "must use HTTPS in production"
      : "must use HTTP or HTTPS";
  }
  if (url.username || url.password) return "must not include URL credentials";
}
