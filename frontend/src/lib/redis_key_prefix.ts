const REDIS_KEY_PREFIX_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export function isValidRedisKeyPrefix(prefix: string): boolean {
  return REDIS_KEY_PREFIX_PATTERN.test(prefix);
}

export function assertRedisKeyPrefix(prefix: string, label: string): void {
  if (!isValidRedisKeyPrefix(prefix)) {
    throw new Error(`${label} must contain 1-128 safe characters`);
  }
}
