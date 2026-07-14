/**
 * W3C Trace Context for agentguard TypeScript SDK.
 */

export interface TraceContext {
  traceId: string;
  spanId: string;
  flags: number;
}

const TRACEPARENT_RE =
  /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

export function parseTraceparent(s: string): TraceContext {
  const m = TRACEPARENT_RE.exec(s.trim());
  if (!m) throw new Error(`malformed traceparent: ${JSON.stringify(s)}`);
  return {
    traceId: m[2],
    spanId: m[3],
    flags: parseInt(m[4], 16),
  };
}

export function freshTraceContext(): TraceContext {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const traceId = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const spanBytes = new Uint8Array(8);
  crypto.getRandomValues(spanBytes);
  const spanId = Array.from(spanBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return { traceId, spanId, flags: 0x01 };
}