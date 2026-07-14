"""W3C Trace Context for agentguard Python SDK.

See https://www.w3.org/TR/trace-context/ for the spec.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass


@dataclass
class TraceContext:
    """Parsed W3C trace context."""

    trace_id: str
    span_id: str
    flags: int = 0x01  # sampled by default

    def to_header(self) -> str:
        """Render as the `traceparent` header value."""
        return f"00-{self.trace_id}-{self.span_id}-{self.flags:02x}"

    def child(self) -> "TraceContext":
        """Return a new context with a fresh span_id and same trace_id."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=uuid.uuid4().hex[:16],
            flags=self.flags,
        )

    @staticmethod
    def fresh() -> "TraceContext":
        """Start a brand-new trace."""
        return TraceContext(
            trace_id=uuid.uuid4().hex + uuid.uuid4().hex[:0],  # 32 hex chars total
            span_id=uuid.uuid4().hex[:16],
        )


_TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def parse_traceparent(s: str) -> TraceContext:
    """Parse a W3C `traceparent` header value.

    Format: `00-<trace_id-hex>-<span_id-hex>-<flags-hex>`.
    Raises ValueError if the value is malformed.
    """
    m = _TRACEPARENT_RE.match(s.strip())
    if not m:
        raise ValueError(f"malformed traceparent: {s!r}")
    _, trace_id, span_id, flags = m.groups()
    return TraceContext(trace_id=trace_id, span_id=span_id, flags=int(flags, 16))