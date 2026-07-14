"""agentguard — Cedar-powered authorization for AI agents (Python SDK)."""

from .client import Client
from .errors import (
    AgentguardError,
    AuthorizationDenied,
    StepUpRequired,
)
from .models import (
    AgentAction,
    Context,
    Decision,
    Effect,
    Principal,
    Resource,
    StepUp,
)
from .trace import TraceContext, parse_traceparent

__version__ = "0.2.0"

__all__ = [
    "AgentAction",
    "AgentguardError",
    "AuthorizationDenied",
    "Client",
    "Context",
    "Decision",
    "Effect",
    "Principal",
    "Resource",
    "StepUp",
    "StepUpRequired",
    "TraceContext",
    "parse_traceparent",
]