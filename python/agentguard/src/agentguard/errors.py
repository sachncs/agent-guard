"""Errors raised by the agentguard Python SDK."""

from __future__ import annotations


class AgentguardError(RuntimeError):
    """Base class for all agentguard SDK errors."""


class AuthorizationDenied(AgentguardError):
    """Raised when an authorization decision is Deny (only when check=True)."""

    def __init__(self, decision) -> None:  # noqa: ANN001 — forward ref
        self.decision = decision
        super().__init__(f"authorization denied: {decision.reasons or 'no matching policy'}")


class CLIUnavailable(AgentguardError):
    """Raised when the agentguard CLI binary cannot be located."""


class PolicyError(AgentguardError):
    """Raised when policies fail to parse or validate."""