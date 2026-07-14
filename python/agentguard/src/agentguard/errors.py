"""Errors raised by the agentguard Python SDK."""

from __future__ import annotations


class AgentguardError(RuntimeError):
    """Base class for all agentguard SDK errors."""


class AuthorizationDenied(AgentguardError):
    """Raised when an authorization decision is Deny (only when check=True)."""

    def __init__(self, decision) -> None:  # noqa: ANN001
        self.decision = decision
        super().__init__(f"authorization denied: {decision.reasons or 'no matching policy'}")


class StepUpRequired(AgentguardError):
    """Raised when the PDP requires step-up authentication (e.g. MFA).

    The `step_up` attribute carries the AuthZEN context.response fields
    (acr_values, amr_values) per RFC 9470.
    """

    def __init__(self, step_up, decision) -> None:  # noqa: ANN001
        self.step_up = step_up
        self.decision = decision
        super().__init__(
            f"step-up required: acr_values={step_up.acr_values!r} "
            f"amr_values={step_up.amr_values!r}"
        )


class CLIUnavailable(AgentguardError):
    """Raised when the agentguard CLI binary cannot be located."""


class PolicyError(AgentguardError):
    """Raised when policies fail to parse or validate."""