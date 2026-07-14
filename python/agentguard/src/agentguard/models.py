"""Data models for the agentguard Python SDK.

These mirror the Rust core's request types so that JSON serialization
matches what the CLI expects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Principal:
    """A principal is either a User or an Agent."""

    uid: str
    kind: str = "user"  # "user" or "agent"
    parent_uid: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def user(cls, uid: str, **attrs: Any) -> "Principal":
        return cls(uid=uid, kind="user", attrs=dict(attrs))

    @classmethod
    def agent(cls, uid: str, *, parent: str | None = None, **attrs: Any) -> "Principal":
        return cls(uid=uid, kind="agent", parent_uid=parent, attrs=dict(attrs))

    @classmethod
    def subagent(cls, uid: str, parent: str, **attrs: Any) -> "Principal":
        return cls(uid=uid, kind="agent", parent_uid=parent, attrs=dict(attrs))

    def to_json(self) -> dict[str, Any]:
        body: dict[str, Any] = {"type": self.kind, "uid": self.uid, "attrs": self.attrs}
        if self.parent_uid:
            body["parent_uid"] = self.parent_uid
        return body


@dataclass
class AgentAction:
    """A tool-call action."""

    tool: str
    operation: str | None = None

    @classmethod
    def tool(cls, name: str) -> "AgentAction":
        return cls(tool=name)

    @classmethod
    def tool_op(cls, name: str, op: str) -> "AgentAction":
        return cls(tool=name, operation=op)

    def to_json(self) -> dict[str, Any]:
        body: dict[str, Any] = {"tool": self.tool}
        if self.operation:
            body["operation"] = self.operation
        return body


@dataclass
class Resource:
    """A resource being acted on."""

    entity_type: str
    uid: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def with_attr(self, k: str, v: Any) -> "Resource":
        self.attrs[k] = v
        return self

    def to_json(self) -> dict[str, Any]:
        return {"entity_type": self.entity_type, "uid": self.uid, "attrs": self.attrs}


@dataclass
class Context:
    """Request context: tool args + session metadata."""

    args: dict[str, Any] = field(default_factory=dict)
    session: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def new(cls) -> "Context":
        return cls()

    def with_arg(self, k: str, v: Any) -> "Context":
        self.args[k] = v
        return self

    def with_session(self, k: str, v: Any) -> "Context":
        self.session[k] = v
        return self

    def to_json(self) -> dict[str, Any]:
        return {"args": self.args, "session": self.session}


@dataclass
class Decision:
    """The result of an authorization check."""

    effect: Effect
    policies: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    request: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def allow(self) -> bool:
        return self.effect == Effect.ALLOW

    @property
    def deny(self) -> bool:
        return self.effect == Effect.DENY

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Decision":
        return cls(
            effect=Effect(data["effect"]),
            policies=list(data.get("policies", [])),
            reasons=list(data.get("reasons", [])),
            request=dict(data.get("request", {})),
            raw=data,
        )