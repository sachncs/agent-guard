"""agentguard_langchain — authorize every LangChain tool call."""

from __future__ import annotations

import logging
from typing import Any, Callable

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from agentguard import AgentAction, AgentguardError, Client, Context, Decision, Principal, Resource

logger = logging.getLogger("agentguard.langchain")


class GuardConfig(BaseModel):
    """Configuration for the agentguard middleware."""

    store: str = ".agentguard"
    principal_factory: Callable[[Any], Principal] | None = Field(default=None)
    """Optional callable that, given the runtime/context, returns the principal.
    Defaults to a fixed `Agent::"default"` if not provided."""
    resource_factory: Callable[[BaseTool, dict[str, Any]], Resource] | None = Field(default=None)
    """Optional callable that picks the resource for a tool call. Defaults to
    `Tool::"<tool-name>"`."""
    deny_message: str = (
        "I cannot perform this action because it is not authorized by your security policies."
    )
    audit: bool = True


class GuardedTool:
    """Wraps a LangChain tool with agentguard authorization.

    Usage:
        from agentguard_langchain import GuardedTool, GuardConfig

        guarded = GuardedTool(my_tool, GuardConfig(store=".agentguard"))
        # Pass `guarded` to your agent instead of `my_tool`.
    """

    def __init__(self, tool: BaseTool, config: GuardConfig | None = None) -> None:
        self.tool = tool
        self.config = config or GuardConfig()
        self.client = Client(store=self.config.store, audit_log=".audit/decisions.jsonl")

    @property
    def name(self) -> str:
        return self.tool.name

    @property
    def description(self) -> str:
        return self.tool.description or ""

    @property
    def args_schema(self) -> Any:
        return self.tool.args_schema

    def _principal(self, runtime: Any) -> Principal:
        if self.config.principal_factory is not None:
            return self.config.principal_factory(runtime)
        return Principal.agent("default")

    def _resource(self, tool: BaseTool, args: dict[str, Any]) -> Resource:
        if self.config.resource_factory is not None:
            return self.config.resource_factory(tool, args)
        return Resource("Tool", tool.name)

    def _check(self, args: dict[str, Any], runtime: Any) -> Decision:
        ctx = Context().with_arg("_raw", args)
        # Surface session info if available on the runtime.
        meta = getattr(runtime, "metadata", None) or {}
        if isinstance(meta, dict):
            for k in ("ip", "user_agent", "mfa", "ts"):
                if k in meta:
                    ctx.with_session(k, meta[k])
        decision = self.client.authorize(
            principal=self._principal(runtime),
            action=AgentAction.tool(self.tool.name),
            resource=self._resource(self.tool, args),
            context=ctx,
            audit=self.config.audit,
        )
        return decision

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Invoke the tool, first checking authorization."""
        runtime = config.get("runnable_config") if isinstance(config, dict) else None
        # Resolve args — depends on the tool's input schema. For simplicity,
        # we accept either dicts or single-string inputs.
        if isinstance(input, dict):
            args = input
        else:
            args = {"input": input}
        decision = self._check(args, runtime)
        if decision.deny:
            logger.warning("denied tool=%s reasons=%s", self.tool.name, decision.reasons)
            raise PermissionError(self.config.deny_message + f" [tool={self.tool.name}]")
        return self.tool.invoke(input, config=config, **kwargs)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        runtime = config.get("runnable_config") if isinstance(config, dict) else None
        if isinstance(input, dict):
            args = input
        else:
            args = {"input": input}
        decision = self._check(args, runtime)
        if decision.deny:
            logger.warning("denied tool=%s reasons=%s", self.tool.name, decision.reasons)
            raise PermissionError(self.config.deny_message + f" [tool={self.tool.name}]")
        return await self.tool.ainvoke(input, config=config, **kwargs)

    def __getattr__(self, item: str) -> Any:
        # Forward attribute access for compatibility with BaseTool.
        return getattr(self.tool, item)


def guard_tools(
    tools: list[BaseTool],
    config: GuardConfig | None = None,
) -> list[GuardedTool]:
    """Convenience: wrap a list of LangChain tools."""
    return [GuardedTool(t, config=config) for t in tools]