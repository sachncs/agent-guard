"""Main client class for the agentguard SDK."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Sequence

from .errors import AgentguardError, AuthorizationDenied, CLIUnavailable
from .models import (
    AgentAction,
    Context,
    Decision,
    Principal,
    Resource,
)


def _find_cli() -> str:
    """Locate the agentguard binary."""
    env = os.environ.get("AGENTGUARD_BIN")
    if env and os.path.isfile(env):
        return env
    on_path = shutil.which("agentguard")
    if on_path:
        return on_path
    # Common cargo install locations.
    cargo_bin = Path.home() / ".cargo" / "bin" / "agentguard"
    if cargo_bin.exists():
        return str(cargo_bin)
    raise CLIUnavailable(
        "agentguard CLI not found. Install with: cargo install --path crates/agentguard-cli"
    )


class Client:
    """High-level interface to the agentguard authorization engine.

    Wraps the `agentguard` CLI binary. Python SDK adds no policy-evaluation
    logic of its own — all decisions come from the Rust core.
    """

    def __init__(
        self,
        store: str | Path = ".agentguard",
        audit_log: str | Path = ".audit/decisions.jsonl",
        cli_bin: str | None = None,
    ) -> None:
        self.store = str(store)
        self.audit_log = str(audit_log)
        self.cli = cli_bin or _find_cli()

    def _run(self, args: Sequence[str], stdin: str | None = None) -> str:
        cmd = [self.cli, "--store", self.store, "--audit", self.audit_log, *args]
        try:
            res = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError as e:
            raise CLIUnavailable(f"agentguard CLI not found at {self.cli}: {e}") from e
        if res.returncode not in (0, 2):
            raise AgentguardError(f"agentguard CLI failed: {res.stderr.strip() or res.stdout.strip()}")
        return res.stdout

    # --- Authorization -----------------------------------------------------

    def authorize(
        self,
        principal: Principal,
        action: AgentAction,
        resource: Resource,
        context: Context | None = None,
        *,
        entities: list[dict[str, Any]] | None = None,
        audit: bool = True,
        check: bool = False,
    ) -> Decision:
        """Evaluate an authorization request. If `check=True`, raise on Deny."""
        req = {
            "principal": principal.to_json(),
            "action": action.to_json(),
            "resource": resource.to_json(),
            "context": (context or Context()).to_json(),
        }
        stdin_json = json.dumps(req)
        args = ["--output", "json", "authorize", "-"]
        if not audit:
            args.append("--no-audit")
        if entities is not None:
            args.extend(["--entities", "<inline>"])

        out = self._run(args, stdin=stdin_json)
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            raise AgentguardError(f"could not parse CLI output: {out!r}")

        decision = Decision.from_json(data)
        if check and decision.deny:
            raise AuthorizationDenied(decision)
        return decision

    def check(
        self,
        principal: Principal,
        action: AgentAction,
        resource: Resource,
        context: Context | None = None,
    ) -> Decision:
        """Like authorize(), but raise AuthorizationDenied on Deny."""
        return self.authorize(principal, action, resource, context, check=True)

    # --- Policies -----------------------------------------------------------

    def validate(self) -> dict[str, Any]:
        """Validate policies. Returns parsed output."""
        out = self._run(["validate"])
        return {"raw": out}

    def init(self, name: str = "myorg") -> None:
        """Initialize a new agentguard store."""
        self._run(["init", "--name", name])

    # --- Delegation ---------------------------------------------------------

    def delegate(
        self,
        from_principal: str,
        to: str,
        actions: Iterable[str],
        resources: Iterable[str],
        ttl_seconds: int = 900,
        key_file: str | None = None,
        out_file: str | None = None,
    ) -> str:
        """Mint a delegation token. Returns the compact token string."""
        args = [
            "delegate",
            "--from", from_principal,
            "--to", to,
            "--actions", *actions,
            "--resources", *resources,
            "--ttl", str(ttl_seconds),
        ]
        if key_file:
            args.extend(["--key-file", key_file])
        if out_file:
            args.extend(["--out", out_file])
        return self._run(args).strip()

    def verify(self, token: str, keys_file: str) -> dict[str, Any]:
        """Verify a delegation token. Returns claims as a dict."""
        out = self._run(["--output", "json", "verify", token, "--keys", keys_file])
        return json.loads(out)

    # --- Logging ------------------------------------------------------------

    def log_tail(
        self,
        n: int = 20,
        principal: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        """Show last N decisions."""
        args = ["log", "tail", "--n", str(n)]
        if principal:
            args.extend(["--principal", principal])
        if action:
            args.extend(["--action", action])
        out = self._run(["--output", "json", *args])
        return json.loads(out)