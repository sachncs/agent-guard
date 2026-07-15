"""
basic-tool-authz — minimal example showing how to authorize a tool call.

Setup:
    cd examples/basic-tool-authz
    cp -r ../../schemas ./.agentguard_schema  # or just use the starter

For this example we run everything in a single script. We:
  1. Initialize an agentguard store in a temp dir.
  2. Write a small policy that allows specific users/agents to call send_email.
  3. Build an AgentRequest and run it through the CLI.
  4. Print the decision.

Run:
    python examples/basic-tool-authz/main.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str], cwd: Path | None = None) -> str:
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    # The CLI returns exit code 2 to signal Deny (so callers can use it in shell pipelines).
    if res.returncode not in (0, 2):
        print(res.stdout, file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return res.stdout


def main() -> None:
    # Make sure the cargo-built CLI is on PATH.
    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.exists() and str(cargo_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")

    store = ROOT / ".agentguard"
    if store.exists():
        shutil.rmtree(store)

    print("→ Initializing agentguard store ...", flush=True)
    run(["agentguard", "init", "--name", "example"], cwd=ROOT)

    print("→ Writing policies ...")
    (store / "policies").mkdir(parents=True, exist_ok=True)
    (store / "policies" / "30_specific_users.cedar").write_text(
        """\
// Specific users may send email from their own mailbox.
permit (
  principal in User::"alice",
  action == Action::"ToolCall::send_email",
  resource == Mailbox::"alice@acme"
);
"""
    )
    (store / "policies" / "40_mfa_required.cedar").write_text(
        """\
// All ToolCall actions require MFA in the session context.
//
// Cedar's Strict validator requires optional attributes to be
// accessed inside an exhaustive `if then else` (the `||` operator
// is not modelled as short-circuit by the static validator, so
// a disjunction like `!has mfa || mfa == false` still triggers
// the optional-access warning). The `if then else` form below
// is exhaustive: in the `then` branch `mfa` is statically known
// to exist; in the `else` branch it is not accessed.
forbid (
  principal,
  action,
  resource
) when {
  if context has session.mfa
  then context.session.mfa == false
  else true
};
"""
    )

    print("→ Validating ...")
    out = run(["agentguard", "validate"], cwd=ROOT)
    print(out)

    print("→ Evaluating decision: alice sending email WITHOUT MFA (should DENY) ...")
    req = {
        "principal": {"type": "user", "uid": "alice", "attrs": {}},
        "action": {"tool": "send_email"},
        "resource": {"entity_type": "Mailbox", "uid": "alice@acme", "attrs": {}},
        "context": {
            "args": {"to": "[email protected]", "subject": "hi", "body": "hello"},
            "session": {"ip": "10.0.0.1", "user_agent": "x", "mfa": False, "ts": 0},
        },
    }
    req_path = ROOT / "request.json"
    req_path.write_text(json.dumps(req))
    out = run(
        ["agentguard", "--output", "json", "authorize", str(req_path)],
        cwd=ROOT,
    )
    print(out)

    print("→ Evaluating decision: alice sending email WITH MFA (should ALLOW) ...")
    req["context"]["session"]["mfa"] = True
    req_path.write_text(json.dumps(req))
    out = run(
        ["agentguard", "--output", "json", "authorize", str(req_path)],
        cwd=ROOT,
    )
    print(out)

    print("→ Evaluating decision: bob sending email (should DENY — not in policy) ...")
    req["principal"]["uid"] = "bob"
    req_path.write_text(json.dumps(req))
    out = run(
        ["agentguard", "--output", "json", "authorize", str(req_path)],
        cwd=ROOT,
    )
    print(out)

    print("→ Decision log tail ...")
    out = run(
        ["agentguard", "log", "tail", "--n", "10"],
        cwd=ROOT,
    )
    print(out)

    print("\n✓ example complete")


if __name__ == "__main__":
    os.chdir(ROOT)
    main()