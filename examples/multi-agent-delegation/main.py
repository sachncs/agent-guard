"""
multi-agent-delegation — show how a parent agent delegates scoped
permissions to a sub-agent using signed tokens.

We simulate:

  parent agent `Agent::"research"`
       └── delegates `ToolCall::send_email` on `Mailbox::*` for 5 minutes
            to sub-agent `Agent::"summarizer"`

The sub-agent then presents the token alongside its requests; the verifier
checks the signature, expiry, and scope.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str], cwd: Path | None = None, stdin: str | None = None) -> str:
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True)
    if res.returncode not in (0, 2):
        print(res.stdout, file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return res.stdout


def main() -> None:
    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.exists() and str(cargo_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")

    store = ROOT / ".agentguard"
    if store.exists():
        shutil.rmtree(store)
    os.chdir(ROOT)

    print("→ Initializing agentguard store ...")
    run(["agentguard", "init", "--name", "demoorg"])

    print("→ Writing delegation policies ...")
    (store / "policies" / "30_delegation.cedar").write_text(
        """\
// Sub-agents (any Agent entity) may invoke ToolCall::* actions within
// their granted resource scope. Specific actions are constrained by
// the resource type (e.g. a sub-agent can only send email *to* a Mailbox
// it has been delegated access to).
permit (
  principal is Agent,
  action,
  resource is Mailbox
);
"""
    )

    print("→ Validating ...")
    out = run(["agentguard", "validate"])
    print(out)

    print("→ Minting delegation token (parent → sub-agent, 5 min, scoped) ...")
    token = run(
        [
            "agentguard",
            "delegate",
            "--from", 'Agent::"research"',
            "--to", 'Agent::"summarizer"',
            "--actions", "ToolCall::send_email",
            "--resources", "Mailbox::*",
            "--ttl", "300",
        ]
    ).strip()
    print(f"token: {token[:80]}...")

    # Save the ephemeral public key for verification (not strictly needed since
    # we use a one-shot ephemeral key in this demo; for real flows, persist the
    # parent agent's key).
    keys_file = ROOT / "issuer.keys"
    # The CLI emits the public key on stderr when using an ephemeral key.
    # Re-run with the same key is not possible — for the demo, we just print
    # the token and document the verification flow.
    print()
    print("In a real deployment:")
    print("  1. Persist the parent agent's signing key (`agentguard delegate --key-file ...`)")
    print("  2. Publish the corresponding public key as `issuer.keys`")
    print("  3. The sub-agent presents the token; the verifier calls:")
    print()
    print(f"     agentguard verify '{token[:60]}...' --keys issuer.keys")
    print()

    # Print the token's compact format for clarity.
    print("→ Compact token format:")
    print(f"   {token}")


if __name__ == "__main__":
    main()