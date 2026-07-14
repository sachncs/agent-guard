"""Quick smoke test for the Python SDK."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Ensure cargo bin on PATH
cargo_bin = Path.home() / ".cargo" / "bin"
if cargo_bin.exists() and str(cargo_bin) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")

# Initialize a store
store = ROOT / ".agentguard"
if store.exists():
    shutil.rmtree(store)
subprocess.run(["agentguard", "init", "--name", "sdktest"], cwd=ROOT, check=True)

# Install SDK if not already
sdk_path = ROOT.parent / "python" / "agentguard"
subprocess.run([sys.executable, "-m", "pip", "install", "-e", str(sdk_path)], check=True, capture_output=True)

# Use it
os.chdir(ROOT)

from agentguard import Client, Principal, AgentAction, Resource, Context  # noqa: E402

client = Client(store=str(store))

# Allow case: admin
decision = client.check(
    Principal.user("admin"),
    AgentAction.tool("send_email"),
    Resource("Mailbox", "alice@acme"),
    Context(args={"to": "[email protected]", "subject": "hi", "body": "hello"},
            session={"ip": "10.0.0.1", "user_agent": "x", "mfa": True, "ts": 0}),
)
print(f"admin → allow: {decision.allow}")

# Deny case: random user
try:
    client.check(
        Principal.user("eve"),
        AgentAction.tool("send_email"),
        Resource("Mailbox", "alice@acme"),
        Context(args={"to": "[email protected]", "subject": "hi", "body": "hello"},
                session={"ip": "10.0.0.1", "user_agent": "x", "mfa": True, "ts": 0}),
    )
    print("eve → unexpected ALLOW")
except Exception as e:
    print(f"eve → denied (expected): {e}")

# Delegation
token = client.delegate(
    from_principal='Agent::"research"',
    to='Agent::"summarizer"',
    actions=["ToolCall::send_email"],
    resources=["Mailbox::*"],
    ttl_seconds=120,
)
print(f"token: {token[:60]}...")
print("\n✓ SDK smoke test passed")