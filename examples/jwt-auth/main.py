"""
examples/jwt-auth — show how to pass a bearer token to the agentguard CLI.

In a production deployment, the agentgateway runs as `agentguard serve` and
authenticates the caller via JWT. In the subprocess path (this example),
the bearer token is passed via the AGENTGUARD_BEARER environment variable.

This example:
  1. Initializes a fresh agentguard store.
  2. Forges a simple unsigned JWT (HS256) for "alice" with a `sub` and
     `aud=agentguard`. In real life, this would come from your IdP.
  3. Mints a verification key and adds it to the store (skipped in this
     example; production keeps keys out-of-band).
  4. Uses the Python SDK to authorize a request as alice.

Note: this is a DEMO of the SDK surface. The actual JWT validation lives
in the auth crate (Stage 3) and is exercised by the server in Stage 7.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Put cargo bin on PATH so the agentguard binary is findable.
cargo_bin = Path.home() / ".cargo" / "bin"
if cargo_bin.exists() and str(cargo_bin) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_unsigned_jwt(sub: str, aud: str) -> str:
    """Forge an unsigned (alg=none) JWT for the demo.

    Production tokens are always signed — your IdP issues them, you
    verify them via the agentguard JWT validator.
    """
    header = {"alg": "none", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": "demo-idp",
        "sub": sub,
        "aud": aud,
        "iat": now,
        "exp": now + 3600,
    }
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def main() -> None:
    store = ROOT / ".agentguard"
    if store.exists():
        shutil.rmtree(store)
    os.chdir(ROOT)

    print("→ Initializing agentguard store ...")
    subprocess.run(["agentguard", "init", "--name", "jwt-demo"], check=True)

    # Mint a fake bearer token. We pass it as the SDK's bearer_token which
    # the CLI receives as AGENTGUARD_BEARER.
    token = make_unsigned_jwt("alice", "agentguard")
    print(f"→ Bearer token (alg=none for demo): {token[:60]}...")

    print("→ Using Python SDK with bearer token ...")
    sys.path.insert(0, str(ROOT.parent.parent / "python" / "agentguard" / "src"))
    from agentguard import Client, Principal, AgentAction, Resource, Context

    client = Client(
        store=str(store),
        bearer_token=token,
        traceparent="00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    )

    decision = client.authorize(
        Principal.user("alice"),
        AgentAction.tool("send_email"),
        Resource("Mailbox", "alice@acme"),
        Context(args={"to": "[email protected]"}, session={"ip": "10.0.0.1", "mfa": True}),
    )
    print(f"  decision.effect = {decision.effect.value}")
    print(f"  decision.policies = {decision.policies}")

    print("\n✓ example complete")


if __name__ == "__main__":
    main()