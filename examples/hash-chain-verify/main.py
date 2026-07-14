"""
examples/hash-chain-verify — show how to use a hash-chained audit log and
verify its integrity.

Steps:
  1. Initialize a chained audit log.
  2. Make several decisions (each writes a chained record).
  3. Verify the chain.
  4. Tamper with a record.
  5. Re-verify — the verifier must reject.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

cargo_bin = Path.home() / ".cargo" / "bin"
if cargo_bin.exists() and str(cargo_bin) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")


def main() -> None:
    os.chdir(ROOT)

    # Set up a chained log
    log_path = ROOT / "chained.jsonl"
    secret_path = ROOT / ".chain-secret"
    if log_path.exists():
        log_path.unlink()
    if secret_path.exists():
        secret_path.unlink()
    secret_path.write_bytes(b"example-chain-secret-32-bytes")

    # Make a few decisions
    print("→ Making 3 decisions (chained audit log) ...")
    sys.path.insert(0, str(ROOT.parent.parent / "python" / "agentguard" / "src"))
    from agentguard import Client, Principal, AgentAction, Resource, Context  # noqa: F401

    store = ROOT / ".agentguard"
    if store.exists():
        shutil.rmtree(store)
    subprocess.run(["agentguard", "init", "--name", "hash-demo"], check=True)
    # Add a permissive policy so decisions produce all-allow.
    (store / "policies" / "30_permit_all.cedar").write_text(
        "permit (principal, action, resource);\n"
    )

    # Note: writing the chained log via the Python SDK requires a chained
    # DecisionLog, which lives in the Rust core. The CLI uses open_with_chain
    # if AGENTGUARD_CHAIN_SECRET is set. We do that here.
    env = os.environ.copy()
    env["AGENTGUARD_CHAIN_SECRET"] = str(secret_path)
    env["AGENTGUARD_AUDIT"] = str(log_path)

    # Pass the secret + audit path through the SDK so the SDK's subprocess
    # call to the CLI inherits them.
    os.environ["AGENTGUARD_CHAIN_SECRET"] = str(secret_path)
    os.environ["AGENTGUARD_AUDIT"] = str(log_path)
    for i in range(3):
        # Bypass the Python SDK and invoke the CLI directly with the chain
        # secret so each record is HMAC-signed.
        req = {
            "principal": {"type": "user", "uid": f"alice{i}", "attrs": {}},
            "action": {"tool": "send_email"},
            "resource": {"entity_type": "Mailbox", "uid": f"alice{i}@acme", "attrs": {}},
            "context": {
                "args": {
                    "to": "[email protected]",
                    "subject": "hi",
                    "body": "hello",
                },
                "session": {"ip": "10.0.0.1", "user_agent": "x", "mfa": True, "ts": 0},
            },
        }
        req_path = ROOT / f"req{i}.json"
        req_path.write_text(json.dumps(req))
        result = subprocess.run(
            ["agentguard", "--output", "json", "authorize", str(req_path)],
            capture_output=True, text=True, env=env,
        )
        try:
            data = json.loads(result.stdout)
            effect = data.get("effect", "?")
        except json.JSONDecodeError:
            effect = f"parse-error: {result.stdout[:80]}"
        print(f"  decision {i}: {effect}")
        req_path.unlink()

    print()
    print("→ Verifying chain ...")
    result = subprocess.run(
        ["agentguard", "audit", "verify", "--audit", str(log_path), "--secret-file", str(secret_path)],
        capture_output=True, text=True, env=env,
    )
    print(f"  exit code: {result.returncode}")
    print(f"  stdout: {result.stdout.strip()}")

    print()
    print("→ Tampering with the second record ...")
    lines = log_path.read_text().splitlines()
    if len(lines) >= 2:
        # Replace the second line's effect
        import json as _json
        rec = _json.loads(lines[1])
        rec["effect"] = "deny"
        lines[1] = _json.dumps(rec, separators=(",", ":"))
        log_path.write_text("\n".join(lines) + "\n")

    print("→ Re-verifying (must fail) ...")
    result = subprocess.run(
        ["agentguard", "audit", "verify", "--audit", str(log_path), "--secret-file", str(secret_path)],
        capture_output=True, text=True, env=env,
    )
    print(f"  exit code: {result.returncode}")
    print(f"  stderr: {result.stderr.strip()[:200]}")

    print()
    print("✓ example complete")


if __name__ == "__main__":
    main()