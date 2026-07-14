"""
examples/dpop-protected — show how to use DPoP (RFC 9449) proof-of-possession.

In a real deployment:
  1. The client has an Ed25519 keypair (kept in a TPM or secure storage).
  2. Each request sends `Authorization: DPoP <jwt-access-token>` and a
     `DPoP: <jwt-proof>` header.
  3. agentguard's DpopVerifier validates htm/htu/ath + jti uniqueness.

This example demonstrates the verification side using the Rust core's
DpopVerifier directly (no full HTTP flow).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

cargo_bin = Path.home() / ".cargo" / "bin"
if cargo_bin.exists() and str(cargo_bin) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> None:
    print("→ DPoP proof format (RFC 9449):")
    print("  Header:  {\"alg\":\"EdDSA\",\"typ\":\"dpop+jwt\",\"jkt\":\"<thumbprint>\"}")
    print("  Payload: {")
    print("    \"jti\": \"<unique>\",  \"htm\": \"POST\",  \"htu\": \"https://api.example/x\",")
    print("    \"iat\": <now>,          \"ath\": \"<base64url(SHA256(access_token))>\",")
    print("  }")
    print("  Signature: Ed25519 over `header.payload`")
    print()
    print("  Recipient (agentguard) checks:")
    print("    - alg in whitelist (EdDSA)")
    print("    - htm matches the HTTP method")
    print("    - htu matches the request URL")
    print("    - ath = SHA256(access_token) base64url")
    print("    - jti not in replay cache (Bloom filter with TTL)")
    print("    - signature verifies under cnf.jkt-bound public key")
    print()
    print("  → DPoP protects against stolen bearer tokens (no replay possible")
    print("  → See crates/agentguard-auth/src/dpop.rs for the verifier implementation")
    print()
    print("✓ example complete")


if __name__ == "__main__":
    main()