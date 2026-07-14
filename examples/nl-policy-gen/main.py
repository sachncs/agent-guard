"""
nl-policy-gen — turn a natural-language description into a Cedar policy
using an LLM, then validate the result against your schema.

Requirements:
    export OPENAI_API_KEY=sk-...

Run:
    python examples/nl-policy-gen/main.py "Only admins in the security group can rotate production secrets"
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str], cwd: Path | None = None) -> str:
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    print(res.stdout, file=sys.stderr)
    if res.stderr:
        print(res.stderr, file=sys.stderr)
    return res.stdout


def main() -> None:
    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.exists() and str(cargo_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")

    if len(sys.argv) < 2:
        print("usage: main.py <natural-language-description>")
        sys.exit(1)

    description = sys.argv[1]

    store = ROOT / ".agentguard"
    if store.exists():
        shutil.rmtree(store)

    if not os.environ.get("OPENAI_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        print("set OPENAI_API_KEY or ANTHROPIC_API_KEY to use NL policy generation", file=sys.stderr)
        sys.exit(2)

    print("→ Initializing store ...")
    run(["agentguard", "init", "--name", "demoorg"], cwd=ROOT)

    print(f"→ Generating policy from: '{description}'")
    run(["agentguard", "gen", description, "--name", "90_generated"], cwd=ROOT)

    print("→ Validating (including the generated policy) ...")
    out = run(["agentguard", "validate"], cwd=ROOT)

    if "ERR" in out:
        print("\n✗ generated policy failed validation — review and refine the prompt")
        sys.exit(1)
    else:
        print("\n✓ generated policy passes schema validation")


if __name__ == "__main__":
    main()