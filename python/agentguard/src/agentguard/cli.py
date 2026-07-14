"""Thin CLI wrapper so users can run the Python SDK as `agentguard-py`."""

from __future__ import annotations

import sys
from .client import Client


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: agentguard-py <store-path> [subcommand ...]")
        return 0
    store = argv[0]
    sub = argv[1:]
    client = Client(store=store)
    if sub and sub[0] == "validate":
        client.validate()
        return 0
    if sub and sub[0] == "init":
        client.init()
        return 0
    print(f"unknown subcommand: {sub}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())