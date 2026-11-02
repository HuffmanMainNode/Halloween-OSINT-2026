"""Command-line interface for Halloween OSINT 2026."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .evm_rpc import inspect_transaction
from .evidence import create_manifest, verify_manifest
from .infrastructure import observe_domain
from .ledger import analyze_transactions

from . import __version__


def _write(data: Any, output: str | None) -> None:
    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if output:
        Path(output).expanduser().write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="halloween-osint", description="Local-first investigative utilities")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    hash_cmd = sub.add_parser("hash", help="Create a SHA-256 evidence manifest")
    hash_cmd.add_argument("directory")
    hash_cmd.add_argument("--output", required=True)

    verify_cmd = sub.add_parser("verify", help="Verify a SHA-256 evidence manifest")
    verify_cmd.add_argument("manifest")

    domain_cmd = sub.add_parser("domain", help="Passively observe DNS and TLS for a supplied hostname")
    domain_cmd.add_argument("hostname")
    domain_cmd.add_argument("--timeout", type=float, default=5.0)
    domain_cmd.add_argument("--output")

    ledger_cmd = sub.add_parser("ledger", help="Analyze a supplied CSV or JSON transaction export")
    ledger_sub = ledger_cmd.add_subparsers(dest="ledger_command", required=True)
    analyze_cmd = ledger_sub.add_parser("analyze")
    analyze_cmd.add_argument("input")
    analyze_cmd.add_argument("--output")

    evm_cmd = sub.add_parser("evm", help="Read-only EVM JSON-RPC inspection")
    evm_sub = evm_cmd.add_subparsers(dest="evm_command", required=True)
    inspect_cmd = evm_sub.add_parser("inspect", help="Inspect a transaction using your own RPC node")
    inspect_cmd.add_argument("--rpc-url", required=True)
    inspect_cmd.add_argument("tx_hash")
    inspect_cmd.add_argument("--timeout", type=float, default=10.0)
    inspect_cmd.add_argument("--output")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "hash":
            result = create_manifest(args.directory, args.output)
            _write({"manifest": args.output, "file_count": len(result["files"]), "algorithm": "sha256"}, None)
            return 0
        if args.command == "verify":
            result = verify_manifest(args.manifest)
            _write(result, None)
            return 0 if result["verified"] else 2
        if args.command == "domain":
            _write(observe_domain(args.hostname, args.timeout), args.output)
            return 0
        if args.command == "ledger" and args.ledger_command == "analyze":
            _write(analyze_transactions(args.input), args.output)
            return 0
        if args.command == "evm" and args.evm_command == "inspect":
            _write(inspect_transaction(args.rpc_url, args.tx_hash, args.timeout), args.output)
            return 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
