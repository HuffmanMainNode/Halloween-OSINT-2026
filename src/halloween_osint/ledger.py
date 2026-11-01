"""Offline normalization and graph summaries for operator-supplied transaction exports."""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from datetime import datetime
from pathlib import Path
from typing import Any

REQUIRED = {"txid", "from_address", "to_address", "value", "asset"}


def _load_rows(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path).expanduser()
    if source.suffix.lower() == ".csv":
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    if source.suffix.lower() == ".json":
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            raise ValueError("JSON input must be an array of transaction objects")
        return data
    raise ValueError("Input must be a .csv or .json file")


def analyze_transactions(path: str | Path) -> dict[str, Any]:
    rows = _load_rows(path)
    seen: set[str] = set()
    transactions: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    duplicates: list[str] = []

    for index, row in enumerate(rows, start=2):
        missing = sorted(key for key in REQUIRED if row.get(key) is None or str(row.get(key)).strip() == "")
        if missing:
            errors.append({"row": index, "error": "missing required fields", "fields": missing})
            continue
        txid = str(row["txid"]).strip()
        sender = str(row["from_address"]).strip()
        recipient = str(row["to_address"]).strip()
        asset = str(row["asset"]).strip().upper()
        try:
            value = Decimal(str(row["value"]))
            if not value.is_finite() or value < 0:
                raise InvalidOperation
        except (InvalidOperation, ValueError):
            errors.append({"row": index, "error": "value must be a finite non-negative decimal"})
            continue
        timestamp = str(row.get("timestamp") or "").strip() or None
        if timestamp:
            try:
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                errors.append({"row": index, "error": "timestamp must be ISO-8601"})
                continue
        if txid in seen:
            duplicates.append(txid)
            continue
        seen.add(txid)
        transactions.append({
            "txid": txid,
            "from_address": sender,
            "to_address": recipient,
            "value": format(value, "f"),
            "asset": asset,
            "timestamp": timestamp,
        })

    totals: dict[str, Decimal] = defaultdict(Decimal)
    flows: dict[str, dict[str, dict[str, Decimal]]] = defaultdict(
        lambda: {"sent": defaultdict(Decimal), "received": defaultdict(Decimal)}
    )
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for tx in transactions:
        amount = Decimal(tx["value"])
        asset = tx["asset"]
        sender, recipient = tx["from_address"], tx["to_address"]
        totals[asset] += amount
        flows[sender]["sent"][asset] += amount
        flows[recipient]["received"][asset] += amount
        key = (sender, recipient, asset)
        if key not in edges:
            edges[key] = {"from": sender, "to": recipient, "asset": asset,
                          "transaction_count": 0, "total_value": Decimal(0)}
        edges[key]["transaction_count"] += 1
        edges[key]["total_value"] += amount

    return {
        "input": Path(path).name,
        "method": "offline aggregation of supplied rows; no chain lookup or identity enrichment",
        "transaction_count": len(transactions),
        "rejected_row_count": len(errors),
        "duplicate_txids": sorted(duplicates),
        "errors": errors,
        "totals_by_asset": {asset: format(value, "f") for asset, value in sorted(totals.items())},
        "address_flows": {
            address: {
                "sent_by_asset": {asset: format(value, "f") for asset, value in sorted(flow["sent"].items())},
                "received_by_asset": {asset: format(value, "f") for asset, value in sorted(flow["received"].items())},
            }
            for address, flow in sorted(flows.items())
        },
        "edges": [
            {"from": item["from"], "to": item["to"], "asset": item["asset"],
             "transaction_count": item["transaction_count"], "total_value": format(item["total_value"], "f")}
            for _, item in sorted(edges.items())
        ],
        "transactions": transactions,
        "limitations": [
            "Rows are treated as supplied facts and are not validated against a blockchain.",
            "Addresses and labels are not attributed to people or organizations.",
            "Values for different assets are never combined.",
            "Fees, token decimals, fiat conversion, and chain-specific semantics are not inferred.",
        ],
    }
