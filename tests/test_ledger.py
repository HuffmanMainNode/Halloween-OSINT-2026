import csv

from halloween_osint.ledger import analyze_transactions


def test_ledger_aggregates_per_asset_and_flags_duplicate(tmp_path):
    path = tmp_path / "transactions.csv"
    rows = [
        ["txid", "from_address", "to_address", "value", "asset", "timestamp"],
        ["a", "A", "B", "1.25", "COIN", "2026-10-31T12:00:00Z"],
        ["b", "B", "C", "0.5", "COIN", "2026-10-31T12:01:00Z"],
        ["b", "B", "C", "0.5", "COIN", "2026-10-31T12:01:00Z"],
        ["c", "A", "D", "10", "TOKEN", ""],
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerows(rows)
    result = analyze_transactions(path)
    assert result["transaction_count"] == 3
    assert result["duplicate_txids"] == ["b"]
    assert result["totals_by_asset"] == {"COIN": "1.75", "TOKEN": "10"}
    assert result["address_flows"]["A"]["sent_by_asset"] == {"COIN": "1.25", "TOKEN": "10"}
    assert result["address_flows"]["B"]["received_by_asset"] == {"COIN": "1.25"}
    assert result["address_flows"]["B"]["sent_by_asset"] == {"COIN": "0.5"}


def test_bad_amount_rejected(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("txid,from_address,to_address,value,asset\nx,A,B,-2,COIN\n", encoding="utf-8")
    result = analyze_transactions(path)
    assert result["transaction_count"] == 0
    assert result["rejected_row_count"] == 1
