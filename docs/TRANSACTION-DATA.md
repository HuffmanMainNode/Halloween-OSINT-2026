# Transaction input format

The ledger analyzer is deliberately offline. It consumes a CSV or JSON export supplied by the operator and does not contact a chain explorer or node.

## CSV

Required columns:

- `txid`: transaction identifier in the supplied dataset
- `from_address`: sending address or source label
- `to_address`: receiving address or destination label
- `value`: non-negative decimal amount as text
- `asset`: asset/ticker label
- `timestamp`: optional ISO-8601 timestamp

Example:

```csv
txid,from_address,to_address,value,asset,timestamp
tx-001,wallet-A,wallet-B,1.25,COIN,2026-10-31T12:00:00Z
tx-002,wallet-B,wallet-C,0.50,COIN,2026-10-31T12:05:00Z
```

## JSON

A JSON array of objects using the same field names is accepted.

## Interpretation

Each row is treated as one supplied transfer record. The analyzer calculates totals and address-to-address edges within the supplied rows. It does not validate chain inclusion, confirmations, token decimals, fees, exchange rates, or whether labels identify real entities. Values for different assets are never combined. Duplicate transaction IDs are reported and excluded after the first occurrence. Missing or malformed values are rejected with row-level errors.

A shared address or transfer path is a data relationship, not proof of common ownership or intent. Use chain-specific validation and independent sources before drawing conclusions.
