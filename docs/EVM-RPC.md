# Read-only EVM JSON-RPC inspection

The `halloween-osint evm inspect` command queries an EVM-compatible node selected by the operator. It calls only `eth_chainId`, `eth_getTransactionByHash`, and `eth_getTransactionReceipt`. It does not sign, broadcast, trace, or alter transactions.

## Use

```bash
halloween-osint evm inspect --rpc-url https://your-node.example/rpc 0x<64-hex-character-transaction-hash>
```

A local node may use HTTP on `localhost` or loopback. Remote endpoints must use HTTPS. Responses are size-limited. The result records the RPC host and explicitly states that node-reported data is not independent consensus verification.

Never put credentials in the RPC URL. Configure authenticated endpoints through a local secure proxy if required. Treat returned transaction data as untrusted input.
