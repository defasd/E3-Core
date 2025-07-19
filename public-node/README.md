# Public Node - E3-Core DAO

## Overview
The Public Node handles user transactions, staking, validator registration, and processes admin events (mint, burn, proof-of-reserve) from the admin node.

## How to Run
```
cargo run -p public-node -- ./public_node_db 4002
```
- `./public_node_db`: Path to the RocksDB database (will be created if it doesn't exist)
- `4002`: P2P port (HTTP API will be on port 5002)

## Key Endpoints (HTTP API on port 5002)
- `POST /api/submit-transaction` - Submit a user transaction
- `POST /api/stake` - Stake tokens
- `POST /api/unstake` - Unstake tokens
- `POST /api/register-validator` - Register as a validator
- `GET /api/balance/:address` - Get balance for an address
- `POST /api/admin-mint` - (admin event, usually internal)
- `POST /api/sync-admin` - Sync with admin node

## Example: Check Balance
```
curl http://localhost:5002/api/balance/123
```

## Example: Submit Transaction
```
curl -X POST http://localhost:5002/api/submit-transaction \
  -H "Content-Type: application/json" \
  -d '{
    "from": "123",
    "to": "456",
    "amount": 10,
    "signature": "SIG",
    "token": "GU"
  }'
```

## Testing Steps
1. Start the public node as above.
2. Mint tokens from the admin node.
3. Use `/api/balance/:address` to verify the balance is updated.
4. Submit a transaction and check the result.

---
See the main project documentation for more details.
