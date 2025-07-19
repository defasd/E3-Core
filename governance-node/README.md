# Governance Node - E3-Core DAO

## Overview
The Governance Node manages proposals, voting, DIDs, and treasury operations. It exposes endpoints for submitting proposals, casting votes, and querying governance state.

## How to Run
```
cargo run -p governance-node -- ./governance_node_db 4003
```
- `./governance_node_db`: Path to the RocksDB database (will be created if it doesn't exist)
- `4003`: P2P port (HTTP API will be on port 5003)

## Key Endpoints (HTTP API on port 5003)
- `POST /api/v1/proposals` - Submit a proposal
- `POST /api/v1/votes` - Cast a vote
- `GET /api/v1/proposals/:id/results` - Get proposal results
- `POST /api/v1/proposals/:id/open-voting` - Open voting on a proposal
- `POST /api/v1/proposals/:id/finalize` - Finalize a proposal
- `GET /api/v1/status` - Get node status

## Example: Submit Proposal
```
curl -X POST http://localhost:5003/api/v1/proposals \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Proposal",
    "description": "A test proposal.",
    "category": "Treasury",
    "submitter_did": "did:example:123",
    "voting_duration_hours": 24,
    "signature": "SIG"
  }'
```

## Testing Steps
1. Start the governance node as above.
2. Submit a proposal using the `/api/v1/proposals` endpoint.
3. Open voting, cast votes, and finalize the proposal.
4. Query results and status endpoints to verify state.

---
See the main project documentation for more details.
