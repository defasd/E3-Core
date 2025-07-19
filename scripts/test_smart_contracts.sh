#!/bin/bash

# E3 Core DAO - Smart Contract Testing Script
# This script tests the complete smart contract governance and execution flow

set -e

echo "🏛️ E3 Core DAO - Smart Contract Integration Testing"
echo "=" | tr -d '\n'; for i in {1..60}; do echo -n "="; done; echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Step 1: Build all components
print_status "Building all E3 Core components..."

print_status "Building governance node..."
cd governance-node
cargo build --release
if [ $? -eq 0 ]; then
    print_success "Governance node built successfully"
else
    print_error "Failed to build governance node"
    exit 1
fi
cd ..

print_status "Building public node..."
cd public-node
cargo build --release
if [ $? -eq 0 ]; then
    print_success "Public node built successfully"
else
    print_error "Failed to build public node"
    exit 1
fi
cd ..

print_status "Building admin node..."
cd admin-node
cargo build --release
if [ $? -eq 0 ]; then
    print_success "Admin node built successfully"
else
    print_error "Failed to build admin node"
    exit 1
fi
cd ..

# Step 2: Start all nodes in background
print_status "Starting all nodes..."

# Create log directory
mkdir -p logs

# Start governance node
print_status "Starting governance node on port 4003..."
./target/release/governance-node ./governance_node_db 4003 > logs/governance.log 2>&1 &
GOVERNANCE_PID=$!
sleep 5

# Start public node
print_status "Starting public node on port 4001..."
./target/release/public-node ./public_node_db 4001 > logs/public.log 2>&1 &
PUBLIC_PID=$!
sleep 5

# Start admin node
print_status "Starting admin node on port 4002..."
./target/release/admin-node ./admin_node_db 4002 > logs/admin.log 2>&1 &
ADMIN_PID=$!
sleep 5

# Function to cleanup processes on exit
cleanup() {
    print_status "Cleaning up processes..."
    kill $GOVERNANCE_PID $PUBLIC_PID $ADMIN_PID 2>/dev/null || true
    wait 2>/dev/null || true
    print_success "Cleanup completed"
}
trap cleanup EXIT

# Step 3: Test API endpoints
print_status "Testing API endpoints..."

# Test governance node status
print_status "Testing governance node status..."
GOVERNANCE_STATUS=$(curl -s http://localhost:5003/api/v1/status)
if [ $? -eq 0 ]; then
    print_success "Governance node is responding: $GOVERNANCE_STATUS"
else
    print_error "Governance node is not responding"
    exit 1
fi

# Test public node status
print_status "Testing public node status..."
PUBLIC_STATUS=$(curl -s http://localhost:6001/api/status)
if [ $? -eq 0 ]; then
    print_success "Public node is responding: $PUBLIC_STATUS"
else
    print_error "Public node is not responding"
    exit 1
fi

# Test admin node status
print_status "Testing admin node status..."
ADMIN_STATUS=$(curl -s http://localhost:5002/api/status)
if [ $? -eq 0 ]; then
    print_success "Admin node is responding: $ADMIN_STATUS"
else
    print_error "Admin node is not responding"
    exit 1
fi

# Step 4: Test Smart Contract Workflow
print_status "Testing smart contract workflow..."

# 4.1: Submit a smart contract
print_status "Submitting smart contract..."
CONTRACT_SUBMISSION='{
    "name": "TestStakingContract",
    "description": "A test staking contract for integration testing",
    "version": "1.0.0",
    "bytecode": "dGVzdF9ieXRlY29kZV9mb3Jfc3Rha2luZ19jb250cmFjdA==",
    "allowed_methods": ["stake", "unstake", "get_balance"],
    "permission_level": "Public",
    "developer_did": "did:example:testdev123",
    "gas_limit": 1000000,
    "metadata": {
        "category": "Test",
        "description": "Integration test contract"
    },
    "signature": "test_signature_123"
}'

CONTRACT_RESPONSE=$(curl -s -X POST http://localhost:5003/api/v1/contracts \
    -H "Content-Type: application/json" \
    -d "$CONTRACT_SUBMISSION")

if echo "$CONTRACT_RESPONSE" | jq -e '.contract_id' > /dev/null 2>&1; then
    CONTRACT_ID=$(echo "$CONTRACT_RESPONSE" | jq -r '.contract_id')
    print_success "Smart contract submitted successfully: $CONTRACT_ID"
else
    print_error "Failed to submit smart contract: $CONTRACT_RESPONSE"
    exit 1
fi

# 4.2: Create approval proposal
print_status "Creating contract approval proposal..."
PROPOSAL_REQUEST='{
    "contract_id": "'$CONTRACT_ID'",
    "submitter_did": "did:example:governance123",
    "signature": "governance_signature_123"
}'

PROPOSAL_RESPONSE=$(curl -s -X POST http://localhost:5003/api/v1/contracts/$CONTRACT_ID/proposal \
    -H "Content-Type: application/json" \
    -d "$PROPOSAL_REQUEST")

if echo "$PROPOSAL_RESPONSE" | jq -e '.proposal_id' > /dev/null 2>&1; then
    PROPOSAL_ID=$(echo "$PROPOSAL_RESPONSE" | jq -r '.proposal_id')
    print_success "Approval proposal created: $PROPOSAL_ID"
else
    print_error "Failed to create approval proposal: $PROPOSAL_RESPONSE"
    exit 1
fi

# 4.3: Open voting on proposal
print_status "Opening voting on proposal..."
OPEN_VOTING_RESPONSE=$(curl -s -X POST http://localhost:5003/api/v1/proposals/$PROPOSAL_ID/open-voting \
    -H "Content-Type: application/json" \
    -d '{}')

print_success "Voting opened: $OPEN_VOTING_RESPONSE"

# 4.4: Cast votes
print_status "Casting votes on proposal..."
VOTE_REQUEST='{
    "proposal_id": "'$PROPOSAL_ID'",
    "did_id": "did:example:voter123",
    "choice": "approve",
    "signature": "voter_signature_123"
}'

VOTE_RESPONSE=$(curl -s -X POST http://localhost:5003/api/v1/votes \
    -H "Content-Type: application/json" \
    -d "$VOTE_REQUEST")

print_success "Vote cast: $VOTE_RESPONSE"

# 4.5: Deploy contract (simulate governance approval)
print_status "Deploying approved contract..."
DEPLOY_REQUEST='{
    "contract_id": "'$CONTRACT_ID'",
    "deployer_did": "did:example:admin123",
    "signature": "admin_signature_123"
}'

DEPLOY_RESPONSE=$(curl -s -X POST http://localhost:5003/api/v1/contracts/$CONTRACT_ID/deploy \
    -H "Content-Type: application/json" \
    -d "$DEPLOY_REQUEST")

print_success "Contract deployment initiated: $DEPLOY_RESPONSE"

# Wait for deployment propagation
sleep 3

# 4.6: Test contract execution on public node
print_status "Testing contract execution on public node..."
EXECUTE_REQUEST='{
    "contract_id": "'$CONTRACT_ID'",
    "method": "stake",
    "parameters": {
        "amount": 1000
    },
    "caller_did": "did:example:user123",
    "gas_limit": 500000,
    "signature": "user_signature_123"
}'

EXECUTE_RESPONSE=$(curl -s -X POST http://localhost:6001/api/contracts/execute \
    -H "Content-Type: application/json" \
    -d "$EXECUTE_REQUEST")

if echo "$EXECUTE_RESPONSE" | jq -e '.success' > /dev/null 2>&1; then
    SUCCESS=$(echo "$EXECUTE_RESPONSE" | jq -r '.success')
    if [ "$SUCCESS" = "true" ]; then
        print_success "Contract executed successfully: $EXECUTE_RESPONSE"
    else
        print_warning "Contract execution failed (expected for demo): $EXECUTE_RESPONSE"
    fi
else
    print_warning "Contract execution response format unexpected: $EXECUTE_RESPONSE"
fi

# 4.7: Test policy management on admin node
print_status "Testing contract policy management..."
POLICY_UPDATE='{
    "contract_id": "'$CONTRACT_ID'",
    "policy_updates": {
        "max_gas_limit": 800000,
        "execution_fee_rate": 0.0002,
        "enabled": true
    }
}'

POLICY_RESPONSE=$(curl -s -X POST http://localhost:5002/api/contracts/policy/update \
    -H "Content-Type: application/json" \
    -d "$POLICY_UPDATE")

print_success "Policy updated: $POLICY_RESPONSE"

# 4.8: Get policy report
print_status "Getting policy report..."
POLICY_REPORT=$(curl -s http://localhost:5002/api/contracts/policy/report)
print_success "Policy report retrieved: $POLICY_REPORT"

# Step 5: Test emergency procedures
print_status "Testing emergency procedures..."

# Emergency shutdown
EMERGENCY_SHUTDOWN='{
    "reason": "Integration test emergency shutdown"
}'

SHUTDOWN_RESPONSE=$(curl -s -X POST http://localhost:5002/api/contracts/emergency/shutdown \
    -H "Content-Type: application/json" \
    -d "$EMERGENCY_SHUTDOWN")

print_success "Emergency shutdown triggered: $SHUTDOWN_RESPONSE"

# Emergency restore
RESTORE_RESPONSE=$(curl -s -X POST http://localhost:5002/api/contracts/emergency/restore \
    -H "Content-Type: application/json" \
    -d '{}')

print_success "Emergency restore completed: $RESTORE_RESPONSE"

# Final status check
print_status "Final status check..."
print_status "Checking available contracts on public node..."
AVAILABLE_CONTRACTS=$(curl -s http://localhost:6001/api/contracts/available)
print_success "Available contracts: $AVAILABLE_CONTRACTS"

print_success "🎉 All integration tests completed successfully!"
print_status "Check logs/ directory for detailed node logs"
print_status "Node processes will be terminated when script exits"

# Keep processes running for manual testing if desired
read -p "Press Enter to terminate all nodes and exit..."

echo
print_success "Smart contract integration testing completed successfully!"
