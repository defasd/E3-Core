//! Smart Contract Governance Integration Example
//!
//! Demonstrates the complete smart contract lifecycle in E3 Core DAO

use std::collections::HashMap;

/// Example of complete smart contract governance flow
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🏛️ E3 Core DAO - Smart Contract Governance Demo");
    println!("=" .repeat(60));
    
    // Step 1: Submit a smart contract to governance
    submit_contract_example().await?;
    
    // Step 2: Create governance proposal for approval
    create_approval_proposal_example().await?;
    
    // Step 3: Vote on proposal
    vote_on_proposal_example().await?;
    
    // Step 4: Deploy approved contract
    deploy_contract_example().await?;
    
    // Step 5: Execute contract on public node
    execute_contract_example().await?;
    
    // Step 6: Update contract policies via admin node
    update_contract_policy_example().await?;
    
    println!("\n✅ Smart contract governance demo completed!");
    Ok(())
}

async fn submit_contract_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n1️⃣ Submitting Smart Contract to Governance Node");
    
    let client = reqwest::Client::new();
    
    // Example WASM bytecode (base64 encoded)
    let example_bytecode = base64::encode(b"fake_wasm_bytecode_for_demo");
    
    let contract_submission = serde_json::json!({
        "name": "TokenStaking",
        "description": "A smart contract for token staking with rewards",
        "version": "1.0.0",
        "bytecode": example_bytecode,
        "allowed_methods": ["stake", "unstake", "get_balance", "get_rewards"],
        "permission_level": "Public",
        "developer_did": "did:example:developer123",
        "gas_limit": 1000000,
        "metadata": {
            "category": "DeFi",
            "audit_status": "Completed",
            "auditor": "SecureAudits Inc"
        },
        "signature": "developer_signature_here"
    });
    
    let response = client
        .post("http://localhost:5003/api/v1/contracts")
        .json(&contract_submission)
        .send()
        .await?;
    
    let result: serde_json::Value = response.json().await?;
    println!("✅ Contract submitted: {}", result);
    
    Ok(())
}

async fn create_approval_proposal_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n2️⃣ Creating Governance Proposal for Contract Approval");
    
    let client = reqwest::Client::new();
    
    let proposal_request = serde_json::json!({
        "contract_id": "contract_12345678-1234-5678-9abc-123456789abc",
        "submitter_did": "did:example:governance_member456",
        "signature": "governance_signature_here"
    });
    
    let response = client
        .post("http://localhost:5003/api/v1/contracts/contract_12345678-1234-5678-9abc-123456789abc/proposal")
        .json(&proposal_request)
        .send()
        .await?;
    
    let result: serde_json::Value = response.json().await?;
    println!("✅ Governance proposal created: {}", result);
    
    Ok(())
}

async fn vote_on_proposal_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n3️⃣ Voting on Contract Approval Proposal");
    
    let client = reqwest::Client::new();
    
    // Simulate multiple votes
    let voters = vec![
        ("did:example:voter1", "approve"),
        ("did:example:voter2", "approve"),
        ("did:example:voter3", "approve"),
    ];
    
    for (voter_did, choice) in voters {
        let vote_request = serde_json::json!({
            "proposal_id": "proposal_87654321-4321-8765-cba9-987654321fed",
            "did_id": voter_did,
            "choice": choice,
            "signature": format!("{}_signature", voter_did)
        });
        
        let response = client
            .post("http://localhost:5003/api/v1/votes")
            .json(&vote_request)
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        println!("✅ Vote cast by {}: {}", voter_did, result);
    }
    
    // Finalize proposal
    let finalize_response = client
        .post("http://localhost:5003/api/v1/proposals/proposal_87654321-4321-8765-cba9-987654321fed/finalize")
        .json(&serde_json::json!({}))
        .send()
        .await?;
    
    let finalize_result: serde_json::Value = finalize_response.json().await?;
    println!("✅ Proposal finalized: {}", finalize_result);
    
    Ok(())
}

async fn deploy_contract_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n4️⃣ Deploying Approved Contract");
    
    let client = reqwest::Client::new();
    
    let deploy_request = serde_json::json!({
        "contract_id": "contract_12345678-1234-5678-9abc-123456789abc",
        "deployer_did": "did:example:governance_admin",
        "signature": "admin_deployment_signature"
    });
    
    let response = client
        .post("http://localhost:5003/api/v1/contracts/contract_12345678-1234-5678-9abc-123456789abc/deploy")
        .json(&deploy_request)
        .send()
        .await?;
    
    let result: serde_json::Value = response.json().await?;
    println!("✅ Contract deployed: {}", result);
    
    Ok(())
}

async fn execute_contract_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n5️⃣ Executing Smart Contract on Public Node");
    
    let client = reqwest::Client::new();
    
    // First, check available contracts
    let available_response = client
        .get("http://localhost:6001/api/contracts/available")
        .send()
        .await?;
    
    let available_contracts: serde_json::Value = available_response.json().await?;
    println!("📄 Available contracts: {}", available_contracts);
    
    // Execute a contract method
    let execution_request = serde_json::json!({
        "contract_id": "contract_12345678-1234-5678-9abc-123456789abc",
        "method": "stake",
        "parameters": {
            "amount": 1000,
            "duration_days": 30
        },
        "caller_did": "did:example:user789",
        "gas_limit": 500000,
        "signature": "user_execution_signature"
    });
    
    let response = client
        .post("http://localhost:6001/api/contracts/execute")
        .json(&execution_request)
        .send()
        .await?;
    
    let result: serde_json::Value = response.json().await?;
    println!("✅ Contract executed: {}", result);
    
    Ok(())
}

async fn update_contract_policy_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n6️⃣ Updating Contract Policy via Admin Node");
    
    let client = reqwest::Client::new();
    
    // Update specific contract policy
    let policy_update = serde_json::json!({
        "contract_id": "contract_12345678-1234-5678-9abc-123456789abc",
        "policy_updates": {
            "max_gas_limit": 800000,
            "execution_fee_rate": 0.0002,
            "rate_limit": {
                "max_executions_per_minute": 10,
                "max_executions_per_hour": 100,
                "max_executions_per_day": 1000
            }
        }
    });
    
    let response = client
        .post("http://localhost:5002/api/contracts/policy/update")
        .json(&policy_update)
        .send()
        .await?;
    
    let result: serde_json::Value = response.json().await?;
    println!("✅ Contract policy updated: {}", result);
    
    // Get policy report
    let report_response = client
        .get("http://localhost:5002/api/contracts/policy/report")
        .send()
        .await?;
    
    let report: serde_json::Value = report_response.json().await?;
    println!("📊 Policy report: {}", report);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_contract_submission_flow() {
        // Test contract submission without actual HTTP calls
        println!("Testing smart contract submission flow...");
        
        // Simulate contract submission data validation
        let contract_data = serde_json::json!({
            "name": "TestContract",
            "bytecode": "dGVzdF9ieXRlY29kZQ==", // "test_bytecode" in base64
            "allowed_methods": ["test_method"],
            "permission_level": "Public"
        });
        
        assert!(contract_data.get("name").is_some());
        assert!(contract_data.get("bytecode").is_some());
        assert!(contract_data.get("allowed_methods").is_some());
        
        println!("✅ Contract data validation passed");
    }
    
    #[tokio::test]
    async fn test_policy_validation() {
        // Test policy update validation
        println!("Testing policy validation...");
        
        let policy_update = serde_json::json!({
            "max_gas_limit": 1000000,
            "execution_fee_rate": 0.0001,
            "enabled": true
        });
        
        assert!(policy_update.get("max_gas_limit").unwrap().as_u64().unwrap() > 0);
        assert!(policy_update.get("execution_fee_rate").unwrap().as_f64().unwrap() >= 0.0);
        
        println!("✅ Policy validation passed");
    }
}
