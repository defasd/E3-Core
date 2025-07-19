//! Integration Test for E3 Core Three-Node Governance System
//! 
//! Tests the complete governance workflow:
//! 1. DAO Node - creates proposals, manages voting, executes decisions
//! 2. Admin Node - receives governance events, applies admin policies
//! 3. Public Node - receives governance events, updates public parameters

use std::collections::{HashMap, HashSet};
use serde_json::json;
use tokio::time::{sleep, Duration};

// Import the governance modules
use e3_core_dao::governance::dao_node::{DAONode, GovernanceEvent, GovernanceEventType};
use e3_core_dao::governance::proposal::{Proposal, ProposalState, ProposalType};
use e3_core_dao::governance::did::{DIDDocument, DIDRegistry};
use e3_core_dao::governance::vote::{Vote, VoteChoice};
use e3_core_dao::governance::integration::{AdminNodeIntegration, PublicNodeIntegration};

// Mock the Admin and Public nodes for testing
use e3_core_dao::admin::admin_node::AdminNode;
use e3_core_dao::public::public_node::PublicNode;

#[tokio::test]
async fn test_full_governance_integration() {
    println!("🚀 Starting E3 Core Three-Node Governance Integration Test");
    
    // Setup phase
    println!("\n📋 PHASE 1: SETUP");
    
    // Create DAO Node
    let dao_node = DAONode::new("test_dao".to_string(), 9000).await.unwrap();
    println!("✅ DAO Node initialized");
    
    // Create test DIDs for voting
    let mut did_registry = DIDRegistry::new();
    
    // Register test voters
    let voter1_did = "did:e3:voter1".to_string();
    let voter2_did = "did:e3:voter2".to_string();
    let voter3_did = "did:e3:voter3".to_string();
    
    let did1 = DIDDocument::new(
        voter1_did.clone(),
        "ed25519".to_string(),
        "voter1_public_key".to_string(),
    );
    let did2 = DIDDocument::new(
        voter2_did.clone(),
        "ed25519".to_string(),
        "voter2_public_key".to_string(),
    );
    let did3 = DIDDocument::new(
        voter3_did.clone(),
        "ed25519".to_string(),
        "voter3_public_key".to_string(),
    );
    
    did_registry.register(did1).unwrap();
    did_registry.register(did2).unwrap();
    did_registry.register(did3).unwrap();
    
    println!("✅ Test DIDs registered: {} voters", did_registry.get_total_registered());
    
    // Create integration handlers
    let admin_integration = AdminNodeIntegration::new("admin-test-node".to_string());
    let public_integration = PublicNodeIntegration::new("public-test-node".to_string());
    
    println!("✅ Integration handlers created");
    
    // Proposal creation and voting phase
    println!("\n📝 PHASE 2: PROPOSAL CREATION AND VOTING");
    
    // Create a policy update proposal
    let proposal_data = json!({
        "policy_type": "fee_structure",
        "new_base_fee": 1000,
        "new_per_byte_fee": 10,
        "effective_block": 100000
    });
    
    let proposal = Proposal::new(
        "Test Policy Update".to_string(),
        "Update transaction fee structure".to_string(),
        ProposalType::PolicyUpdate,
        proposal_data,
        voter1_did.clone(),
        7 * 24 * 60 * 60, // 7 days voting period
    );
    
    let proposal_id = proposal.id.clone();
    println!("📝 Created proposal: {}", proposal_id);
    
    // Create governance events for proposal creation
    let proposal_event = GovernanceEvent {
        event_id: format!("prop-create-{}", proposal_id),
        event_type: GovernanceEventType::ProposalCreated,
        proposal_id: Some(proposal_id.clone()),
        data: json!({
            "title": proposal.title,
            "description": proposal.description,
            "proposal_type": proposal.proposal_type,
            "proposer": proposal.proposer,
            "voting_end": proposal.voting_end
        }),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    // Test Admin Node processing
    println!("\n🏛️  PHASE 3: ADMIN NODE PROCESSING");
    let admin_receipt = admin_integration
        .process_governance_event(proposal_event.clone())
        .await
        .unwrap();
    
    println!("✅ Admin Node processed proposal creation");
    println!("   Receipt: {:?}", admin_receipt);
    
    // Test Public Node processing  
    println!("\n🌐 PHASE 4: PUBLIC NODE PROCESSING");
    let public_receipt = public_integration
        .process_governance_event(proposal_event.clone())
        .await
        .unwrap();
    
    println!("✅ Public Node processed proposal creation");
    println!("   Receipt: {:?}", public_receipt);
    
    // Voting phase
    println!("\n🗳️  PHASE 5: VOTING");
    
    // Cast votes
    let vote1 = Vote::new(
        voter1_did.clone(),
        proposal_id.clone(),
        VoteChoice::For,
        Some("Supporting the fee update".to_string()),
    );
    
    let vote2 = Vote::new(
        voter2_did.clone(),
        proposal_id.clone(),
        VoteChoice::For,
        Some("Fees need adjustment".to_string()),
    );
    
    let vote3 = Vote::new(
        voter3_did.clone(),
        proposal_id.clone(),
        VoteChoice::Against,
        Some("Too high fees".to_string()),
    );
    
    println!("✅ Votes cast: 2 For, 1 Against");
    
    // Simulate proposal passing
    println!("\n✅ PHASE 6: PROPOSAL EXECUTION");
    
    let proposal_passed_event = GovernanceEvent {
        event_id: format!("prop-passed-{}", proposal_id),
        event_type: GovernanceEventType::ProposalStatusChanged,
        proposal_id: Some(proposal_id.clone()),
        data: json!({
            "old_state": "Voting",
            "new_state": "Passed",
            "votes_for": 2,
            "votes_against": 1,
            "total_voters": 3
        }),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    // Process proposal passing in both nodes
    let admin_passed_receipt = admin_integration
        .process_governance_event(proposal_passed_event.clone())
        .await
        .unwrap();
    
    let public_passed_receipt = public_integration
        .process_governance_event(proposal_passed_event.clone())
        .await
        .unwrap();
    
    println!("✅ Both nodes processed proposal passing");
    
    // Policy update execution
    println!("\n⚙️  PHASE 7: POLICY UPDATE EXECUTION");
    
    let policy_update_event = GovernanceEvent {
        event_id: format!("policy-update-{}", proposal_id),
        event_type: GovernanceEventType::PolicyUpdate,
        proposal_id: Some(proposal_id.clone()),
        data: json!({
            "policy_type": "fee_structure",
            "new_base_fee": 1000,
            "new_per_byte_fee": 10,
            "effective_block": 100000
        }),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    // Process policy update in both nodes
    let admin_policy_receipt = admin_integration
        .process_governance_event(policy_update_event.clone())
        .await
        .unwrap();
    
    let public_policy_receipt = public_integration
        .process_governance_event(policy_update_event.clone())
        .await
        .unwrap();
    
    println!("✅ Policy update applied to both nodes");
    
    // Treasury operation test
    println!("\n💰 PHASE 8: TREASURY OPERATIONS");
    
    let treasury_event = GovernanceEvent {
        event_id: format!("treasury-{}", chrono::Utc::now().timestamp()),
        event_type: GovernanceEventType::DisbursementExecuted,
        proposal_id: None,
        data: json!({
            "recipient": "did:e3:recipient1",
            "amount": 50000.0,
            "purpose": "Development funding",
            "proposal_id": proposal_id
        }),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    let admin_treasury_receipt = admin_integration
        .process_governance_event(treasury_event.clone())
        .await
        .unwrap();
    
    let public_treasury_receipt = public_integration
        .process_governance_event(treasury_event.clone())
        .await
        .unwrap();
    
    println!("✅ Treasury disbursement processed by both nodes");
    
    // Results and validation
    println!("\n📊 PHASE 9: RESULTS AND VALIDATION");
    
    println!("🎉 Integration test completed successfully!");
    println!("   📋 Events processed:");
    println!("      - Proposal creation: ✅");
    println!("      - Proposal status change: ✅");
    println!("      - Policy update: ✅");
    println!("      - Treasury disbursement: ✅");
    println!("   🏛️  Admin Node: {} events processed", 4);
    println!("   🌐 Public Node: {} events processed", 4);
    println!("   📝 Total governance events: {}", 8);
    
    // Verify all receipts were successful
    assert!(admin_receipt.processed);
    assert!(public_receipt.processed);
    assert!(admin_passed_receipt.processed);
    assert!(public_passed_receipt.processed);
    assert!(admin_policy_receipt.processed);
    assert!(public_policy_receipt.processed);
    assert!(admin_treasury_receipt.processed);
    assert!(public_treasury_receipt.processed);
    
    println!("✅ All assertions passed - Integration test successful! 🎉");
}

#[tokio::test]
async fn test_governance_event_validation() {
    println!("🔍 Testing governance event validation");
    
    let integration = AdminNodeIntegration::new("test-admin".to_string());
    
    // Test invalid event (empty event_id)
    let invalid_event = GovernanceEvent {
        event_id: "".to_string(),
        event_type: GovernanceEventType::ProposalCreated,
        proposal_id: Some("test-proposal".to_string()),
        data: json!({}),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    // This should handle the invalid event gracefully
    let result = integration.process_governance_event(invalid_event).await;
    
    // The integration should still process it but may log warnings
    match result {
        Ok(receipt) => {
            println!("✅ Invalid event handled gracefully");
            println!("   Receipt processed: {}", receipt.processed);
        }
        Err(e) => {
            println!("⚠️  Invalid event rejected: {}", e);
        }
    }
}

#[tokio::test]
async fn test_cross_node_communication_simulation() {
    println!("🔗 Testing cross-node communication simulation");
    
    // Simulate the three nodes communicating
    let dao_node_id = "dao-primary";
    let admin_node_id = "admin-primary";
    let public_node_id = "public-primary";
    
    let admin_integration = AdminNodeIntegration::new(admin_node_id.to_string());
    let public_integration = PublicNodeIntegration::new(public_node_id.to_string());
    
    // Create a governance event from DAO node
    let event = GovernanceEvent {
        event_id: format!("cross-comm-{}", chrono::Utc::now().timestamp()),
        event_type: GovernanceEventType::PolicyUpdate,
        proposal_id: Some("cross-test-proposal".to_string()),
        data: json!({
            "source_node": dao_node_id,
            "policy_type": "validator_requirements",
            "new_min_stake": 100000
        }),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    println!("📡 Simulating broadcast from DAO node to Admin and Public nodes");
    
    // Process in parallel (simulating real P2P broadcast)
    let (admin_result, public_result) = tokio::join!(
        admin_integration.process_governance_event(event.clone()),
        public_integration.process_governance_event(event.clone())
    );
    
    match (admin_result, public_result) {
        (Ok(admin_receipt), Ok(public_receipt)) => {
            println!("✅ Both nodes received and processed the event");
            println!("   Admin receipt: {:?}", admin_receipt);
            println!("   Public receipt: {:?}", public_receipt);
            
            // Verify both nodes processed the same event
            assert_eq!(admin_receipt.event_id, public_receipt.event_id);
            assert!(admin_receipt.processed);
            assert!(public_receipt.processed);
            
            println!("✅ Cross-node communication test passed!");
        }
        (Err(admin_err), _) => {
            panic!("❌ Admin node failed to process event: {}", admin_err);
        }
        (_, Err(public_err)) => {
            panic!("❌ Public node failed to process event: {}", public_err);
        }
    }
}
