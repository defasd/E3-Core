//! DAO Node Implementation
//!
//! The governance node handles decentralized autonomous organization functionality
//! including proposal management, voting, DID authentication, and treasury operations.

use base64::Engine;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use base64;
use hex;
use e3_core_lib::{
    network_config::NetworkConfig,
    p2p::P2PNetwork,
};

// Import governance modules from the workspace root
use crate::{
    proposal::{ProposalManager, Proposal, ProposalState, ProposalCategory},
    did::{DidRegistry, Did},
    vote::{VotingEngine, Vote, VoteChoice, ConsensusResult},
    treasury::{TreasuryManager, DisbursementRequest, DisbursementCategory},
    reporting::{ReportingEngine, ReportType, ReportPeriod},
    smart_contract::{ContractRegistry, ContractGovernanceEvent, SmartContract, ContractStatus},
};

// Governance event for cross-node communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvent {
    pub event_id: String,
    pub event_type: GovernanceEventType,
    pub proposal_id: Option<String>,
    pub did_id: Option<String>,
    pub data: serde_json::Value,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceEventType {
    ProposalCreated,
    ProposalStatusChanged,
    VoteCast,
    DisbursementRequested,
    DisbursementExecuted,
    PolicyUpdate,
    TreasuryUpdate,
    // Smart contract events
    ContractSubmitted,
    ContractApproved,
    ContractDeployed,
    ContractDisabled,
}

// Governance event receipt for acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEventReceipt {
    pub event_id: String,
    pub received_by: String,
    pub processed: bool,
    pub timestamp: u64,
    pub result: Option<String>,
}

// Main DAO Node structure
pub struct DaoNode {
    pub node_id: String,
    pub network_config: NetworkConfig,
    pub p2p_network: Option<Arc<RwLock<P2PNetwork>>>,
    // Core governance components
    pub proposal_manager: Arc<RwLock<ProposalManager>>,
    pub voting_engine: Arc<RwLock<VotingEngine>>,
    pub did_registry: Arc<RwLock<DidRegistry>>,
    pub treasury_manager: Arc<RwLock<TreasuryManager>>,
    pub reporting_engine: Arc<RwLock<ReportingEngine>>,
    pub contract_registry: Arc<RwLock<ContractRegistry>>,
    // Event handling
    pub event_counter: Arc<RwLock<u64>>,
}

impl DaoNode {
    pub fn new(node_id: String, network_config: NetworkConfig) -> Self {
        DaoNode {
            node_id,
            network_config,
            p2p_network: None,
            proposal_manager: Arc::new(RwLock::new(ProposalManager::new())),
            voting_engine: Arc::new(RwLock::new(VotingEngine::new())),
            did_registry: Arc::new(RwLock::new(DidRegistry::new())),
            treasury_manager: Arc::new(RwLock::new(TreasuryManager::new())),
            reporting_engine: Arc::new(RwLock::new(ReportingEngine::new())),
            contract_registry: Arc::new(RwLock::new(ContractRegistry::new())),
            event_counter: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Start the DAO node with P2P networking
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🏛️  Starting DAO Node: {}", self.node_id);
        
        // Initialize P2P network
        // Use port 4003 to match bootstrap peer config
        // Step 1 & 2: Add and subscribe to the 'governance_events' gossipsub topic
        let port = 4003;
        let p2p_network = Arc::new(RwLock::new(
            {
                // Step 2: Subscribe to the governance_events topic using the new helper method
                let net = P2PNetwork::new(port).await?;
                net.subscribe_topic("governance_events");
                net
            }
        ));
        self.p2p_network = Some(p2p_network.clone());
        
        // Setup event listeners
        self.setup_governance_receipt_listener().await?;
        
        // Initialize treasury with default funds for testing
        {
            let mut treasury = self.treasury_manager.write().await;
            treasury.add_funds("treasury_main", 100000.0)?;
            println!("💰 Initialized treasury with 100,000 ST tokens");
        }
        
        println!("✅ DAO Node started successfully");
        Ok(())
    }
    
    /// Register a new DID
    pub async fn register_did(&self, method: String, network: String, public_key: String, wallet_address: String, signature: String) -> Result<String, String> {
        let mut did_registry = self.did_registry.write().await;
        // Parse public_key from hex or base64 string to ed25519_dalek::PublicKey
        let public_key_bytes = match hex::decode(&public_key) {
            Ok(bytes) => bytes,
            Err(_) => return Err("Invalid public key encoding (expected hex)".to_string()),
        };
        let public_key = match ed25519_dalek::PublicKey::from_bytes(&public_key_bytes) {
            Ok(pk) => pk,
            Err(_) => return Err("Invalid public key bytes".to_string()),
        };
        // You may want to validate the signature here in a real implementation
        did_registry.issue_did(method, network, public_key, wallet_address)
    }

    /// Get treasury status (returns stats from TreasuryManager)
    pub async fn get_treasury_status(&self) -> serde_json::Value {
        let treasury_manager = self.treasury_manager.read().await;
        let stats = treasury_manager.get_treasury_stats();
        serde_json::to_value(stats).unwrap_or_else(|_| serde_json::json!({"error": "Failed to serialize treasury stats"}))
    }
    /// Setup governance event receipt listener
    async fn setup_governance_receipt_listener(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Listen for incoming governance events from the P2P network using the listen method
        if let Some(p2p_network) = &self.p2p_network {
            let node_id = self.node_id.clone();
            let handler = move |msg: &str| {
                if let Ok(event) = serde_json::from_str::<GovernanceEvent>(msg) {
                    // Avoid processing events originated from self
                    if let Some(sender) = event.did_id.as_ref() {
                        if sender == &node_id {
                            return;
                        }
                    }
                    println!("📥 [DAO Node] Received governance event: {:?}", event.event_type);
                    // Example: handle event types (expand as needed)
                    match event.event_type {
                        GovernanceEventType::ProposalCreated => {
                            println!("[DAO Node] Sync: ProposalCreated event for proposal {:?}", event.proposal_id);
                        }
                        GovernanceEventType::ProposalStatusChanged => {
                            println!("[DAO Node] Sync: ProposalStatusChanged event for proposal {:?}", event.proposal_id);
                        }
                        GovernanceEventType::VoteCast => {
                            println!("[DAO Node] Sync: VoteCast event for proposal {:?}", event.proposal_id);
                        }
                        GovernanceEventType::DisbursementRequested => {
                            println!("[DAO Node] Sync: DisbursementRequested event for proposal {:?}", event.proposal_id);
                        }
                        GovernanceEventType::DisbursementExecuted => {
                            println!("[DAO Node] Sync: DisbursementExecuted event for proposal {:?}", event.proposal_id);
                        }
                        GovernanceEventType::PolicyUpdate => {
                            println!("[DAO Node] Sync: PolicyUpdate event");
                        }
                        GovernanceEventType::TreasuryUpdate => {
                            println!("[DAO Node] Sync: TreasuryUpdate event");
                        }
                        GovernanceEventType::ContractSubmitted => {
                            println!("[DAO Node] Sync: ContractSubmitted event");
                        }
                        GovernanceEventType::ContractApproved => {
                            println!("[DAO Node] Sync: ContractApproved event");
                        }
                        GovernanceEventType::ContractDeployed => {
                            println!("[DAO Node] Sync: ContractDeployed event");
                        }
                        GovernanceEventType::ContractDisabled => {
                            println!("[DAO Node] Sync: ContractDisabled event");
                        }
                    }
                    // TODO: Implement actual state sync/merge logic as needed
                }
            };
            let _ = p2p_network.read().await.listen("governance_event", handler).await;
        }
        Ok(())
    }
    
    /// Submit a new proposal
    pub async fn submit_proposal(
        &self,
        title: String,
        description: String,
        category: ProposalCategory,
        submitter_did: String,
        voting_duration_hours: u64,
    ) -> Result<String, String> {
        // Verify DID exists and is eligible
        {
            let did_registry = self.did_registry.read().await;
            if did_registry.get_did(&submitter_did).is_none() {
                return Err("Submitter DID not found".to_string());
            }
        }
        
        // Create execution data with voting duration
        let execution_data = serde_json::json!({
            "voting_duration_hours": voting_duration_hours,
            "proposal_type": "governance"
        });
        
        // Submit proposal
        let proposal_id = {
            let mut proposal_manager = self.proposal_manager.write().await;
            proposal_manager.submit_proposal(
                title,
                description,
                category,
                submitter_did.clone(),
                execution_data,
            )?
        };
        
        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::ProposalCreated,
            Some(proposal_id.clone()),
            Some(submitter_did),
            serde_json::json!({
                "proposal_id": proposal_id,
                "action": "created"
            }),
        ).await?;
        
        println!("📝 Proposal submitted: {}", proposal_id);
        Ok(proposal_id)
    }
    
    /// Cast a vote on a proposal
    pub async fn cast_vote(
        &self,
        proposal_id: String,
        did_id: String,
        choice: String,
        signature: Vec<u8>,
    ) -> Result<String, String> {
        // Verify DID can vote
        {
            let did_registry = self.did_registry.read().await;
            did_registry.can_vote(&did_id, &proposal_id)?;
        }
        
        // Convert choice string to VoteChoice
        let vote_choice = VoteChoice::from_string(&choice)?;
        
        // Validate signature before casting vote
        {
            let voting_engine = self.voting_engine.read().await;
            let did_registry = self.did_registry.read().await;
            voting_engine.validate_vote_signature(
                &proposal_id,
                &did_id,
                &vote_choice,
                &signature,
                &did_registry,
            )?;
        }
        
        // Cast vote
        let vote_id = {
            let mut voting_engine = self.voting_engine.write().await;
            voting_engine.cast_vote(
                proposal_id.clone(),
                did_id.clone(),
                vote_choice,
                signature,
                None,
            )?
        };
        
        // Record vote in DID registry
        {
            let mut did_registry = self.did_registry.write().await;
            did_registry.record_vote(&did_id, &proposal_id, &choice)?;
        }
        
        // Update proposal vote counts (placeholder: you may need to pass actual counts)
        // let mut proposal_manager = self.proposal_manager.write().await;
        // proposal_manager.update_vote_counts(&proposal_id, yes, no, abstain)?;
        
        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::VoteCast,
            Some(proposal_id.clone()),
            Some(did_id.clone()),
            serde_json::json!({
                "vote_id": vote_id,
                "proposal_id": proposal_id,
                "choice": choice
            }),
        ).await?;
        
        println!("🗳️  Vote cast: {} for proposal {}", vote_id, proposal_id);
        Ok(vote_id)
    }

    /// Cast a vote with signature validation (new DID-based voting system)
    pub async fn cast_vote_with_signature(
        &self,
        proposal_id: String,
        did: String,
        vote_choice: String,
        timestamp: u64,
        nonce: String,
        signature: String,
    ) -> Result<String, String> {
        // Verify DID exists and can vote
        {
            let did_registry = self.did_registry.read().await;
            did_registry.can_vote(&did, &proposal_id)?;
        }
        
        // Convert choice string to VoteChoice
        let choice = VoteChoice::from_string(&vote_choice)?;
        
        // Validate vote timing (within proposal period)
        {
            let proposal_manager = self.proposal_manager.read().await;
            let proposal = proposal_manager.get_proposal(&proposal_id)
                .ok_or("Proposal not found")?;
            if !proposal.is_voting_period_active() {
                return Err("Voting period is not active for this proposal".to_string());
            }
        }
        
        // Reconstruct vote message for signature verification
        let vote_message = format!("{}:{}:{}:{}:{}", did, proposal_id, vote_choice, timestamp, nonce);
        
        // Get DID public key for signature verification
        let did_public_key = {
            let did_registry = self.did_registry.read().await;
            did_registry.get_did_public_key(&did)?
        };
        
        // Verify signature
        if !self.verify_vote_signature(&vote_message, &signature, &did_public_key)? {
            return Err("Invalid vote signature".to_string());
        }
        
        // Check for duplicate votes from this DID
        {
            let voting_engine = self.voting_engine.read().await;
            if voting_engine.has_voted(&proposal_id, &did)? {
                return Err("DID has already voted on this proposal".to_string());
            }
        }
        
        // Validate nonce (prevent replay attacks)
        {
            let voting_engine = self.voting_engine.read().await;
            if voting_engine.is_nonce_used(&nonce)? {
                return Err("Nonce has already been used".to_string());
            }
        }
        
        // Cast vote
        let vote_id = {
            let mut voting_engine = self.voting_engine.write().await;
            voting_engine.cast_vote_with_did_enforcement(
                proposal_id.clone(),
                did.clone(),
                choice,
                signature.into_bytes(),
                timestamp,
                nonce.clone(),
            )?
        };
        
        // Record vote in DID registry
        {
            let mut did_registry = self.did_registry.write().await;
            did_registry.record_vote(&did, &proposal_id, &vote_choice)?;
        }
        
        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::VoteCast,
            Some(proposal_id.clone()),
            Some(did.clone()),
            serde_json::json!({
                "vote_id": vote_id,
                "proposal_id": proposal_id,
                "choice": vote_choice,
                "did": did,
                "timestamp": timestamp,
                "nonce": nonce
            }),
        ).await?;
        
        println!("🗳️  Vote cast with DID: {} for proposal {} by DID {}", vote_id, proposal_id, did);
        Ok(vote_id)
    }

    /// Verify vote signature using Ed25519
    fn verify_vote_signature(&self, message: &str, signature_b64: &str, public_key_hex: &str) -> Result<bool, String> {
        use ed25519_dalek::{PublicKey, Signature};
        use sha2::{Sha256, Digest};
        
        // Hash the message
        let mut hasher = Sha256::default();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();
        
        // Decode public key
        let pub_key_bytes = hex::decode(public_key_hex)
            .map_err(|_| "Invalid public key hex".to_string())?;
        let pub_key_array: [u8; 32] = pub_key_bytes.as_slice()
            .try_into()
            .map_err(|_| "Invalid public key length".to_string())?;
        let public_key = PublicKey::from_bytes(&pub_key_array)
            .map_err(|_| "Invalid public key format".to_string())?;
        
        // Decode signature using the new base64 API
        let signature_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64)
            .map_err(|_| "Invalid signature base64".to_string())?;
        let signature_array: [u8; 64] = signature_bytes.as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length".to_string())?;
        let signature = Signature::from_bytes(&signature_array)
            .map_err(|_| "Invalid signature format".to_string())?;
        
        // Verify signature
        Ok(public_key.verify_strict(&hash, &signature).is_ok())
    }

    /// Get active proposals (proposals in voting state)
    pub async fn get_active_proposals(&self) -> Vec<Proposal> {
        let proposal_manager = self.proposal_manager.read().await;
        proposal_manager.get_active_proposals()
    }
    
    /// Close voting and finalize proposal
    pub async fn finalize_proposal(&self, proposal_id: String) -> Result<ConsensusResult, String> {
        // Get proposal and check if voting period has ended
        let voting_active = {
            let proposal_manager = self.proposal_manager.read().await;
            let proposal = proposal_manager.get_proposal(&proposal_id)
                .ok_or("Proposal not found")?;
            proposal.is_voting_period_active()
        };
        if voting_active {
            return Err("Voting period has not ended".to_string());
        }
        
        // Update eligible voters count in voting engine
        {
            let did_registry = self.did_registry.read().await;
            let eligible_voters = did_registry.get_total_eligible_voters();
            
            let mut voting_engine = self.voting_engine.write().await;
            voting_engine.set_eligible_voters(&proposal_id, eligible_voters)?;
        }
        
        // Determine consensus
        let consensus_result = {
            let voting_engine = self.voting_engine.read().await;
            voting_engine.determine_consensus(&proposal_id, true)?
        };
        
        // Update proposal state based on consensus
        let new_state = match consensus_result {
            ConsensusResult::Passed => ProposalState::Passed,
            ConsensusResult::Rejected | ConsensusResult::Failed => ProposalState::Rejected,
            ConsensusResult::Pending => return Err("Consensus still pending".to_string()),
        };
        {
            let mut proposal_manager = self.proposal_manager.write().await;
            if let Some(proposal) = proposal_manager.get_proposal_mut(&proposal_id) {
                proposal.state = new_state.clone();
            }
        }
        
        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::ProposalStatusChanged,
            Some(proposal_id.clone()),
            None,
            serde_json::json!({
                "proposal_id": proposal_id,
                "new_state": format!("{:?}", new_state),
                "consensus_result": format!("{:?}", consensus_result)
            }),
        ).await?;
        
        println!("🏁 Proposal {} finalized with result: {:?}", proposal_id, consensus_result);
        Ok(consensus_result)
    }
    
    /// Request treasury disbursement
    pub async fn request_disbursement(
        &self,
        proposal_id: String,
        recipient: String,
        amount: f64,
        category: DisbursementCategory,
        description: String,
    ) -> Result<String, String> {
        let request_id = {
            let mut treasury = self.treasury_manager.write().await;
            treasury.create_disbursement_request(
                proposal_id.clone(),
                recipient.clone(),
                amount,
                category,
                description,
            )?
        };
        
        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::DisbursementRequested,
            Some(proposal_id),
            None,
            serde_json::json!({
                "request_id": request_id,
                "recipient": recipient,
                "amount": amount
            }),
        ).await?;
        
        println!("💸 Disbursement requested: {} for {} ST", request_id, amount);
        Ok(request_id)
    }
    
    /// Generate governance report
    pub async fn generate_report(
        &self,
        report_type: ReportType,
        period: ReportPeriod,
    ) -> Result<serde_json::Value, String> {
        let proposals = {
            let proposal_manager = self.proposal_manager.read().await;
            // You may need to access the internal proposals map directly
            // proposal_manager.proposals.clone()
            std::collections::HashMap::new() // Placeholder
        };
        
        let votes = {
            let voting_engine = self.voting_engine.read().await;
            // In a real implementation, we'd have a method to get all votes
            std::collections::HashMap::new() // Placeholder
        };
        
        let report = {
            let mut reporting_engine = self.reporting_engine.write().await;
            let did_registry = self.did_registry.read().await;
            let treasury_manager = self.treasury_manager.read().await;
            
            match report_type {
                ReportType::GovernanceActivity => {
                    let report = reporting_engine.generate_governance_activity_report(&proposals, &votes, period);
                    serde_json::to_value(report).map_err(|e| e.to_string())?
                }
                ReportType::TreasuryStatus => {
                    let report = reporting_engine.generate_treasury_status_report(&treasury_manager, period);
                    serde_json::to_value(report).map_err(|e| e.to_string())?
                }
                ReportType::ParticipationMetrics => {
                    let report = reporting_engine.generate_participation_metrics_report(&did_registry, &votes, &proposals, period);
                    serde_json::to_value(report).map_err(|e| e.to_string())?
                }
                ReportType::DIDMetrics => {
                    let report = reporting_engine.generate_did_metrics_report(&did_registry, period);
                    serde_json::to_value(report).map_err(|e| e.to_string())?
                }
                _ => {
                    reporting_engine.generate_comprehensive_report(&proposals, &votes, &did_registry, &treasury_manager, period)
                }
            }
        };
        
        Ok(report)
    }
    
    /// Dispatch governance event to other nodes
    async fn dispatch_governance_event(
        &self,
        event_type: GovernanceEventType,
        proposal_id: Option<String>,
        did_id: Option<String>,
        data: serde_json::Value,
    ) -> Result<(), String> {
        let event_id = {
            let mut counter = self.event_counter.write().await;
            *counter += 1;
            format!("GOV_EVENT_{:08}", *counter)
        };

        let event = GovernanceEvent {
            event_id: event_id.clone(),
            event_type,
            proposal_id,
            did_id,
            data,
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature: vec![], // In a real implementation, this would be cryptographically signed
        };


        // --- Step 3: Broadcast governance event to the network ---
        // Use P2PNetwork::broadcast with a Message struct for the 'governance_events' topic
        if let Some(p2p_network) = &self.p2p_network {
            let network = p2p_network.read().await;
            let message = e3_core_lib::p2p::Message::new(
                "governance_events".to_string(),
                serde_json::to_string(&event).map_err(|e| {
                    eprintln!("[DAO Node] Failed to serialize governance event: {}", e);
                    format!("Failed to serialize governance event: {}", e)
                })?,
                self.node_id.clone(),
            );
            if let Err(e) = network.broadcast(message).await {
                eprintln!("[DAO Node] Failed to broadcast governance event: {}", e);
                return Err(format!("Failed to broadcast governance event: {}", e));
            } else {
                println!("📡 Broadcasted governance event '{}' to topic 'governance_events'", event_id);
            }
        } else {
            eprintln!("[DAO Node] P2P network not initialized; cannot broadcast governance event");
            return Err("P2P network not initialized".to_string());
        }

        println!("✅ Dispatched governance event: {}", event_id);
        Ok(())
    }
    
    /// Get node status
    pub async fn get_status(&self) -> serde_json::Value {
        let proposal_count = {
            let proposal_manager = self.proposal_manager.read().await;
            // proposal_manager.proposals.len()
            0 // Placeholder
        };
        
        let did_count = {
            let did_registry = self.did_registry.read().await;
            did_registry.list_active_dids().len()
        };
        
        let treasury_stats = {
            let treasury_manager = self.treasury_manager.read().await;
            treasury_manager.get_treasury_stats()
        };
        
        serde_json::json!({
            "node_id": self.node_id,
            "status": "running",
            "proposal_count": proposal_count,
            "active_dids": did_count,
            "treasury_balance": treasury_stats.total_balance,
            "timestamp": chrono::Utc::now().timestamp()
        })
    }
    
    /// Get real-time voting results for a proposal
    pub async fn get_voting_results(&self, proposal_id: String) -> Result<serde_json::Value, String> {
        let voting_engine = self.voting_engine.read().await;
        voting_engine.get_real_time_results(&proposal_id)
    }
    
    /// Generate cryptographic proof of voting results
    pub async fn generate_voting_proof(&self, proposal_id: String) -> Result<serde_json::Value, String> {
        let voting_engine = self.voting_engine.read().await;
        let proof = voting_engine.generate_proof(&proposal_id)?;
        serde_json::to_value(proof).map_err(|e| e.to_string())
    }
    
    /// Open voting for a proposal
    pub async fn open_voting(&self, proposal_id: String) -> Result<(), String> {
        // Get voting duration from the proposal's execution data
        let voting_duration_hours = {
            let proposal_manager = self.proposal_manager.read().await;
            if let Some(proposal) = proposal_manager.get_proposal(&proposal_id) {
                proposal.execution_data
                    .get("voting_duration_hours")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(24) // Default to 24 hours
            } else {
                return Err("Proposal not found".to_string());
            }
        };
        
        {
            let mut proposal_manager = self.proposal_manager.write().await;
            proposal_manager.open_voting(&proposal_id, voting_duration_hours)?;
        }
        
        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::ProposalStatusChanged,
            Some(proposal_id.clone()),
            None,
            serde_json::json!({
                "proposal_id": proposal_id,
                "action": "voting_opened",
                "new_state": "Voting",
                "voting_duration_hours": voting_duration_hours
            }),
        ).await?;
        
        println!("🗳️  Voting opened for proposal: {} (duration: {} hours)", proposal_id, voting_duration_hours);
        Ok(())
    }

    // =================== SMART CONTRACT MANAGEMENT ===================

    /// Submit a smart contract for governance approval
    pub async fn submit_smart_contract(
        &self,
        request: crate::smart_contract::ContractSubmissionRequest,
    ) -> Result<String, String> {
        // Verify DID exists and is eligible
        {
            let did_registry = self.did_registry.read().await;
            if did_registry.get_did(&request.developer_did).is_none() {
                return Err("Developer DID not found".to_string());
            }
        }

        // TODO: Validate signature in production
        if request.signature.is_empty() {
            return Err("Signature required".to_string());
        }

        // Submit contract to registry
        let contract_id = {
            let mut contract_registry = self.contract_registry.write().await;
            contract_registry.submit_contract(request)?
        };

        // Get developer DID for event
        let developer_did = {
            let contract_registry = self.contract_registry.read().await;
            contract_registry.get_contract(&contract_id)
                .map(|c| c.developer_did.clone())
                .unwrap_or_default()
        };

        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::ContractSubmitted,
            None,
            Some(developer_did),
            serde_json::json!({
                "contract_id": contract_id,
                "action": "contract_submitted"
            }),
        ).await?;

        Ok(contract_id)
    }

    /// Create a governance proposal for contract approval
    pub async fn create_contract_approval_proposal(
        &self,
        contract_id: String,
        submitter_did: String,
    ) -> Result<String, String> {
        // Get contract details
        let contract = {
            let contract_registry = self.contract_registry.read().await;
            contract_registry.get_contract(&contract_id)
                .ok_or_else(|| "Contract not found".to_string())?
                .clone()
        };

        // Create proposal for contract approval
        let proposal_title = format!("Approve Smart Contract: {}", contract.name);
        let proposal_description = format!(
            "Approve deployment of smart contract '{}' (version {}) by DID: {}\n\nDescription: {}\n\nAllowed Methods: {:?}\n\nPermission Level: {:?}",
            contract.name,
            contract.version,
            contract.developer_did,
            contract.description,
            contract.allowed_methods,
            contract.permission_level
        );

        let proposal_id = self.submit_proposal(
            proposal_title,
            proposal_description,
            ProposalCategory::SmartContract,
            submitter_did,
            72, // 3 days voting period for contract approvals
        ).await?;

        // Associate contract with proposal
        {
            let mut contract_registry = self.contract_registry.write().await;
            contract_registry.set_governance_proposal(&contract_id, proposal_id.clone())?;
            contract_registry.update_contract_status(&contract_id, ContractStatus::UnderReview)?;
        }

        Ok(proposal_id)
    }

    /// Approve a smart contract (called when governance proposal passes)
    pub async fn approve_smart_contract(
        &self,
        contract_id: String,
        proposal_id: String,
    ) -> Result<(), String> {
        // Update contract status to approved
        {
            let mut contract_registry = self.contract_registry.write().await;
            contract_registry.update_contract_status(&contract_id, ContractStatus::Approved)?;
        }

        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::ContractApproved,
            Some(proposal_id),
            None,
            serde_json::json!({
                "contract_id": contract_id,
                "action": "contract_approved"
            }),
        ).await?;

        Ok(())
    }

    /// Deploy an approved smart contract
    pub async fn deploy_smart_contract(&self, contract_id: String) -> Result<(), String> {
        let contract = {
            let contract_registry = self.contract_registry.read().await;
            let contract = contract_registry.get_contract(&contract_id)
                .ok_or_else(|| "Contract not found".to_string())?;
            
            if contract.status != ContractStatus::Approved {
                return Err("Contract not approved for deployment".to_string());
            }
            
            contract.clone()
        };

        // Update contract status to deployed
        {
            let mut contract_registry = self.contract_registry.write().await;
            contract_registry.update_contract_status(&contract_id, ContractStatus::Deployed)?;
        }

        // Dispatch deployment event to Public/Admin nodes
        self.dispatch_governance_event(
            GovernanceEventType::ContractDeployed,
            None,
            None,
            serde_json::json!({
                "contract_id": contract_id,
                "bytecode": base64::engine::general_purpose::STANDARD.encode(&contract.bytecode),
                "allowed_methods": contract.allowed_methods,
                "permission_level": contract.permission_level,
                "gas_limit": contract.gas_limit,
                "action": "contract_deployed"
            }),
        ).await?;

        println!("📄 Smart contract deployed: {}", contract_id);
        Ok(())
    }

    /// Get smart contract by ID
    pub async fn get_smart_contract(&self, contract_id: &str) -> Option<SmartContract> {
        let contract_registry = self.contract_registry.read().await;
        contract_registry.get_contract(contract_id).cloned()
    }

    /// Get all smart contracts by status
    pub async fn get_smart_contracts_by_status(&self, status: ContractStatus) -> Vec<SmartContract> {
        let contract_registry = self.contract_registry.read().await;
        contract_registry.get_contracts_by_status(status)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all deployed smart contracts (for public node consumption)
    pub async fn get_deployed_smart_contracts(&self) -> std::collections::HashMap<String, SmartContract> {
        let contract_registry = self.contract_registry.read().await;
        contract_registry.get_deployed_contracts().clone()
    }

    /// Disable a smart contract
    pub async fn disable_smart_contract(&self, contract_id: String, reason: String) -> Result<(), String> {
        {
            let mut contract_registry = self.contract_registry.write().await;
            contract_registry.disable_contract(&contract_id)?;
        }

        // Dispatch governance event
        self.dispatch_governance_event(
            GovernanceEventType::ContractDisabled,
            None,
            None,
            serde_json::json!({
                "contract_id": contract_id,
                "reason": reason,
                "action": "contract_disabled"
            }),
        ).await?;

        Ok(())
    }

    /// Get contracts submitted by a specific DID
    pub async fn get_contracts_by_developer(&self, developer_did: &str) -> Vec<SmartContract> {
        let contract_registry = self.contract_registry.read().await;
        contract_registry.get_contracts_by_developer(developer_did)
            .into_iter()
            .cloned()
            .collect()
    }
}
