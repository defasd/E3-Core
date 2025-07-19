// admin/admin_node.rs
// AdminNode struct: privileged admin logic with PoA consensus

use e3_core_lib::node::Node;
use e3_core_lib::p2p::{P2PNetwork, Message};
use e3_core_lib::{NetworkConfig, PeerDiscoveryService, DiscoveryEvent};
use e3_core_lib::{GoldUnit, AdminEvent, CrossChainMessage, ExecutionReceipt};
// TODO: Fix governance integration
// use governance::integration::AdminNodeIntegration;
// use governance::dao_node::GovernanceEvent;
use crate::consensus_poa::{PoAConsensus, AdminTx, AdminBlock, AdminPublicKey};
use crate::contract_policy::ContractPolicyManager;
use ed25519_dalek::{Keypair, PublicKey};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

// Temporary stub types until governance integration is fixed
#[derive(Debug, Clone)]
pub struct AdminNodeIntegration {
    node_id: String,
}

impl AdminNodeIntegration {
    pub fn new(node_id: String) -> Self {
        Self { node_id }
    }
    
    pub async fn process_governance_event(&self, event: &GovernanceEvent) -> Result<serde_json::Value, String> {
        // Stub implementation
        Ok(serde_json::json!({
            "status": "processed",
            "event_id": event.event_id
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvent {
    pub event_id: String,
    pub data: serde_json::Value,
}

// Receipt structure for tracking public chain execution of admin events
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AdminEventReceipt {
    pub event_type: String,
    pub details: String,
    pub public_block_hash: String,
    pub admin_block_hash: String,
    pub timestamp: u64,
}

pub struct AdminNode {
    pub node: Node,
    pub p2p_network: P2PNetwork,
    pub consensus: PoAConsensus,
    pub signing_key: Keypair,
    pub gold_units: GoldUnit,
    pub execution_receipts: Vec<AdminEventReceipt>, // Track execution receipts from public chain
    pub network_config: NetworkConfig,
    pub discovery_service: Option<PeerDiscoveryService>,
    pub governance_integration: AdminNodeIntegration, // Governance event handler
    pub contract_policy_manager: ContractPolicyManager, // Smart contract policy management
}

impl AdminNode {
    pub async fn new(db_path: String, port: u16, signing_key: Keypair, initial_authorities: HashSet<AdminPublicKey>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut consensus = PoAConsensus::new(initial_authorities);
        consensus.init_genesis();
        
        // Load network configuration from environment or defaults
        let network_config = NetworkConfig::from_env();
        
        // Initialize governance integration with unique node ID
        let node_id = format!("admin-{}", hex::encode(&signing_key.public.to_bytes()[..8]));
        let governance_integration = AdminNodeIntegration::new(node_id);
        
        // Step 2: Subscribe to the governance_events topic using the new helper method
        let p2p_network = {
            let net = P2PNetwork::new(port).await?;
            net.subscribe_topic("governance_events");
            net
        };
        Ok(AdminNode {
            node: Node::new(db_path, port),
            p2p_network,
            consensus,
            signing_key,
            gold_units: GoldUnit::new(),
            execution_receipts: Vec::new(),
            network_config,
            discovery_service: None, // Will be initialized in start()
            governance_integration,
            contract_policy_manager: ContractPolicyManager::new(),
        })
    }

    pub async fn new_with_config(db_path: String, port: u16, signing_key: Keypair, initial_authorities: HashSet<AdminPublicKey>, network_config: NetworkConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut consensus = PoAConsensus::new(initial_authorities);
        consensus.init_genesis();
        
        Ok(AdminNode {
            node: Node::new(db_path, port),
            p2p_network: P2PNetwork::new(port).await?,
            consensus,
            signing_key,
            gold_units: GoldUnit::new(),
            execution_receipts: Vec::new(),
            network_config,
            discovery_service: None, // Will be initialized in start()
            governance_integration: AdminNodeIntegration::new("".to_string()), // Placeholder, will be set in start()
            contract_policy_manager: ContractPolicyManager::new(),
        })
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting AdminNode P2P networking...");
        self.p2p_network.start().await?;
        
        // Initialize peer discovery service
        println!("🔍 Initializing peer discovery: {}", self.network_config.discovery_methods());
        
        let (mut discovery_service, mut discovery_events) = e3_core_lib::peer_discovery::create_discovery_service_with_config(
            &self.signing_key, // Use ed25519_dalek signing key instead of libp2p keypair
            self.network_config.clone()
        ).await?;
        
        // Start the discovery process
        discovery_service.start_discovery().await?;
        self.discovery_service = Some(discovery_service);
        
        // Handle discovery events
        let p2p_network = self.p2p_network.clone();
        tokio::spawn(async move {
            while let Some(event) = discovery_events.recv().await {
                match event {
                    DiscoveryEvent::PeerDiscovered { peer_id, addresses } => {
                        println!("✅ Discovered peer: {} with {} addresses", peer_id, addresses.len());
                        for addr in addresses {
                            if let Err(e) = p2p_network.connect_to_peer(&addr).await {
                                println!("❌ Failed to connect to discovered peer {}: {:?}", addr, e);
                            } else {
                                println!("🔗 Connected to discovered peer: {}", addr);
                            }
                        }
                    }
                    DiscoveryEvent::PeerExpired { peer_id } => {
                        println!("⏰ Peer expired: {}", peer_id);
                    }
                }
            }
        });
        
        // Start periodic chain synchronization
        let p2p_network = self.p2p_network.clone();
        let node = self.node.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let chain_summary = node.get_chain_summary();
                let message = Message::new(
                    "chain_summary".to_string(),
                    chain_summary,
                    "admin".to_string(),
                );
                if let Err(e) = p2p_network.broadcast(message).await {
                    println!("Failed to broadcast chain summary: {:?}", e);
                }
                println!("AdminNode: Broadcasted periodic chain summary");
            }
        });

        // Legacy peer connection as fallback (if bootstrap peers are empty and discovery fails)
        if self.network_config.bootstrap_peers.is_empty() && !self.network_config.enable_mdns {
            println!("⚠️  No discovery methods enabled, using legacy peer connection");
            let p2p_clone = self.p2p_network.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                
                // Fallback to hardcoded peers only if no discovery is enabled
                let fallback_peers = vec![
                    "/ip4/127.0.0.1/tcp/4002", // Public node
                    "/ip4/127.0.0.1/tcp/4003", // Another potential node
                ];
                
                for peer_addr in fallback_peers {
                    if let Err(e) = p2p_clone.connect_to_peer(peer_addr).await {
                        println!("AdminNode: Could not connect to {}: {:?}", peer_addr, e);
                    } else {
                        println!("AdminNode: Attempting connection to {}", peer_addr);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            });
        }

        // Add periodic peer status reporting with discovery info
        let p2p_status = self.p2p_network.clone();
        let network_config = self.network_config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                let peer_count = p2p_status.get_peer_count().await;
                println!("📊 AdminNode P2P Status: {} peers | Discovery: {}", 
                    peer_count, 
                    network_config.discovery_methods()
                );
            }
        });

        // --- Governance Event Listener ---
        // Listen for messages on the 'governance_events' gossipsub topic and process them
        let governance_p2p = self.p2p_network.clone();
        let governance_integration = self.governance_integration.clone();
        tokio::spawn(async move {
            governance_p2p.listen("governance_events", move |content: &str| {
                let governance_integration = governance_integration.clone();
                let content = content.to_string();
                tokio::spawn(async move {
                    // Attempt to deserialize the incoming message as a GovernanceEvent
                    match serde_json::from_str::<GovernanceEvent>(&content) {
                        Ok(event) => {
                            // Use the integration handler for governance events
                            match governance_integration.process_governance_event(&event).await {
                                Ok(receipt) => {
                                    println!("[AdminNode] Processed governance event {}: receipt = {:?}", event.event_id, receipt);
                                }
                                Err(e) => {
                                    eprintln!("[AdminNode] Failed to process governance event {}: {}", event.event_id, e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[AdminNode] Failed to deserialize governance event: {}", e);
                        }
                    }
                });
            }).await.unwrap();
        });

        // Start message handling for admin sync requests
        let p2p_clone = self.p2p_network.clone();
        let consensus_clone = self.consensus.clone();
        tokio::spawn(async move {
            let p2p_for_closure = p2p_clone.clone();
            p2p_clone.listen("request_admin_events", move |content: &str| {
                println!("📦 Received sync request from public node: {}", content);
                let p2p = p2p_for_closure.clone();
                let consensus = consensus_clone.clone();
                tokio::spawn(async move {
                    // Prepare all admin events from the chain for sync
                    let events: Vec<serde_json::Value> = consensus.get_event_log()
                        .iter()
                        .enumerate()
                        .filter_map(|(i, tx)| {
                            let block_hash = if i < consensus.chain.len() {
                                consensus.chain[i].hash.clone()
                            } else {
                                "unknown".to_string()
                            };
                            let timestamp = if i < consensus.chain.len() {
                                consensus.chain[i].timestamp
                            } else {
                                chrono::Utc::now().timestamp() as u64
                            };
                            match tx {
                                AdminTx::Mint { to, amount } => {
                                    Some(serde_json::json!({
                                        "event_type": "mint",
                                        "data": {
                                            "to": to,
                                            "amount": amount
                                        },
                                        "admin_block_hash": block_hash,
                                        "timestamp": timestamp
                                    }))
                                },
                                AdminTx::Burn { from, amount } => {
                                    Some(serde_json::json!({
                                        "event_type": "burn",
                                        "data": {
                                            "from": from,
                                            "amount": amount
                                        },
                                        "admin_block_hash": block_hash,
                                        "timestamp": timestamp
                                    }))
                                },
                                AdminTx::Transfer { from, to, amount } => {
                                    Some(serde_json::json!({
                                        "event_type": "transfer",
                                        "data": {
                                            "from": from,
                                            "to": to,
                                            "amount": amount
                                        },
                                        "admin_block_hash": block_hash,
                                        "timestamp": timestamp
                                    }))
                                },
                                AdminTx::ProofOfReserve { details } => {
                                    Some(serde_json::json!({
                                        "event_type": "proof_of_reserve",
                                        "data": {
                                            "details": details
                                        },
                                        "admin_block_hash": block_hash,
                                        "timestamp": timestamp
                                    }))
                                },
                                AdminTx::ProposeAddAdmin { .. } |
                                AdminTx::ProposeRemoveAdmin { .. } |
                                AdminTx::VoteAuthorityChange { .. } => {
                                    // Skip authority proposals for now
                                    None
                                },
                            }
                        })
                        .collect();
                    let sync_message = Message::new(
                        "sync_admin_events".to_string(),
                        serde_json::to_string(&events).unwrap(),
                        "admin".to_string(),
                    );
                    if let Err(e) = p2p.broadcast(sync_message).await {
                        println!("Failed to send admin events during sync: {:?}", e);
                    } else {
                        println!("✅ Sent {} admin events for sync", events.len());
                    }
                });
            }).await.unwrap();
        });

        println!("✅ AdminNode started successfully with peer discovery");
        Ok(())
    }

    // Privileged admin actions using PoA consensus
    // DEPRECATED: Use mint_gt_with_proof instead
    pub async fn mint_gt(&mut self, _amount: u64, _to: String) -> Result<AdminBlock, String> {
        return Err("Minting requires proof of reserve. Use mint_gt_with_proof() instead.".to_string());
    }

    // NEW: Minting now ALWAYS requires proof of reserve
    pub async fn mint_gt_with_proof(&mut self, amount: u64, to: String, proof_of_reserve: String) -> Result<AdminBlock, String> {
        // Validate proof of reserve is not empty
        if proof_of_reserve.trim().is_empty() {
            return Err("Proof of reserve cannot be empty when minting".to_string());
        }

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        // Mint the Gold Units
        self.gold_units.mint(&to, amount, timestamp)
            .map_err(|e| format!("Failed to mint GU: {}", e))?;

        // Create both mint and proof of reserve transactions in the same block
        let mint_tx = AdminTx::Mint { to: to.clone(), amount };
        let proof_tx = AdminTx::ProofOfReserve { details: proof_of_reserve.clone() };
        let block = self.consensus.propose_block(&self.signing_key, vec![mint_tx, proof_tx])?;
        
        // Create and broadcast admin event for cross-chain sync
        let admin_event = AdminEvent::GUMinted {
            to: to.clone(),
            amount,
            proof_hash: proof_of_reserve.clone(),
            timestamp,
            admin_signature: format!("admin_sig_{}", block.hash), // Simplified signature for now
        };

        let cross_chain_message = CrossChainMessage::new(
            e3_core_lib::events::ChainType::Admin,
            e3_core_lib::events::ChainType::Public,
            e3_core_lib::events::MessagePayload::AdminEvent(admin_event),
            format!("admin_sig_{}", block.hash),
        );

        // Broadcast the cross-chain message
        let message = Message::new(
            "admin_actions".to_string(),
            serde_json::to_string(&cross_chain_message).map_err(|e| format!("Serialization error: {}", e))?,
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast mint action: {:?}", e);
        }

        // Also broadcast the complete admin block
        let admin_block_data = serde_json::json!({
            "index": block.index,
            "hash": block.hash,
            "prev_hash": block.prev_hash,
            "timestamp": block.timestamp,
            "txs": block.txs
        });
        let block_message = Message::new(
            "admin_block".to_string(),
            admin_block_data.to_string(),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(block_message).await {
            println!("Failed to broadcast admin block: {:?}", e);
        }
        
        println!("✅ Successfully minted {} GU to {} with proof: {}", amount, to, proof_of_reserve);
        println!("   New GU balance for {}: {}", to, self.gold_units.get_balance(&to));
        println!("   Total GU supply: {}", self.gold_units.get_total_supply());

        // Add receipt for mint
        self.execution_receipts.push(AdminEventReceipt {
            event_type: "mint".to_string(),
            details: format!("Minted {} GU to {} with proof: {}", amount, to, proof_of_reserve),
            public_block_hash: String::new(), // Fill with actual public block hash if available
            admin_block_hash: block.hash.clone(),
            timestamp: block.timestamp,
        });

        Ok(block)
    }

    pub async fn burn_gt(&mut self, amount: u64, from: String) -> Result<AdminBlock, String> {
        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        // Burn the Gold Units
        self.gold_units.burn(&from, amount, timestamp)
            .map_err(|e| format!("Failed to burn GU: {}", e))?;

        let tx = AdminTx::Burn { from: from.clone(), amount };
        let block = self.consensus.propose_block(&self.signing_key, vec![tx])?;
        
        // Create and broadcast admin event for cross-chain sync
        let admin_event = AdminEvent::GUBurned {
            from: from.clone(),
            amount,
            timestamp,
            admin_signature: format!("admin_sig_{}", block.hash),
        };

        let cross_chain_message = CrossChainMessage::new(
            e3_core_lib::events::ChainType::Admin,
            e3_core_lib::events::ChainType::Public,
            e3_core_lib::events::MessagePayload::AdminEvent(admin_event),
            format!("admin_sig_{}", block.hash),
        );

        // Broadcast the cross-chain message
        let message = Message::new(
            "admin_actions".to_string(),
            serde_json::to_string(&cross_chain_message).map_err(|e| format!("Serialization error: {}", e))?,
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast burn action: {:?}", e);
        }

        // Also broadcast the complete admin block
        let admin_block_data = serde_json::json!({
            "index": block.index,
            "hash": block.hash,
            "prev_hash": block.prev_hash,
            "timestamp": block.timestamp,
            "txs": block.txs
        });
        let block_message = Message::new(
            "admin_block".to_string(),
            admin_block_data.to_string(),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(block_message).await {
            println!("Failed to broadcast admin block: {:?}", e);
        }
        
        println!("✅ Successfully burned {} GU from {}", amount, from);
        println!("   New GU balance for {}: {}", from, self.gold_units.get_balance(&from));
        println!("   Total GU supply: {}", self.gold_units.get_total_supply());

        // Add receipt for burn
        self.execution_receipts.push(AdminEventReceipt {
            event_type: "burn".to_string(),
            details: format!("Burned {} GU from {}", amount, from),
            public_block_hash: String::new(), // Fill with actual public block hash if available
            admin_block_hash: block.hash.clone(),
            timestamp: block.timestamp,
        });
        Ok(block)
    }

    pub async fn record_proof_of_reserve(&mut self, details: String) -> Result<AdminBlock, String> {
        let tx = AdminTx::ProofOfReserve { details: details.clone() };
        let block = self.consensus.propose_block(&self.signing_key, vec![tx])?;
        
        // Broadcast the admin action
        let action = serde_json::json!({
            "event_type": "proof_of_reserve",
            "data": {
                "details": details
            },
            "admin_block_hash": block.hash
        });
        let message = Message::new(
            "admin_actions".to_string(),
            action.to_string(),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast proof of reserve: {:?}", e);
        }

        // Also broadcast the complete admin block
        let admin_block_data = serde_json::json!({
            "index": block.index,
            "hash": block.hash,
            "prev_hash": block.prev_hash,
            "timestamp": block.timestamp,
            "txs": block.txs
        });
        let block_message = Message::new(
            "admin_block".to_string(),
            admin_block_data.to_string(),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(block_message).await {
            println!("Failed to broadcast admin block: {:?}", e);
        }
        
        println!("Recorded proof of reserve: {}", details);
        // Add receipt for proof of reserve
        self.execution_receipts.push(AdminEventReceipt {
            event_type: "proof_of_reserve".to_string(),
            details: format!("Proof of reserve recorded: {}", details),
            public_block_hash: String::new(), // Fill with actual public block hash if available
            admin_block_hash: block.hash.clone(),
            timestamp: block.timestamp,
        });
        Ok(block)
    }

    // Authority management methods
    pub async fn propose_add_admin(&mut self, new_admin: PublicKey) -> Result<AdminBlock, String> {
        let tx = AdminTx::ProposeAddAdmin { new_admin: AdminPublicKey::from(new_admin) };
        let block = self.consensus.propose_block(&self.signing_key, vec![tx])?;
        
        // Broadcast the proposal
        let message = Message::new(
            "admin_proposal".to_string(),
            format!("Proposed adding new admin: {:?}", new_admin),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin proposal: {:?}", e);
        }
        
        println!("Proposed adding new admin: {:?}", new_admin);
        Ok(block)
    }

    pub async fn propose_remove_admin(&mut self, admin: PublicKey) -> Result<AdminBlock, String> {
        let tx = AdminTx::ProposeRemoveAdmin { admin: AdminPublicKey::from(admin) };
        let block = self.consensus.propose_block(&self.signing_key, vec![tx])?;
        
        // Broadcast the proposal
        let message = Message::new(
            "admin_proposal".to_string(),
            format!("Proposed removing admin: {:?}", admin),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin proposal: {:?}", e);
        }
        
        println!("Proposed removing admin: {:?}", admin);
        Ok(block)
    }

    // Overloaded methods for AdminPublicKey
    pub async fn propose_add_admin_key(&mut self, new_admin: AdminPublicKey) -> Result<AdminBlock, String> {
        let tx = AdminTx::ProposeAddAdmin { new_admin: new_admin.clone() };
        let block = self.consensus.propose_block(&self.signing_key, vec![tx])?;
        
        // Broadcast the proposal
        let message = Message::new(
            "admin_proposal".to_string(),
            format!("Proposed adding new admin: {:?}", new_admin),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin proposal: {:?}", e);
        }
        
        println!("Proposed adding new admin: {:?}", new_admin);
        Ok(block)
    }

    pub async fn propose_remove_admin_key(&mut self, admin: AdminPublicKey) -> Result<AdminBlock, String> {
        let tx = AdminTx::ProposeRemoveAdmin { admin: admin.clone() };
        let block = self.consensus.propose_block(&self.signing_key, vec![tx])?;
        
        // Broadcast the proposal
        let message = Message::new(
            "admin_proposal".to_string(),
            format!("Proposed removing admin: {:?}", admin),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin proposal: {:?}", e);
        }
        
        println!("Proposed removing admin: {:?}", admin);
        Ok(block)
    }

    pub async fn vote_authority_change(&mut self, proposal_id: u64, approve: bool) -> Result<bool, String> {
        let voter_admin_key = AdminPublicKey::from(self.signing_key.public);
        let executed = self.consensus.vote_on_proposal(&voter_admin_key, proposal_id, approve)?;
        
        if executed {
            // Broadcast authority change
            let message = Message::new(
                "authority_change".to_string(),
                format!("Authority set changed - proposal {} executed", proposal_id),
                "admin".to_string(),
            );
            if let Err(e) = self.p2p_network.broadcast(message).await {
                println!("Failed to broadcast authority change: {:?}", e);
            }
            println!("Proposal {} executed - authority set updated", proposal_id);
        } else {
            println!("Voted on proposal {} - still pending", proposal_id);
        }
        
        Ok(executed)
    }

    // Query methods
    pub fn get_authorities(&self) -> &HashSet<AdminPublicKey> {
        self.consensus.get_authorities()
    }

    pub fn get_pending_proposals(&self) -> Vec<&crate::consensus_poa::AuthorityProposal> {
        self.consensus.get_pending_proposals().values().collect()
    }

    pub fn get_admin_chain_summary(&self) -> (u64, String, usize) {
        if let Some(latest) = self.consensus.get_latest_block() {
            (latest.index, latest.hash.clone(), self.consensus.chain.len())
        } else {
            (0, "genesis".to_string(), 0)
        }
    }

    pub fn get_event_log(&self) -> &[AdminTx] {
        self.consensus.get_event_log()
    }

    pub async fn broadcast_admin_action(&self, action: String) {
        let message = Message::new(
            "admin_actions".to_string(),
            action.clone(),
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin action: {:?}", e);
        } else {
            println!("Broadcasted admin action: {}", action);
        }
    }

    pub async fn synchronize_chain(&self) {
        let chain_summary = self.node.get_chain_summary();
        let message = Message::new(
            "chain_summary".to_string(),
            chain_summary,
            "admin".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast chain summary: {:?}", e);
        } else {
            println!("Broadcasted chain summary.");
        }
    }

    /// Handle governance events related to smart contract policies
    pub async fn handle_contract_policy_event(&mut self, event: &GovernanceEvent) -> Result<(), String> {
        if let Some(action) = event.data.get("action").and_then(|a| a.as_str()) {
            match action {
                "update_contract_policy" => {
                    if let Some(contract_id) = event.data.get("contract_id").and_then(|c| c.as_str()) {
                        if let Some(policy_updates) = event.data.get("policy_updates") {
                            self.contract_policy_manager.update_contract_policy(
                                contract_id.to_string(),
                                policy_updates.clone(),
                            )?;
                        }
                    }
                }
                "update_global_policy" => {
                    if let Some(policy_updates) = event.data.get("policy_updates") {
                        self.contract_policy_manager.update_global_policy(policy_updates.clone())?;
                    }
                }
                "emergency_shutdown" => {
                    let reason = event.data.get("reason")
                        .and_then(|r| r.as_str())
                        .unwrap_or("Emergency governance directive")
                        .to_string();
                    self.contract_policy_manager.emergency_shutdown(reason);
                }
                "emergency_restore" => {
                    self.contract_policy_manager.emergency_restore();
                }
                _ => {
                    println!("📋 Unknown contract policy action: {}", action);
                }
            }
        }
        Ok(())
    }

    /// Get contract policy report
    pub fn get_contract_policy_report(&self) -> serde_json::Value {
        self.contract_policy_manager.generate_policy_report()
    }

    /// Check if contract execution is allowed
    pub fn is_contract_execution_allowed(&self, contract_id: &str) -> bool {
        self.contract_policy_manager.is_execution_allowed(contract_id)
    }

    // Receipt handling for public chain execution confirmations
    pub async fn handle_admin_event_receipt(&mut self, receipt: AdminEventReceipt) {
        self.execution_receipts.push(receipt);
    }

    // Get all execution receipts for audit purposes
    pub fn get_execution_receipts(&self) -> &[AdminEventReceipt] {
        &self.execution_receipts
    }

    // Get receipts for a specific admin block hash
    pub fn get_receipts_for_admin_block(&self, admin_block_hash: &str) -> Vec<&AdminEventReceipt> {
        self.execution_receipts.iter()
            .filter(|r| r.admin_block_hash == admin_block_hash)
            .collect()
    }

    // === Gold Unit Methods ===

    /// Transfer Gold Units between admin accounts
    pub async fn transfer_gold_unit(&mut self, from: String, to: String, amount: u64) -> Result<AdminBlock, String> {
        // Transfer the Gold Units
        self.gold_units.transfer(&from, &to, amount)
            .map_err(|e| format!("Failed to transfer GU: {}", e))?;

        // Create admin transaction for the transfer
        let tx = AdminTx::Transfer { from: from.clone(), to: to.clone(), amount };
        let block = self.consensus.propose_block(&self.signing_key, vec![tx])?;
        
        println!("✅ Successfully transferred {} GU from {} to {}", amount, from, to);
        println!("   {} balance: {}", from, self.gold_units.get_balance(&from));
        println!("   {} balance: {}", to, self.gold_units.get_balance(&to));

        Ok(block)
    }

    /// Get Gold Unit balance for a specific address
    pub fn get_gold_unit_balance(&self, address: &str) -> u64 {
        self.gold_units.get_balance(address)
    }

    /// Get total Gold Unit supply
    pub fn get_gold_unit_supply(&self) -> u64 {
        self.gold_units.get_total_supply()
    }

    /// Get Gold Unit metadata
    pub fn get_gold_unit_metadata(&self) -> &e3_core_lib::tokens::GoldUnitMetadata {
        &self.gold_units.metadata
    }

    /// Get all Gold Unit balances (for admin dashboard)
    pub fn get_all_gold_unit_balances(&self) -> &std::collections::HashMap<String, u64> {
        &self.gold_units.balances
    }

    /// Process execution receipt from public chain
    pub fn process_execution_receipt(&mut self, receipt: ExecutionReceipt) {
        println!("📩 Received execution receipt: {:?}", receipt);
        
        // Convert ExecutionReceipt to AdminEventReceipt for storage
        let admin_receipt = AdminEventReceipt {
            event_type: receipt.event_type,
            details: format!("Public chain executed: success={}, SU minted={:?}", 
                           receipt.success, receipt.su_minted),
            public_block_hash: "public_block_hash_placeholder".to_string(),
            admin_block_hash: receipt.event_id,
            timestamp: receipt.timestamp,
        };
        
        self.execution_receipts.push(admin_receipt);
        println!("✅ Stored execution receipt");
    }

    /// Handle governance events from DAO node
    pub async fn handle_governance_event(&self, event: GovernanceEvent) -> Result<(), String> {
        println!("🏛️  AdminNode received governance event: {}", event.event_id);
        
        // Process the event through governance integration
        let receipt = self.governance_integration
            .process_governance_event(&event)
            .await
            .map_err(|e| format!("Failed to process governance event: {}", e))?;
        
        println!("✅ AdminNode processed governance event - Receipt: {:?}", receipt);


        // ------       Development ONLY       ------ //
        // - In a real implementation, you might want to:
        // - Store the receipt in admin storage
        // - Trigger specific admin actions based on the event
        // - Update admin node state or policies



        Ok(())
    }
    
    /// Get status of governance integration
    pub fn get_governance_integration_status(&self) -> String {
        format!("Governance integration active for node: {}", self.governance_integration.node_id)
    }

    /// Get node ID for governance integration
    pub fn get_governance_node_id(&self) -> &str {
        &self.governance_integration.node_id
    }
}
