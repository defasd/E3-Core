use base64::Engine;
// public/public_node.rs
// PublicNode struct: public chain logic with PoS consensus

use e3_core_lib::node::Node;
use e3_core_lib::p2p::{P2PNetwork, Message};
use e3_core_lib::{NetworkConfig, PeerDiscoveryService, DiscoveryEvent};
// TODO: Fix governance integration
// use governance::integration::PublicNodeIntegration;
// use governance::dao_node::GovernanceEvent;
use crate::consensus_pos::{PoSConsensus, PublicTx, PublicBlock, ValidatorPublicKey, TokenType};
use crate::smart_contract_executor::{ContractExecutor, ExecutableContract, ContractExecutionRequest};
use ed25519_dalek::Keypair;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use std::fs;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use base64;

// Temporary stub types until governance integration is fixed
#[derive(Debug, Clone)]
pub struct PublicNodeIntegration {
    node_id: String,
}

impl PublicNodeIntegration {
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

// Receipt structure for admin event execution confirmation
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AdminEventReceipt {
    pub event_type: String,
    pub details: String,
    pub public_block_hash: String,
    pub admin_block_hash: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AdminEvent {
    pub event_type: String,
    pub data: serde_json::Value,
    pub admin_block_hash: String,
    pub timestamp: u64,
}

pub struct PublicNode {
    pub node: Node,
    pub p2p_network: P2PNetwork,
    pub consensus: PoSConsensus,
    pub signing_key: Keypair,
    pub transaction_pool: Vec<PublicTx>,
    pub network_config: NetworkConfig,
    pub discovery_service: Option<PeerDiscoveryService>,
    pub governance_integration: PublicNodeIntegration, // Governance event handler
    pub admin_events: Vec<AdminEvent>,
    pub contract_executor: ContractExecutor, // Smart contract execution engine
}

impl PublicNode {

    /// Handle a governance event from the Governance/DAO Node (DEPRECATED)
    /// Use governance_integration.process_governance_event() instead
    pub async fn process_governance_event(&mut self, event: GovernanceEvent) -> Result<(), String> {
        println!("⚠️  Using deprecated process_governance_event. Use governance_integration instead.");
        
        // Delegate to the new governance integration handler
        let receipt = self.governance_integration
            .process_governance_event(&event)
            .await
            .map_err(|e| format!("Failed to process governance event: {}", e))?;
        
        println!("✅ Governance event processed via integration - Receipt: {:?}", receipt);
        Ok(())
    }
    
    fn load_admin_events(path: &str) -> Vec<AdminEvent> {
        fs::read_to_string(path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_default()
    }

    fn save_admin_events(path: &str, events: &Vec<AdminEvent>) {
        // Ensure the parent directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(events) {
            let _ = std::fs::write(path, json);
        }
    }

    pub async fn new(db_path: String, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        // For demo purposes, generate a simple keypair from deterministic seed
        let seed = [port as u8; 32]; // Simple seed based on port
        use ed25519_dalek::{SecretKey, PublicKey};
        let secret = SecretKey::from_bytes(&seed)?;
        let public = PublicKey::from(&secret);
        let signing_key = Keypair { secret, public };
        
        // Initialize governance integration with unique node ID
        let node_id = format!("public-{}", hex::encode(&signing_key.public.to_bytes()[..8]));
        let governance_integration = PublicNodeIntegration::new(node_id);
        let mut consensus = PoSConsensus::new(1000); // Minimum stake of 1000 tokens
        consensus.init_genesis();
        
        // Initialize with some test balances for demo
        let mut genesis_balances = HashMap::new();
        genesis_balances.insert(TokenType::SU, 1_000_000);
        consensus.balances.insert("genesis".to_string(), genesis_balances);
        
        let mut treasury_balances = HashMap::new();
        treasury_balances.insert(TokenType::SU, 500_000);
        consensus.balances.insert("treasury".to_string(), treasury_balances);
        
        let mut treasury_alt_balances = HashMap::new();
        treasury_alt_balances.insert(TokenType::SU, 0);
        consensus.balances.insert("Treasury".to_string(), treasury_alt_balances); // Support both cases for demo
        
        // Load network configuration from environment or defaults
        let network_config = NetworkConfig::from_env();
        
        let admin_events = Self::load_admin_events("public_db/admin_events.json");
        // Step 2: Subscribe to the governance_events topic using the new helper method
        let p2p_network = {
            let net = P2PNetwork::new(port).await?;
            net.subscribe_topic("governance_events");
            net
        };
        Ok(PublicNode {
            node: Node::new(db_path, port),
            p2p_network,
            consensus,
            signing_key,
            transaction_pool: Vec::new(),
            network_config,
            discovery_service: None, // Will be initialized in start()
            governance_integration, // Use the initialized governance integration
            admin_events,
            contract_executor: ContractExecutor::new(),
        })
    }

    pub async fn new_with_config(db_path: String, port: u16, network_config: NetworkConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // For demo purposes, generate a simple keypair from deterministic seed
        let seed = [port as u8; 32]; // Simple seed based on port
        use ed25519_dalek::{SecretKey, PublicKey};
        let secret = SecretKey::from_bytes(&seed)?;
        let public = PublicKey::from(&secret);
        let signing_key = Keypair { secret, public };
        let mut consensus = PoSConsensus::new(1000); // Minimum stake of 1000 tokens
        consensus.init_genesis();
        
        // Initialize with some test balances for demo
        let mut genesis_balances = HashMap::new();
        genesis_balances.insert(TokenType::SU, 1_000_000);
        consensus.balances.insert("genesis".to_string(), genesis_balances);
        
        let mut treasury_balances = HashMap::new();
        treasury_balances.insert(TokenType::SU, 500_000);
        consensus.balances.insert("treasury".to_string(), treasury_balances);
        
        let mut treasury_alt_balances = HashMap::new();
        treasury_alt_balances.insert(TokenType::SU, 0);
        consensus.balances.insert("Treasury".to_string(), treasury_alt_balances); // Support both cases for demo
        
        // Initialize governance integration with unique node ID for config version
        let config_node_id = format!("public-config-{}", hex::encode(&signing_key.public.to_bytes()[..8]));
        let config_governance_integration = PublicNodeIntegration::new(config_node_id);
        
        Ok(PublicNode {
            node: Node::new(db_path, port),
            p2p_network: P2PNetwork::new(port).await?,
            consensus,
            signing_key,
            transaction_pool: Vec::new(),
            network_config,
            discovery_service: None, // Will be initialized in start()
            governance_integration: config_governance_integration,
            admin_events: Vec::new(),
            contract_executor: ContractExecutor::new(),
        })
    }

    pub async fn start(self) -> Result<Arc<tokio::sync::Mutex<Self>>, Box<dyn std::error::Error>> {
        // Move self into Arc<Mutex<>> at the beginning
        use tokio::sync::Mutex;
        let public_node_ptr = Arc::new(Mutex::new(self));
        
        // Get references to needed fields for spawned tasks
        let (p2p_network, node, network_config, signing_key);
        {
            let node_ref = public_node_ptr.lock().await;
            p2p_network = node_ref.p2p_network.clone();
            node = node_ref.node.clone();
            network_config = node_ref.network_config.clone();
            // Get a copy of the signing key
            signing_key = Keypair::from_bytes(&node_ref.signing_key.to_bytes())?;
        }
        
        println!("Starting PublicNode P2P networking...");
        p2p_network.start().await?;
        
        // Initialize peer discovery service
        println!("🔍 Initializing peer discovery: {}", network_config.discovery_methods());
        
        let (mut discovery_service, mut discovery_events) = e3_core_lib::peer_discovery::create_discovery_service_with_config(
            &signing_key, // Use ed25519_dalek signing key
            network_config.clone()
        ).await?;
        
        // Start the discovery process
        discovery_service.start_discovery().await?;
        {
            let mut node_ref = public_node_ptr.lock().await;
            node_ref.discovery_service = Some(discovery_service);
        }
        
        // Handle discovery events
        let p2p_network_clone = p2p_network.clone();
        tokio::spawn(async move {
            while let Some(event) = discovery_events.recv().await {
                match event {
                    DiscoveryEvent::PeerDiscovered { peer_id, addresses } => {
                        println!("✅ Discovered peer: {} with {} addresses", peer_id, addresses.len());
                        for addr in addresses {
                            if let Err(e) = p2p_network_clone.connect_to_peer(&addr).await {
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
        
        // Start periodic block production if this node is a validator
        let p2p_network_clone = p2p_network.clone();
        let node_clone = node.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                // Block production logic would go here
                let chain_summary = node_clone.get_chain_summary();
                let message = Message::new(
                    "chain_summary".to_string(),
                    chain_summary,
                    "public".to_string(),
                );
                if let Err(e) = p2p_network_clone.broadcast(message).await {
                    println!("Failed to broadcast chain summary: {:?}", e);
                }
                println!("PublicNode: Broadcasted periodic chain summary");
            }
        });

        // Legacy peer connection as fallback (if bootstrap peers are empty and discovery fails)
        if network_config.bootstrap_peers.is_empty() && !network_config.enable_mdns {
            println!("⚠️  No discovery methods enabled, using legacy peer connection");
            let p2p_clone = p2p_network.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                
                let fallback_peers = vec![
                    "/ip4/127.0.0.1/tcp/4001", // Admin node
                    "/ip4/127.0.0.1/tcp/4003", // Another potential node
                ];
                
                for peer_addr in fallback_peers {
                    if let Err(e) = p2p_clone.connect_to_peer(peer_addr).await {
                        println!("PublicNode: Could not connect to {}: {:?}", peer_addr, e);
                    } else {
                        println!("PublicNode: Attempting connection to {}", peer_addr);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            });
        }

        // Add periodic peer status reporting with discovery info
        let p2p_status = p2p_network.clone();
        let network_config_clone = network_config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                let peer_count = p2p_status.get_peer_count().await;
                println!("📊 PublicNode P2P Status: {} peers | Discovery: {}", 
                    peer_count, 
                    network_config_clone.discovery_methods()
                );
            }
        });

        // --- Refactored admin_actions P2P listener to use Arc<Mutex<PublicNode>> on the main instance ---
        let admin_p2p_network = p2p_network.clone();
        tokio::spawn({
            let public_node_ptr = public_node_ptr.clone();
            async move {
                admin_p2p_network.listen("admin_actions", move |content: &str| {
                    let public_node_ptr = public_node_ptr.clone();
                    let content = content.to_string();
                    tokio::spawn(async move {
                        let msg: Message = match Message::from_json(&content) {
                            Some(m) => m,
                            None => {
                                println!("Failed to parse P2P message");
                                return;
                            }
                        };
                        let content: serde_json::Value = match serde_json::from_str(&msg.content) {
                            Ok(val) => val,
                            Err(e) => {
                                println!("Failed to parse admin action: {:?}", e);
                                return;
                            }
                        };
                        let event_type = content["event_type"].as_str().unwrap_or("");
                        let data = content["data"].clone();
                        let admin_block_hash = content["admin_block_hash"].as_str().unwrap_or("").to_string();

                        let mut node = public_node_ptr.lock().await;
                        match event_type {
                            "mint" => {
                                let to = data["to"].as_str().unwrap_or("").to_string();
                                let amount = data["amount"].as_u64().unwrap_or(0);
                                let _ = node.admin_mint(to, amount, admin_block_hash).await;
                            },
                            "burn" => {
                                let from = data["from"].as_str().unwrap_or("").to_string();
                                let amount = data["amount"].as_u64().unwrap_or(0);
                                let _ = node.admin_burn(from, amount, admin_block_hash).await;
                            },
                            "proof_of_reserve" => {
                                let details = data["details"].as_str().unwrap_or("").to_string();
                                let _ = node.admin_proof_of_reserve(details, admin_block_hash).await;
                            },
                            _ => {
                                println!("Unknown admin event type: {}", event_type);
                            }
                        }
                    });
                    // Return unit type as required by listen
                });
            }
        });
        // --- End refactor ---

        // --- Governance Event Listener ---
        // Listen for messages on the 'governance_events' gossipsub topic and process them
        let governance_p2p = p2p_network.clone();
        let public_node_ptr_clone = public_node_ptr.clone();
        tokio::spawn(async move {
            governance_p2p.listen("governance_events", move |content: &str| {
                let public_node_ptr = public_node_ptr_clone.clone();
                let content = content.to_string();
                tokio::spawn(async move {
                    // Attempt to deserialize the incoming message as a GovernanceEvent
                    match serde_json::from_str::<GovernanceEvent>(&content) {
                        Ok(event) => {
                            let mut node = public_node_ptr.lock().await;
                            // Use the new integration handler for governance events
                            match node.governance_integration.process_governance_event(&event).await {
                                Ok(receipt) => {
                                    println!("[PublicNode] Processed governance event {}: receipt = {:?}", event.event_id, receipt);
                                }
                                Err(e) => {
                                    eprintln!("[PublicNode] Failed to process governance event {}: {}", event.event_id, e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[PublicNode] Failed to deserialize governance event: {}", e);
                        }
                    }
                });
            }).await.unwrap();
        });

        // Note: spawn_admin_block_listener should be called externally after PublicNode creation
        println!("✅ PublicNode started successfully with peer discovery");
        
        Ok(public_node_ptr)
    }

    // Static method to handle admin block listening and sync protocol
    pub fn spawn_admin_block_listener(public_node_ptr: Arc<tokio::sync::Mutex<PublicNode>>) {
        let admin_block_p2p;
        {
            // Get a clone of the p2p_network for the listener
            let node = public_node_ptr.clone();
            admin_block_p2p = futures::executor::block_on(async { node.lock().await.p2p_network.clone() });
        }
        
        // Clone admin_block_p2p for multiple uses
        let admin_block_p2p_clone1 = admin_block_p2p.clone();
        let admin_block_p2p_clone2 = admin_block_p2p.clone();
        let admin_block_p2p_clone3 = admin_block_p2p.clone();
        
        // Clone public_node_ptr for multiple uses  
        let public_node_ptr_clone1 = public_node_ptr.clone();
        let public_node_ptr_clone2 = public_node_ptr.clone();
        
        tokio::spawn(async move {
            admin_block_p2p_clone1.listen("admin_block", move |content: &str| {
                let public_node_ptr = public_node_ptr_clone1.clone();
                let content = content.to_string();
                tokio::spawn(async move {
                    // Parse the incoming admin block message
                    let msg = match Message::from_json(&content) {
                        Some(m) => m,
                        None => {
                            println!("Failed to parse admin_block message");
                            return;
                        }
                    };
                    let admin_block: serde_json::Value = match serde_json::from_str(&msg.content) {
                        Ok(b) => b,
                        Err(e) => {
                            println!("Failed to deserialize admin block: {:?}", e);
                            return;
                        }
                    };
                    
                    let admin_block_hash = admin_block["hash"].as_str().unwrap_or("").to_string();
                    println!("Processing admin block: {}", admin_block_hash);
                    
                    // Process transactions in the admin block
                    if let Some(txs) = admin_block["txs"].as_array() {
                        let mut node = public_node_ptr.lock().await;
                        for tx in txs {
                            // Check if this is a Mint transaction
                            if let Some(mint_data) = tx.get("Mint") {
                                let to = mint_data["to"].as_str().unwrap_or("");
                                let amount = mint_data["amount"].as_u64().unwrap_or(0);
                                // Only check admin_block_hash and event_type for duplicates
                                let already_processed = node.admin_events.iter().any(|e| 
                                    e.admin_block_hash == admin_block_hash && 
                                    e.event_type == "mint"
                                );
                                if !already_processed && !to.is_empty() && amount > 0 {
                                    let _ = node.admin_mint(to.to_string(), amount, admin_block_hash.clone()).await;
                                }
                            }
                            // Check if this is a Burn transaction
                            else if let Some(burn_data) = tx.get("Burn") {
                                let from = burn_data["from"].as_str().unwrap_or("");
                                let amount = burn_data["amount"].as_u64().unwrap_or(0);
                                let already_processed = node.admin_events.iter().any(|e| 
                                    e.admin_block_hash == admin_block_hash && 
                                    e.event_type == "burn"
                                );
                                if !already_processed && !from.is_empty() && amount > 0 {
                                    let _ = node.admin_burn(from.to_string(), amount, admin_block_hash.clone()).await;
                                }
                            }
                            // Check if this is a ProofOfReserve transaction
                            else if let Some(proof_data) = tx.get("ProofOfReserve") {
                                let details = proof_data["details"].as_str().unwrap_or("");
                                let already_processed = node.admin_events.iter().any(|e| 
                                    e.admin_block_hash == admin_block_hash && 
                                    e.event_type == "proof_of_reserve"
                                );
                                if !already_processed && !details.is_empty() {
                                    let _ = node.admin_proof_of_reserve(details.to_string(), admin_block_hash.clone()).await;
                                }
                            }
                        }
                    }
                    // Fallback: check for legacy events format
                    else if let Some(events) = admin_block["events"].as_array() {
                        let mut node = public_node_ptr.lock().await;
                        for event in events {
                            let event_type = event["type"].as_str().unwrap_or("");
                            let data = event["data"].clone();
                            // Process using the legacy format
                            let _ = node.process_admin_event(
                                event_type.to_string(),
                                data,
                                admin_block_hash.clone()
                            ).await;
                        }
                    }
                });
            }).await.unwrap();
        });
        
        // Request sync of missed admin events on startup
        let sync_p2p = admin_block_p2p_clone2.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await; // Wait for network to be ready
            let sync_request = Message::new(
                "request_admin_events".to_string(),
                "{}".to_string(), // Empty payload
                "public".to_string(),
            );
            if let Err(e) = sync_p2p.broadcast(sync_request).await {
                println!("Failed to request admin events sync: {:?}", e);
            } else {
                println!("Requested sync of missed admin events from admin nodes");
            }
        });
        
        // Periodic sync requests for missed admin events
        let periodic_sync_p2p = admin_block_p2p_clone3.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                let sync_request = Message::new(
                    "request_admin_events".to_string(),
                    "{}".to_string(),
                    "public".to_string(),
                );
                if let Err(e) = periodic_sync_p2p.broadcast(sync_request).await {
                    println!("Failed to send periodic admin events sync request: {:?}", e);
                } else {
                    println!("Sent periodic request for missed admin events");
                }
            }
        });

        // Listen for sync_admin_events responses from admin nodes
        let sync_response_p2p = admin_block_p2p.clone();
        tokio::spawn(async move {
            sync_response_p2p.listen("sync_admin_events", move |content: &str| {
                let public_node_ptr = public_node_ptr_clone2.clone();
                let content = content.to_string();
                tokio::spawn(async move {
                    let msg = match Message::from_json(&content) {
                        Some(m) => m,
                        None => {
                            println!("Failed to parse sync_admin_events message");
                            return;
                        }
                    };
                    let mut node = public_node_ptr.lock().await;
                    if let Err(e) = node.handle_admin_event_sync_from_str(&msg.content).await {
                        println!("Failed to handle admin event sync: {}", e);
                    } else {
                        println!("Handled admin event sync from sync_admin_events");
                    }
                });
            }).await.unwrap();
        });
    }

    // Public chain transaction methods
    pub async fn submit_transaction(&mut self, from: String, to: String, amount: u64, token: TokenType, _signature: String) -> Result<String, String> {
        // TODO: Verify signature properly
        let tx = PublicTx::Transfer { from, to, amount, token: token.clone() };
        
        // Add to transaction pool
        self.transaction_pool.push(tx.clone());
        
        // Check if we should produce a block (bootstrap or normal)
        self.check_and_produce_block().await?;
        
        // Broadcast the transaction
        let message = Message::new(
            "new_transaction".to_string(),
            format!("New transaction: {{ from: {} -> to: {} amount: {} token: {:?} }}", 
                   "from", "to", amount, token),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast transaction: {:?}", e);
        }
        
        // Return transaction hash (simplified)
        Ok(format!("tx_hash_{}", chrono::Utc::now().timestamp()))
    }

    pub async fn stake_tokens(&mut self, staker: String, amount: u64, _signature: String) -> Result<String, String> {
        // Parse staker hex string into ValidatorPublicKey
        let staker_bytes = hex::decode(&staker).map_err(|_| "Invalid staker hex".to_string())?;
        let staker_key = ValidatorPublicKey::from_bytes(staker_bytes.try_into().map_err(|_| "Invalid staker key length".to_string())?);
        let tx = PublicTx::Stake { staker: staker_key, amount };
        
        self.transaction_pool.push(tx);
        
        // Broadcast the staking action
        let message = Message::new(
            "stake_action".to_string(),
            format!("Staked {} tokens", amount),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast stake action: {:?}", e);
        }
        
        // Trigger block production
        self.check_and_produce_block().await?;
        
        println!("Staked {} tokens for {}", amount, staker);
        Ok("Staked successfully".to_string())
    }

    pub async fn unstake_tokens(&mut self, staker: String, amount: u64, _signature: String) -> Result<String, String> {
        // Parse staker hex string into ValidatorPublicKey
        let staker_bytes = hex::decode(&staker).map_err(|_| "Invalid staker hex".to_string())?;
        let staker_key = ValidatorPublicKey::from_bytes(staker_bytes.try_into().map_err(|_| "Invalid staker key length".to_string())?);
        let tx = PublicTx::Unstake { staker: staker_key, amount };
        
        self.transaction_pool.push(tx);
        
        // Broadcast the unstaking action
        let message = Message::new(
            "unstake_action".to_string(),
            format!("Unstaked {} tokens", amount),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast unstake action: {:?}", e);
        }
        
        // Trigger block production
        self.check_and_produce_block().await?;
        
        println!("Unstaked {} tokens for {}", amount, staker);
        Ok("Unstaked successfully".to_string())
    }

    pub async fn register_validator(&mut self, validator_key: ValidatorPublicKey, stake: u64) -> Result<String, String> {
        let tx = PublicTx::ValidatorRegistration { validator: validator_key.clone(), stake };
        
        self.transaction_pool.push(tx);
        
        // Broadcast validator registration
        let message = Message::new(
            "validator_registration".to_string(),
            format!("New validator registered with stake: {}", stake),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast validator registration: {:?}", e);
        }
        
        // Trigger block production check after validator registration
        self.check_and_produce_block().await?;
        
        println!("Validator registered with stake: {}", stake);
        Ok("Validator registered successfully".to_string())
    }

    pub async fn produce_block(&mut self) -> Result<PublicBlock, String> {
        if self.transaction_pool.is_empty() {
            return Err("No transactions to include in block".to_string());
        }

        println!("DEBUG: Attempting to produce block with {} transactions", self.transaction_pool.len());
        let txs = self.transaction_pool.drain(..).collect();
        
        match self.consensus.propose_block(&self.signing_key, txs) {
            Ok(block) => {
                // Broadcast the new block
                let message = Message::new(
                    "new_block".to_string(),
                    format!("New block produced: #{} hash: {}", block.index, block.hash),
                    "public".to_string(),
                );
                if let Err(e) = self.p2p_network.broadcast(message).await {
                    println!("Failed to broadcast new block: {:?}", e);
                }
                
                println!("Produced new block: #{} with {} transactions", block.index, block.txs.len());
                Ok(block)
            },
            Err(e) => {
                println!("ERROR: Failed to propose block: {}", e);
                Err(e)
            }
        }
    }

    pub async fn check_and_produce_block(&mut self) -> Result<(), String> {
        let chain_len = self.consensus.chain.len();
        let pool_len = self.transaction_pool.len();
        let validators = self.consensus.get_validators();
        let active_validators = self.consensus.validator_set.get_active_validators();
        
        println!("DEBUG: check_and_produce_block - chain_len: {}, pool_len: {}, validators: {}, active_validators: {}", 
                 chain_len, pool_len, validators.len(), active_validators.len());
        
        // PATCH: Always allow genesis block production if chain height is 0 or only genesis block exists and there are pending txs
        let chain_empty = chain_len <= 1; // Only dummy genesis block exists
        if chain_empty && !self.transaction_pool.is_empty() {
            println!("(PATCH) Producing genesis block with pending transactions to bootstrap validator set");
            return self.produce_block().await.map(|_| ());
        }
        // If we have enough transactions, produce a block (normal operation)
        else if self.transaction_pool.len() >= 1 {
            println!("DEBUG: Attempting to produce block with {} transactions", pool_len);
            return self.produce_block().await.map(|_| ());
        } else {
            println!("DEBUG: No transactions to produce block");
        }
        Ok(())
    }

    // Query methods
    pub fn get_validators(&self) -> Vec<String> {
        self.consensus.get_validators()
            .iter()
            .map(|(key, validator)| {
                format!("{}:{}", hex::encode(key.as_bytes()), validator.stake)
            })
            .collect()
    }

    pub fn get_balance(&self, address: &str, token_type: TokenType) -> Option<u64> {
        Some(self.consensus.get_balance(address, token_type))
    }

    pub fn get_all_balances(&self, address: &str) -> HashMap<TokenType, u64> {
        self.consensus.get_all_balances(address)
    }

    pub fn get_status(&self) -> serde_json::Value {
        let latest_block = self.consensus.get_latest_block();
        let _validator_count = self.consensus.get_validators().len();
        let _total_stake = self.consensus.validator_set.total_stake;
        
        serde_json::json!({
            "height": latest_block.map_or(0, |b| b.index),
            "latest_hash": latest_block
        })
    }

    pub fn get_block(&self, index: u64) -> Option<serde_json::Value> {
        self.consensus.get_block(index).map(|block| {
            serde_json::json!({
                "index": block.index,
                "timestamp": block.timestamp,
                "prev_hash": block.prev_hash,
                "hash": block.hash,
                "proposer": hex::encode(block.proposer.as_bytes()),
                "transaction_count": block.txs.len(),
                "state_root": block.state_root
            })
        })
    }

    pub fn get_recent_events(&self) -> Vec<serde_json::Value> {
        let mut events = Vec::new();

        // 1. Include admin events (as before)
        for event in self.admin_events.iter().rev() {
            events.push(serde_json::json!({
                "type": event.event_type,
                "data": event.data,
                "admin_block_hash": event.admin_block_hash,
                "timestamp": event.timestamp,
            }));
        }

        // 2. Include recent user transactions, stake, and unstake events from recent blocks (last 10 blocks)
        let recent_blocks = self.consensus.chain.iter().rev().take(10);
        for block in recent_blocks {
            for tx in &block.txs {
                match tx {
                    crate::consensus_pos::PublicTx::Transfer { from, to, amount, token } => {
                        events.push(serde_json::json!({
                            "type": "transaction",
                            "timestamp": block.timestamp,
                            "data": {
                                "from": from,
                                "to": to,
                                "amount": amount,
                                "token": token,
                                "block_hash": block.hash,
                            }
                        }));
                    }
                    crate::consensus_pos::PublicTx::Stake { staker, amount } => {
                        events.push(serde_json::json!({
                            "type": "stake",
                            "timestamp": block.timestamp,
                            "data": {
                                "staker": format!("{:?}", staker),
                                "amount": amount,
                                "block_hash": block.hash,
                            }
                        }));
                    }
                    crate::consensus_pos::PublicTx::Unstake { staker, amount } => {
                        events.push(serde_json::json!({
                            "type": "unstake",
                            "timestamp": block.timestamp,
                            "data": {
                                "staker": format!("{:?}", staker),
                                "amount": amount,
                                "block_hash": block.hash,
                            }
                        }));
                    }
                    _ => {}
                }
            }
        }

        events
    }

    pub fn get_public_chain_summary(&self) -> (u64, String, usize) {
        if let Some(latest) = self.consensus.get_latest_block() {
            (latest.index, latest.hash.clone(), self.consensus.chain.len())
        } else {
            (0, "genesis".to_string(), 0)
        }
    }

    // Cross-chain integration methods
    pub async fn process_admin_event(&mut self, event_type: String, data: serde_json::Value, admin_block_hash: String) -> Result<(), String> {
        let tx = match event_type.as_str() {
            "mint" => {
                let to = data["to"].as_str().ok_or("Missing 'to' field")?;
                let amount = data["amount"].as_u64().ok_or("Missing 'amount' field")?;
                PublicTx::AdminMint { 
                    to: to.to_string(), 
                    amount, 
                    admin_block_hash: admin_block_hash.clone() 
                }
            },
            "burn" => {
                let from = data["from"].as_str().ok_or("Missing 'from' field")?;
                let amount = data["amount"].as_u64().ok_or("Missing 'amount' field")?;
                PublicTx::AdminBurn { 
                    from: from.to_string(), 
                    amount, 
                    admin_block_hash: admin_block_hash.clone() 
                }
            },
            "proof_of_reserve" => {
                let details = data["details"].as_str().ok_or("Missing 'details' field")?;
                PublicTx::AdminProofOfReserve { 
                    details: details.to_string(), 
                    admin_block_hash: admin_block_hash.clone() 
                }
            },
            _ => return Err(format!("Unknown admin event type: {}", event_type)),
        };

        self.transaction_pool.push(tx);
        
        // Broadcast cross-chain event
        let message = Message::new(
            "cross_chain_event".to_string(),
            format!("Processed admin {} event from block {}", event_type, admin_block_hash),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast cross-chain event: {:?}", e);
        }
        
        println!("Processed admin {} event from block {}", event_type, admin_block_hash);
        Ok(())
    }

    pub async fn synchronize_chain(&self) {
        let chain_summary = self.node.get_chain_summary();
        let message = Message::new(
            "chain_summary".to_string(),
            chain_summary,
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast chain summary: {:?}", e);
        } else {
            println!("Broadcasted public chain summary.");
        }
    }

    pub fn print_chain(&self) {
        self.node.print_chain();
    }

    // Admin operation methods for direct API access
    pub async fn admin_mint(&mut self, to: String, amount: u64, admin_block_hash: String) -> Result<PublicBlock, String> {
        // Ensure only this admin event is in the pool
        self.transaction_pool.clear();
        let tx = PublicTx::AdminMint { 
            to: to.clone(), 
            amount, 
            admin_block_hash: admin_block_hash.clone() 
        };
        self.transaction_pool.push(tx);
        // Always produce a block for this admin event
        let _block = self.produce_block().await?;
        let latest_block = self.consensus.get_latest_block().unwrap();
        
        let event = AdminEvent {
            event_type: "mint".to_string(), // PATCH: canonical event type
            data: serde_json::json!({"to": to, "amount": amount}),
            admin_block_hash: admin_block_hash.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.admin_events.push(event);
        Self::save_admin_events("public_db/admin_events.json", &self.admin_events);
        
        self.send_admin_receipt_to_admin_node(
            "mint",
            &format!("Minted {} tokens to {}", amount, to),
            &latest_block.hash,
            &admin_block_hash,
        ).await;
        let message = Message::new(
            "admin_mint".to_string(),
            format!("Admin minted {} tokens to {}", amount, to),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin mint: {:?}", e);
        }
        println!("Admin minted {} tokens to {}", amount, to);
        Ok(latest_block.clone())
    }

    pub async fn admin_burn(&mut self, from: String, amount: u64, admin_block_hash: String) -> Result<PublicBlock, String> {
        self.transaction_pool.clear();
        let tx = PublicTx::AdminBurn { 
            from: from.clone(), 
            amount, 
            admin_block_hash: admin_block_hash.clone() 
        };
        
        self.transaction_pool.push(tx);
        let _block = self.produce_block().await?;
        let latest_block = self.consensus.get_latest_block().unwrap();
        
        let event = AdminEvent {
            event_type: "burn".to_string(), // PATCH: canonical event type
            data: serde_json::json!({"from": from, "amount": amount}),
            admin_block_hash: admin_block_hash.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.admin_events.push(event);
        Self::save_admin_events("public_db/admin_events.json", &self.admin_events);
        
        self.send_admin_receipt_to_admin_node(
            "burn",
            &format!("Burned {} tokens from {}", amount, from),
            &latest_block.hash,
            &admin_block_hash,
        ).await;
        let message = Message::new(
            "admin_burn".to_string(),
            format!("Admin burned {} tokens from {}", amount, from),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin burn: {:?}", e);
        }
        println!("Admin burned {} tokens from {}", amount, from);
        Ok(latest_block.clone())
    }

    pub async fn admin_proof_of_reserve(&mut self, details: String, admin_block_hash: String) -> Result<PublicBlock, String> {
        self.transaction_pool.clear();
        let tx = PublicTx::AdminProofOfReserve { 
            details: details.clone(), 
            admin_block_hash: admin_block_hash.clone() 
        };
        
        self.transaction_pool.push(tx);
        let _block = self.produce_block().await?;
        let latest_block = self.consensus.get_latest_block().unwrap();
        
        let event = AdminEvent {
            event_type: "proof_of_reserve".to_string(), // PATCH: canonical event type
            data: serde_json::json!({"details": details}),
            admin_block_hash: admin_block_hash.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.admin_events.push(event);
        Self::save_admin_events("public_db/admin_events.json", &self.admin_events);
        
        self.send_admin_receipt_to_admin_node(
            "proof_of_reserve",
            &format!("Proof of reserve: {}", details),
            &latest_block.hash,
            &admin_block_hash,
        ).await;
        let message = Message::new(
            "admin_proof_of_reserve".to_string(),
            format!("Admin proof of reserve: {}", details),
            "public".to_string(),
        );
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to broadcast admin proof of reserve: {:?}", e);
        }
        println!("Admin proof of reserve recorded: {}", details);
        Ok(latest_block.clone())
    }

    // Helper method to send admin event execution receipts
    async fn send_admin_receipt_to_admin_node(
        &self,
        event_type: &str,
        details: &str,
        public_block_hash: &str,
        admin_block_hash: &str,
    ) {
        let receipt = AdminEventReceipt {
            event_type: event_type.to_string(),
            details: details.to_string(),
            public_block_hash: public_block_hash.to_string(),
            admin_block_hash: admin_block_hash.to_string(),
            timestamp: Utc::now().timestamp() as u64,
        };
        
        let message = Message::new(
            "admin_event_receipt".to_string(),
            serde_json::to_string(&receipt).unwrap(),
            "public".to_string(),
        );
        
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to send admin event receipt: {:?}", e);
        } else {
            println!("Sent admin event receipt: {} - {}", event_type, details);
        }
    }

    // Enhanced cross-chain sync methods
    pub async fn sync_with_admin_node(&mut self, _admin_peer_id: Option<String>) -> Result<(), String> {
        // Request latest admin chain events from connected admin nodes
        let message = Message::new(
            "request_admin_events".to_string(),
            "Request latest admin events for sync".to_string(),
            "public".to_string(),
        );
        
        if let Err(e) = self.p2p_network.broadcast(message).await {
            println!("Failed to request admin events: {:?}", e);
            return Err("Failed to request admin events".to_string());
        }
        
        println!("Requested admin events for cross-chain sync");
        Ok(())
    }

    pub async fn handle_admin_event_sync(&mut self, admin_events: Vec<serde_json::Value>) -> Result<(), String> {
        let event_count = admin_events.len();
        for event in &admin_events {
            let event_type = event["event_type"].as_str().unwrap_or("unknown");
            let data = &event["data"];
            let admin_block_hash = event["admin_block_hash"].as_str().unwrap_or("unknown").to_string();
            
            match event_type {
                "mint" => {
                    let to = data["to"].as_str().ok_or("Missing 'to' field")?;
                    let amount = data["amount"].as_u64().ok_or("Missing 'amount' field")?;
                    self.admin_mint(to.to_string(), amount, admin_block_hash).await?;
                },
                "burn" => {
                    let from = data["from"].as_str().ok_or("Missing 'from' field")?;
                    let amount = data["amount"].as_u64().ok_or("Missing 'amount' field")?;
                    self.admin_burn(from.to_string(), amount, admin_block_hash).await?;
                },
                "proof_of_reserve" => {
                    let details = data["details"].as_str().ok_or("Missing 'details' field")?;
                    self.admin_proof_of_reserve(details.to_string(), admin_block_hash).await?;
                },
                _ => {
                    println!("Unknown admin event type: {}", event_type);
                }
            }
        }
        
        println!("Synced {} admin events", event_count);
        Ok(())
    }

    // Enhanced cross-chain sync methods - Robust admin event sync handler
    pub async fn handle_admin_event_sync_from_str(&mut self, response_body: &str) -> Result<(), String> {
        // Parse as generic JSON value
        let parsed: serde_json::Value = match serde_json::from_str(response_body) {
            Ok(val) => val,
            Err(e) => return Err(format!("Failed to parse admin event sync payload: {}", e)),
        };

        let items: Vec<serde_json::Value> = if parsed.is_array() {
            parsed.as_array().unwrap().clone()
        } else {
            vec![parsed]
        };

        let mut processed = 0;
        for item in items {
            // Check if this is an admin block (has txs array) or a direct event
            if let Some(txs) = item.get("txs").and_then(|v| v.as_array()) {
                // This is an admin block - extract events from transactions
                let admin_block_hash = item.get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown").to_string();
                
                println!("[admin_event_sync] Processing admin block: {}", admin_block_hash);
                
                for tx in txs {
                    // Extract transaction type and data
                    if let Some(mint_data) = tx.get("Mint") {
                        let to = mint_data.get("to").and_then(|v| v.as_str());
                        let amount = mint_data.get("amount").and_then(|v| v.as_u64());
                        
                        if let (Some(to), Some(amount)) = (to, amount) {
                            // Check if we already processed this event to avoid duplicates
                            let already_processed = self.admin_events.iter().any(|e| 
                                e.admin_block_hash == admin_block_hash && 
                                e.event_type == "mint" &&
                                e.data.get("to").and_then(|v| v.as_str()) == Some(to) &&
                                e.data.get("amount").and_then(|v| v.as_u64()) == Some(amount)
                            );
                            
                            if !already_processed {
                                let _ = self.admin_mint(to.to_string(), amount, admin_block_hash.clone()).await;
                                processed += 1;
                                println!("[admin_event_sync] Processed mint: {} tokens to {}", amount, to);
                            } else {
                                println!("[admin_event_sync] Skipping duplicate mint event for block {}", admin_block_hash);
                            }
                        } else {
                            println!("[admin_event_sync] Skipping mint tx: missing to/amount: {:?}", mint_data);
                        }
                    }
                    else if let Some(burn_data) = tx.get("Burn") {
                        let from = burn_data.get("from").and_then(|v| v.as_str());
                        let amount = burn_data.get("amount").and_then(|v| v.as_u64());
                        
                        if let (Some(from), Some(amount)) = (from, amount) {
                            let already_processed = self.admin_events.iter().any(|e| 
                                e.admin_block_hash == admin_block_hash && 
                                e.event_type == "burn" &&
                                e.data.get("from").and_then(|v| v.as_str()) == Some(from) &&
                                e.data.get("amount").and_then(|v| v.as_u64()) == Some(amount)
                            );
                            
                            if !already_processed {
                                let _ = self.admin_burn(from.to_string(), amount, admin_block_hash.clone()).await;
                                processed += 1;
                                println!("[admin_event_sync] Processed burn: {} tokens from {}", amount, from);
                            } else {
                                println!("[admin_event_sync] Skipping duplicate burn event for block {}", admin_block_hash);
                            }
                        } else {
                            println!("[admin_event_sync] Skipping burn tx: missing from/amount: {:?}", burn_data);
                        }
                    }
                    else if let Some(proof_data) = tx.get("ProofOfReserve") {
                        let details = proof_data.get("details").and_then(|v| v.as_str());
                        
                        if let Some(details) = details {
                            let already_processed = self.admin_events.iter().any(|e| 
                                e.admin_block_hash == admin_block_hash && 
                                e.event_type == "proof_of_reserve" &&
                                e.data.get("details").and_then(|v| v.as_str()) == Some(details)
                            );
                            
                            if !already_processed {
                                let _ = self.admin_proof_of_reserve(details.to_string(), admin_block_hash.clone()).await;
                                processed += 1;
                                println!("[admin_event_sync] Processed proof_of_reserve: {}", details);
                            } else {
                                println!("[admin_event_sync] Skipping duplicate proof_of_reserve event for block {}", admin_block_hash);
                            }
                        } else {
                            println!("[admin_event_sync] Skipping proof_of_reserve tx: missing details: {:?}", proof_data);
                        }
                    }
                    else {
                        println!("[admin_event_sync] Skipping unknown transaction type: {:?}", tx);
                    }
                }
            }
            else {
                // This might be a direct event format - try to process as before
                let event_type = item.get("event_type")
                    .or_else(|| item.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                if !event_type.is_empty() {
                    let data = item.get("data").cloned().unwrap_or(serde_json::json!({}));
                    let admin_block_hash = item.get("admin_block_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown").to_string();

                    // Check for duplicates before processing
                    let already_processed = self.admin_events.iter().any(|e| 
                        e.admin_block_hash == admin_block_hash && 
                        e.event_type == event_type &&
                        e.data == data
                    );
                    
                    if !already_processed {
                        match event_type {
                            "mint" | "admin_mint" => {
                                let to = data.get("to").and_then(|v| v.as_str());
                                let amount = data.get("amount").and_then(|v| v.as_u64());
                                if let (Some(to), Some(amount)) = (to, amount) {
                                    let _ = self.admin_mint(to.to_string(), amount, admin_block_hash.clone()).await;
                                    processed += 1;
                                }
                            },
                            "burn" | "admin_burn" => {
                                let from = data.get("from").and_then(|v| v.as_str());
                                let amount = data.get("amount").and_then(|v| v.as_u64());
                                if let (Some(from), Some(amount)) = (from, amount) {
                                    let _ = self.admin_burn(from.to_string(), amount, admin_block_hash.clone()).await;
                                    processed += 1;
                                }
                            },
                            "proof_of_reserve" | "admin_proof_of_reserve" => {
                                let details = data.get("details").and_then(|v| v.as_str());
                                if let Some(details) = details {
                                    let _ = self.admin_proof_of_reserve(details.to_string(), admin_block_hash.clone()).await;
                                    processed += 1;
                                }
                            },
                            _ => {
                                println!("[admin_event_sync] Unknown event_type: {} in event: {:?}", event_type, item);
                            }
                        }
                    } else {
                        println!("[admin_event_sync] Skipping duplicate event: {} for block {}", event_type, admin_block_hash);
                    }
                } else {
                    println!("[admin_event_sync] Skipping item: not an admin block or valid event: {:?}", item);
                }
            }
        }
        
        if processed > 0 {
            println!("✅ Synced {} admin events successfully", processed);
        } else {
            println!("⚠️  No new admin events found to sync");
        }
        Ok(())
    }

    /// Handle governance events from DAO node (new integrated approach)
    pub async fn handle_governance_event(&self, event: GovernanceEvent) -> Result<(), String> {
        println!("🌐 PublicNode received governance event: {}", event.event_id);
        
        // Process the event through governance integration
        let receipt = self.governance_integration
            .process_governance_event(&event)
            .await
            .map_err(|e| format!("Failed to process governance event: {}", e))?;
        
        println!("✅ PublicNode processed governance event - Receipt: {:?}", receipt);
        
        // In a real implementation, you might want to:
        // - Store the receipt in public storage
        // - Update public blockchain state based on the event
        // - Trigger specific public node actions
        
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

    /// Handle governance events specifically related to smart contracts
    pub async fn handle_contract_governance_event(&mut self, event: &GovernanceEvent) -> Result<(), String> {
        if let Some(action) = event.data.get("action").and_then(|a| a.as_str()) {
            match action {
                "contract_deployed" => {
                    self.handle_contract_deployment(event).await
                }
                "contract_disabled" => {
                    self.handle_contract_disable(event).await
                }
                _ => {
                    println!("📄 Unknown contract governance action: {}", action);
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    /// Handle contract deployment event from governance
    async fn handle_contract_deployment(&mut self, event: &GovernanceEvent) -> Result<(), String> {
        let data = &event.data;
        
        let contract_id = data.get("contract_id")
            .and_then(|c| c.as_str())
            .ok_or_else(|| "Missing contract_id in deployment event".to_string())?;
        
        let bytecode_b64 = data.get("bytecode")
            .and_then(|b| b.as_str())
            .ok_or_else(|| "Missing bytecode in deployment event".to_string())?;
        
        let bytecode = base64::engine::general_purpose::STANDARD.decode(bytecode_b64)
            .map_err(|_| "Invalid bytecode encoding".to_string())?;
        
        let allowed_methods: Vec<String> = data.get("allowed_methods")
            .and_then(|m| m.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        
        let permission_level = match data.get("permission_level").and_then(|p| p.as_str()).unwrap_or("Public") {
            "Public" => crate::smart_contract_executor::PermissionLevel::Public,
            "Restricted" => crate::smart_contract_executor::PermissionLevel::Restricted,
            "Admin" => crate::smart_contract_executor::PermissionLevel::Admin,
            "Governance" => crate::smart_contract_executor::PermissionLevel::Governance,
            _ => crate::smart_contract_executor::PermissionLevel::Public,
        };
        
        let gas_limit = data.get("gas_limit")
            .and_then(|g| g.as_u64())
            .unwrap_or(1_000_000);
        
        let executable_contract = ExecutableContract {
            contract_id: contract_id.to_string(),
            name: format!("Contract {}", contract_id),
            bytecode,
            allowed_methods,
            permission_level,
            gas_limit,
            deployment_timestamp: chrono::Utc::now(),
        };
        
        self.contract_executor.add_contract(executable_contract);
        
        println!("📄 Public Node: Deployed smart contract {}", contract_id);
        Ok(())
    }

    /// Handle contract disable event from governance
    async fn handle_contract_disable(&mut self, event: &GovernanceEvent) -> Result<(), String> {
        let contract_id = event.data.get("contract_id")
            .and_then(|c| c.as_str())
            .ok_or_else(|| "Missing contract_id in disable event".to_string())?;
        
        self.contract_executor.remove_contract(contract_id);
        
        println!("📄 Public Node: Disabled smart contract {}", contract_id);
        Ok(())
    }

    /// Execute a smart contract method
    pub async fn execute_smart_contract(
        &self,
        request: ContractExecutionRequest,
    ) -> Result<crate::smart_contract_executor::ContractExecutionResult, String> {
        self.contract_executor.execute_contract(request).await
    }

    /// Get available smart contracts
    pub fn get_available_contracts(&self) -> Vec<String> {
        self.contract_executor.get_available_contracts()
    }

    /// Get contract metadata
    pub fn get_contract_metadata(&self, contract_id: &str) -> Option<serde_json::Value> {
        self.contract_executor.get_contract_stats(contract_id)
    }
}
