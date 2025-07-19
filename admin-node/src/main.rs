// admin_main.rs - Entry point for admin node
use std::env;
use std::collections::HashSet;
use std::sync::Arc;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use e3_core_lib::p2p::Message;

mod admin_node;
mod consensus_poa;
mod kafka_publisher;
mod contract_policy;
use admin_node::AdminNode;
use consensus_poa::AdminPublicKey;
use kafka_publisher::AdminKafkaPublisher;

// HTTP API Request/Response structures
#[derive(Deserialize)]
struct MintRequest {
    amount: u64,
    to: String,
    proof_of_reserve: String, // REQUIRED: Proof of reserve for minting
}

#[derive(Deserialize)]
struct BurnRequest {
    amount: u64,
    from: String,
}

#[derive(Deserialize)]
struct ProofOfReserveRequest {
    details: String,
}

#[derive(Deserialize)]
struct ProposeAdminRequest {
    public_key: String, // hex encoded
}

#[derive(Deserialize)]
struct VoteRequest {
    proposal_id: u64,
    approve: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    node_id: String,
    chain_index: u64,
    chain_hash: String,
    chain_length: usize,
    authorities_count: usize,
    pending_proposals: usize,
}

#[derive(Serialize)]
struct AuthoritiesResponse {
    authorities: Vec<String>, // hex encoded public keys
}

#[derive(Serialize)]
struct ProposalsResponse {
    proposals: Vec<ProposalInfo>,
}

#[derive(Serialize)]
struct ProposalInfo {
    id: u64,
    proposal_type: String,
    target_key: String,
    proposer: String,
    votes_for: usize,
    votes_against: usize,
    status: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

// Shared state for HTTP handlers
struct AppStateData {
    admin_node: AdminNode,
    kafka_publisher: Option<AdminKafkaPublisher>,
}

type AppState = Arc<Mutex<AppStateData>>;

// HTTP API Handlers
async fn mint_handler(
    State(state): State<AppState>,
    Json(payload): Json<MintRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut app_state = state.lock().await;
    match app_state.admin_node.mint_gt_with_proof(payload.amount, payload.to.clone(), payload.proof_of_reserve.clone()).await {
        Ok(block) => {
            // Publish to Kafka if available
            if let Some(kafka_publisher) = &app_state.kafka_publisher {
                if let Err(e) = kafka_publisher.publish_mint_event(
                    payload.to.clone(),
                    payload.amount,
                    block.hash.clone()
                ).await {
                    eprintln!("Failed to publish mint event to Kafka: {}", e);
                }
            }
            
            Ok(Json(ApiResponse {
                success: true,
                data: Some(format!("Minted {} GT tokens with proof of reserve. Block hash: {}", payload.amount, block.hash)),
                error: None,
            }))
        },
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn burn_handler(
    State(state): State<AppState>,
    Json(payload): Json<BurnRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut app_state = state.lock().await;
    match app_state.admin_node.burn_gt(payload.amount, payload.from.clone()).await {
        Ok(block) => {
            // Publish to Kafka if available
            if let Some(kafka_publisher) = &app_state.kafka_publisher {
                if let Err(e) = kafka_publisher.publish_burn_event(
                    payload.from.clone(),
                    payload.amount,
                    block.hash.clone()
                ).await {
                    eprintln!("Failed to publish burn event to Kafka: {}", e);
                }
            }
            
            Ok(Json(ApiResponse {
                success: true,
                data: Some(format!("Burned {} GT tokens. Block hash: {}", payload.amount, block.hash)),
                error: None,
            }))
        },
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn proof_of_reserve_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProofOfReserveRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut app_state = state.lock().await;
    match app_state.admin_node.record_proof_of_reserve(payload.details.clone()).await {
        Ok(block) => {
            // Publish to Kafka if available
            if let Some(kafka_publisher) = &app_state.kafka_publisher {
                if let Err(e) = kafka_publisher.publish_proof_of_reserve_event(
                    payload.details.clone(),
                    block.hash.clone()
                ).await {
                    eprintln!("Failed to publish proof of reserve event to Kafka: {}", e);
                }
            }
            
            Ok(Json(ApiResponse {
                success: true,
                data: Some(format!("Proof of reserve recorded. Block hash: {}", block.hash)),
                error: None,
            }))
        },
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn propose_add_admin_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProposeAdminRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut app_state = state.lock().await;
    
    // Parse hex-encoded public key
    let public_key_bytes = match hex::decode(&payload.public_key) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid hex-encoded public key".to_string()),
        })),
    };

    if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid public key length".to_string()),
        }));
    }

    let mut key_array = [0u8; PUBLIC_KEY_LENGTH];
    key_array.copy_from_slice(&public_key_bytes);
    
    let admin_key = AdminPublicKey::from_bytes(key_array);
    
    match app_state.admin_node.propose_add_admin_key(admin_key).await {
        Ok(block) => Ok(Json(ApiResponse {
            success: true,
            data: Some(format!("Proposal to add admin created. Block hash: {}", block.hash)),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn propose_remove_admin_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProposeAdminRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut app_state = state.lock().await;
    
    // Parse hex-encoded public key
    let public_key_bytes = match hex::decode(&payload.public_key) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid hex-encoded public key".to_string()),
        })),
    };

    if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid public key length".to_string()),
        }));
    }

    let mut key_array = [0u8; PUBLIC_KEY_LENGTH];
    key_array.copy_from_slice(&public_key_bytes);
    
    let admin_key = AdminPublicKey::from_bytes(key_array);
    
    match app_state.admin_node.propose_remove_admin_key(admin_key).await {
        Ok(block) => Ok(Json(ApiResponse {
            success: true,
            data: Some(format!("Proposal to remove admin created. Block hash: {}", block.hash)),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn vote_handler(
    State(state): State<AppState>,
    Json(payload): Json<VoteRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut app_state = state.lock().await;
    match app_state.admin_node.vote_authority_change(payload.proposal_id, payload.approve).await {
        Ok(completed) => {
            let message = if completed {
                "Vote recorded and proposal completed"
            } else {
                "Vote recorded"
            };
            Ok(Json(ApiResponse {
                success: true,
                data: Some(message.to_string()),
                error: None,
            }))
        },
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn status_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<StatusResponse>>, StatusCode> {
    let app_state = state.lock().await;
    let (index, hash, length) = app_state.admin_node.get_admin_chain_summary();
    let authorities = app_state.admin_node.get_authorities();
    let pending_proposals = app_state.admin_node.get_pending_proposals();
    
    Ok(Json(ApiResponse {
        success: true,
        data: Some(StatusResponse {
            node_id: hex::encode(app_state.admin_node.signing_key.public.to_bytes()),
            chain_index: index,
            chain_hash: hash,
            chain_length: length,
            authorities_count: authorities.len(),
            pending_proposals: pending_proposals.len(),
        }),
        error: None,
    }))
}

async fn authorities_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<AuthoritiesResponse>>, StatusCode> {
    let app_state = state.lock().await;
    let authorities = app_state.admin_node.get_authorities();
    
    let authority_keys: Vec<String> = authorities
        .iter()
        .map(|key| hex::encode(key.as_bytes()))
        .collect();
    
    Ok(Json(ApiResponse {
        success: true,
        data: Some(AuthoritiesResponse {
            authorities: authority_keys,
        }),
        error: None,
    }))
}

async fn proposals_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ProposalsResponse>>, StatusCode> {
    let app_state = state.lock().await;
    let pending_proposals = app_state.admin_node.get_pending_proposals();
    
    let proposal_infos: Vec<ProposalInfo> = pending_proposals
        .iter()
        .map(|proposal| ProposalInfo {
            id: proposal.id,
            proposal_type: match &proposal.action {
                consensus_poa::AuthorityAction::AddAdmin(_) => "add_authority".to_string(),
                consensus_poa::AuthorityAction::RemoveAdmin(_) => "remove_authority".to_string(),
            },
            target_key: match &proposal.action {
                consensus_poa::AuthorityAction::AddAdmin(key) => hex::encode(key.as_bytes()),
                consensus_poa::AuthorityAction::RemoveAdmin(key) => hex::encode(key.as_bytes()),
            },
            proposer: "".to_string(), // Fill with actual proposer if available
            votes_for: proposal.approvals,
            votes_against: proposal.rejections,
            status: if proposal.is_completed() { "completed".to_string() } else { "pending".to_string() },
        })
        .collect();
    
    Ok(Json(ApiResponse {
        success: true,
        data: Some(ProposalsResponse {
            proposals: proposal_infos,
        }),
        error: None,
    }))
}

async fn receipts_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<admin_node::AdminEventReceipt>>>, StatusCode> {
    let app_state = state.lock().await;
    let receipts = app_state.admin_node.execution_receipts.clone();
    Ok(Json(ApiResponse {
        success: true,
        data: Some(receipts),
        error: None,
    }))
}

// Handler for /gold_unit_supply
async fn gold_unit_supply_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<u64>>, StatusCode> {
    let app_state = state.lock().await;
    let supply = app_state.admin_node.get_gold_unit_supply();
    Ok(Json(ApiResponse {
        success: true,
        data: Some(supply),
        error: None,
    }))
}

// Handler for /status (simple health check)
async fn simple_status_handler() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse {
        success: true,
        data: Some("Admin node running"),
        error: None,
    })
}

// Contract policy request/response structures
#[derive(Deserialize)]
struct UpdateContractPolicyRequest {
    contract_id: String,
    policy_updates: serde_json::Value,
}

#[derive(Deserialize)]
struct UpdateGlobalPolicyRequest {
    policy_updates: serde_json::Value,
}

#[derive(Deserialize)]
struct EmergencyShutdownRequest {
    reason: String,
}

// =================== CONTRACT POLICY HANDLERS ===================

async fn update_contract_policy_handler(
    State(state): State<AppState>,
    Json(req): Json<UpdateContractPolicyRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut node = state.lock().await;
    
    match node.admin_node.contract_policy_manager.update_contract_policy(req.contract_id.clone(), req.policy_updates) {
        Ok(()) => {
            let response = serde_json::json!({
                "status": "success",
                "message": "Contract policy updated",
                "contract_id": req.contract_id
            });
            Ok(Json(response))
        }
        Err(e) => {
            let response = serde_json::json!({
                "status": "error",
                "message": e
            });
            Ok(Json(response))
        }
    }
}

async fn update_global_policy_handler(
    State(state): State<AppState>,
    Json(req): Json<UpdateGlobalPolicyRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut node = state.lock().await;
    
    match node.admin_node.contract_policy_manager.update_global_policy(req.policy_updates) {
        Ok(()) => {
            let response = serde_json::json!({
                "status": "success",
                "message": "Global contract policy updated"
            });
            Ok(Json(response))
        }
        Err(e) => {
            let response = serde_json::json!({
                "status": "error",
                "message": e
            });
            Ok(Json(response))
        }
    }
}

async fn contract_policy_report_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let node = state.lock().await;
    let report = node.admin_node.contract_policy_manager.generate_policy_report();
    Ok(Json(report))
}

async fn emergency_shutdown_handler(
    State(state): State<AppState>,
    Json(req): Json<EmergencyShutdownRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut node = state.lock().await;
    node.admin_node.contract_policy_manager.emergency_shutdown(req.reason.clone());
    
    let response = serde_json::json!({
        "status": "success",
        "message": "Emergency shutdown activated",
        "reason": req.reason
    });
    Ok(Json(response))
}

async fn emergency_restore_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut node = state.lock().await;
    node.admin_node.contract_policy_manager.emergency_restore();
    
    let response = serde_json::json!({
        "status": "success",
        "message": "Smart contract execution restored"
    });
    Ok(Json(response))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Booting E3-Core Admin Node...");

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <db_path> <port>", args[0]);
        return Ok(());
    }
    let db_path = &args[1];
    let port = &args[2];
    let port: u16 = port.parse().map_err(|_| {
        format!("Invalid port number: {}", port)
    })?;

    // For demo, create a keypair (in production, load from secure storage)
    use ed25519_dalek::{SecretKey, PublicKey, Keypair};
    let secret_bytes = [1u8; SECRET_KEY_LENGTH]; // Use proper key generation in production
    let secret = SecretKey::from_bytes(&secret_bytes)?;
    let public = PublicKey::from(&secret);
    let keypair = Keypair { secret, public };
    
    // Initial authority set (for demo, just this node)
    let mut initial_authorities = HashSet::new();
    initial_authorities.insert(AdminPublicKey::from(keypair.public));

    let mut admin_node = AdminNode::new(db_path.to_string(), port, keypair, initial_authorities).await?;
    admin_node.start().await?;

    // Initialize Kafka publisher
    let kafka_publisher = match AdminKafkaPublisher::new("localhost:9092", "admin-events") {
        Ok(publisher) => {
            println!("Kafka publisher initialized successfully");
            Some(publisher)
        },
        Err(e) => {
            eprintln!("Failed to initialize Kafka publisher: {:?}", e);
            eprintln!("Continuing without Kafka - events will not be published");
            None
        }
    };

    // Wrap in Arc<Mutex<>> for shared access across HTTP handlers
    let app_state: AppState = Arc::new(Mutex::new(AppStateData {
        admin_node,
        kafka_publisher,
    }));

    // Build HTTP API routes
    let app = Router::new()
        .route("/api/mint", post(mint_handler))
        .route("/api/burn", post(burn_handler))
        .route("/api/proof-of-reserve", post(proof_of_reserve_handler))
        .route("/api/propose/add-admin", post(propose_add_admin_handler))
        .route("/api/propose/remove-admin", post(propose_remove_admin_handler))
        .route("/api/vote", post(vote_handler))
        .route("/api/status", get(status_handler))
        .route("/api/authorities", get(authorities_handler))
        .route("/api/proposals", get(proposals_handler))
        .route("/api/receipts", get(receipts_handler))
        .route("/gold_unit_supply", get(gold_unit_supply_handler))
        .route("/status", get(simple_status_handler))
        // Contract policy endpoints
        .route("/api/contracts/policy/update", post(update_contract_policy_handler))
        .route("/api/contracts/policy/global", post(update_global_policy_handler))
        .route("/api/contracts/policy/report", get(contract_policy_report_handler))
        .route("/api/contracts/emergency/shutdown", post(emergency_shutdown_handler))
        .route("/api/contracts/emergency/restore", post(emergency_restore_handler))
        .with_state(app_state.clone());

    // Calculate HTTP server port (node port + 1000)
    let http_port = port + 1000;
    let addr = format!("0.0.0.0:{}", http_port);
    let socket_addr: std::net::SocketAddr = addr.parse().map_err(|_| {
        format!("Invalid socket address: {}", addr)
    })?;
    
    println!("Admin Node started on port {}", port);
    println!("HTTP API server starting on {}", addr);
    println!("Node ID: {}", hex::encode(app_state.lock().await.admin_node.signing_key.public.to_bytes()));

    // Start HTTP server in background
    tokio::spawn(async move {
        println!("HTTP API listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(&socket_addr).await.unwrap();
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });

    // Set up P2P message handler for admin event receipts
    {
        let app_state_clone = app_state.clone();
        let p2p_network = app_state.lock().await.admin_node.p2p_network.clone();
        
        // Listen for admin event receipts from public nodes
        tokio::spawn(async move {
            if let Err(e) = p2p_network.listen("admin_event_receipt", move |content: &str| {
                let app_state_clone = app_state_clone.clone();
                let content = content.to_string();
                
                tokio::spawn(async move {
                    match serde_json::from_str::<admin_node::AdminEventReceipt>(&Message::from_json(content.as_str()).unwrap().content) {
                        Ok(receipt) => {
                            let mut node = app_state_clone.lock().await;
                            node.admin_node.handle_admin_event_receipt(receipt).await;
                        },
                        Err(e) => {
                            println!("Failed to parse admin event receipt: {:?}", e);
                        }
                    }
                });
            }).await {
                println!("Failed to set up admin event receipt listener: {:?}", e);
            }
        });

        // Listen for sync requests from public nodes
        let p2p_network_sync = app_state.lock().await.admin_node.p2p_network.clone();
        let app_state_sync = app_state.clone();
        tokio::spawn(async move {
            let p2p_clone = p2p_network_sync.clone();
            if let Err(e) = p2p_network_sync.listen("request_admin_events", move |_content: &str| {
                let app_state_clone = app_state_sync.clone();
                let p2p_network_clone = p2p_clone.clone();
                
                tokio::spawn(async move {
                    println!("[DEBUG] Received request_admin_events from public node");
                    
                    // Get all admin events from the consensus layer
                    let node = app_state_clone.lock().await;
                    let event_log = node.admin_node.get_event_log();
                    
                    // Serialize all admin events
                    let events_json = serde_json::json!({
                        "event_type": "admin_events_sync",
                        "events": event_log.iter().enumerate().map(|(index, tx)| {
                            match tx {
                                consensus_poa::AdminTx::Mint { to, amount } => serde_json::json!({
                                    "event_type": "mint",
                                    "data": { "to": to, "amount": amount },
                                    "index": index
                                }),
                                consensus_poa::AdminTx::Burn { from, amount } => serde_json::json!({
                                    "event_type": "burn", 
                                    "data": { "from": from, "amount": amount },
                                    "index": index
                                }),
                                consensus_poa::AdminTx::ProofOfReserve { details } => serde_json::json!({
                                    "event_type": "proof_of_reserve",
                                    "data": { "details": details },
                                    "index": index
                                }),
                                _ => serde_json::json!({
                                    "event_type": "other",
                                    "data": {},
                                    "index": index
                                })
                            }
                        }).collect::<Vec<_>>()
                    });
                    
                    // Send sync response
                    let sync_message = Message::new(
                        "sync_admin_events".to_string(),
                        events_json.to_string(),
                        "admin".to_string(),
                    );
                    
                    if let Err(e) = p2p_network_clone.broadcast(sync_message).await {
                        println!("Failed to send sync response: {:?}", e);
                    } else {
                        println!("[DEBUG] Sent {} admin events to public node", event_log.len());
                    }
                });
            }).await {
                println!("Failed to set up sync request listener: {:?}", e);
            }
        });
    }

    // Demo admin actions after startup delay
    // tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // {
    //     let mut node = app_state.lock().await;
    //     // Mint some GT tokens with required proof of reserve
    //     if let Ok(_) = node.mint_gt_with_proof(100, "Treasury".to_string(), "Audited: 100oz gold in vault A1 - Initial mint".to_string()).await {
    //         println!("Demo: Mint operation with proof successful");
    //     }
    //     // Print current admin chain status
    //     let (index, hash, length) = node.get_admin_chain_summary();
    //     println!("Admin Chain Summary - Index: {}, Hash: {}, Length: {}", index, hash, length);
    //     // Print authorities
    //     println!("Current authorities: {:?}", node.get_authorities());
    // }

    // Keep the node running with periodic status updates
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        
        let node = app_state.lock().await;
        let (index, _, _) = node.admin_node.get_admin_chain_summary();
        println!("Admin node running - Latest block: {} - HTTP API on :{}", index, http_port);
    }
}
