// public/public_main.rs - Entry point for public node with HTTP API
use std::env;
use std::sync::Arc;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

mod public_node;
mod consensus_pos;
mod kafka_publisher;
mod kafka_consumer;
mod smart_contract_executor;
use public_node::PublicNode;
use consensus_pos::{ValidatorPublicKey, TokenType};
use kafka_consumer::KafkaConsumer;

// HTTP API Request/Response structures
#[derive(Deserialize)]
struct SubmitTxRequest {
    from: String,
    to: String,
    amount: u64,
    signature: String,
    token: TokenType, // Add token field
}

#[derive(Deserialize)]
struct StakeRequest {
    staker: String,
    amount: u64,
    signature: String,
}

#[derive(Deserialize)]
struct UnstakeRequest {
    staker: String,
    amount: u64,
    signature: String,
}

#[derive(Deserialize)]
struct ValidatorRegRequest {
    validator_key: String, // hex encoded
    stake: u64,
}

#[derive(Serialize)]
struct StatusResponse {
    node_id: String,
    chain_height: u64,
    chain_hash: String,
    validator_count: usize,
    total_stake: u64,
    transaction_pool_size: usize,
}

#[derive(Serialize)]
struct ValidatorsResponse {
    validators: Vec<String>,
}

#[derive(Serialize)]
struct EventsResponse {
    events: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

// Shared state for HTTP handlers
type AppState = Arc<Mutex<PublicNode>>;

// HTTP API Handlers
async fn submit_tx_handler(
    State(state): State<AppState>,
    Json(payload): Json<SubmitTxRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.submit_transaction(payload.from, payload.to, payload.amount, payload.token, payload.signature).await {
        Ok(tx_hash) => Ok(Json(ApiResponse {
            success: true,
            data: Some(format!("Transaction submitted. Hash: {}", tx_hash)),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn stake_handler(
    State(state): State<AppState>,
    Json(payload): Json<StakeRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.stake_tokens(payload.staker, payload.amount, payload.signature).await {
        Ok(msg) => Ok(Json(ApiResponse {
            success: true,
            data: Some(msg),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn unstake_handler(
    State(state): State<AppState>,
    Json(payload): Json<UnstakeRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.unstake_tokens(payload.staker, payload.amount, payload.signature).await {
        Ok(msg) => Ok(Json(ApiResponse {
            success: true,
            data: Some(msg),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn register_validator_handler(
    State(state): State<AppState>,
    Json(payload): Json<ValidatorRegRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut public_node = state.lock().await;
    
    // Parse hex-encoded validator key
    let validator_key_bytes = match hex::decode(&payload.validator_key) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid hex-encoded validator key".to_string()),
        })),
    };

    if validator_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid validator key length".to_string()),
        }));
    }

    let mut key_array = [0u8; PUBLIC_KEY_LENGTH];
    key_array.copy_from_slice(&validator_key_bytes);
    
    let validator_key = ValidatorPublicKey::from_bytes(key_array);
    
    match public_node.register_validator(validator_key, payload.stake).await {
        Ok(msg) => Ok(Json(ApiResponse {
            success: true,
            data: Some(msg),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn validators_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ValidatorsResponse>>, StatusCode> {
    let public_node = state.lock().await;
    let validators = public_node.get_validators();
    
    Ok(Json(ApiResponse {
        success: true,
        data: Some(ValidatorsResponse { validators }),
        error: None,
    }))
}

async fn balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let public_node = state.lock().await;
    let balances = public_node.get_all_balances(&address);
    let su = balances.get(&TokenType::SU).cloned().unwrap_or(0);
    let gu = balances.get(&TokenType::GU).cloned().unwrap_or(0);
    Ok(Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "SU": su,
            "GU": gu
        })),
        error: None,
    }))
}

async fn status_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let public_node = state.lock().await;
    let status = public_node.get_status();
    
    Ok(Json(ApiResponse {
        success: true,
        data: Some(status),
        error: None,
    }))
}

async fn block_handler(
    State(state): State<AppState>,
    Path(index): Path<u64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let public_node = state.lock().await;
    match public_node.get_block(index) {
        Some(block) => Ok(Json(ApiResponse {
            success: true,
            data: Some(block),
            error: None,
        })),
        None => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Block not found".to_string()),
        })),
    }
}

async fn events_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<EventsResponse>>, StatusCode> {
    let public_node = state.lock().await;
    let events = public_node.get_recent_events();
    
    Ok(Json(ApiResponse {
        success: true,
        data: Some(EventsResponse { events }),
        error: None,
    }))
}

async fn produce_block_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.produce_block().await {
        Ok(block) => Ok(Json(ApiResponse {
            success: true,
            data: Some(format!("Block produced: #{} hash: {}", block.index, block.hash)),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

// Add a transfer handler for /api/transfer
#[derive(Deserialize)]
struct TransferRequest {
    from: String,
    to: String,
    amount: u64,
    signature: String,
    token: TokenType, // New field for token type
}

async fn transfer_handler(
    State(state): State<AppState>,
    Json(payload): Json<TransferRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.submit_transaction(payload.from, payload.to, payload.amount, payload.token, payload.signature).await {
        Ok(tx_hash) => Ok(Json(ApiResponse {
            success: true,
            data: Some(format!("Transfer submitted. Hash: {}", tx_hash)),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

// Admin operations request structures
#[derive(Deserialize)]
struct AdminMintRequest {
    to: String,
    amount: u64,
    admin_block_hash: String,
}

#[derive(Deserialize)]
struct AdminBurnRequest {
    from: String,
    amount: u64,
    admin_block_hash: String,
}

#[derive(Deserialize)]
struct AdminProofOfReserveRequest {
    details: String,
    admin_block_hash: String,
}

async fn admin_mint_handler(
    State(state): State<AppState>,
    Json(payload): Json<AdminMintRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.admin_mint(payload.to, payload.amount, payload.admin_block_hash).await {
        Ok(block) => Ok(Json(ApiResponse {
            success: true,
            data: Some(serde_json::to_value(block).unwrap()),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn admin_burn_handler(
    State(state): State<AppState>,
    Json(payload): Json<AdminBurnRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.admin_burn(payload.from, payload.amount, payload.admin_block_hash).await {
        Ok(block) => Ok(Json(ApiResponse {
            success: true,
            data: Some(serde_json::to_value(block).unwrap()),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn admin_proof_of_reserve_handler(
    State(state): State<AppState>,
    Json(payload): Json<AdminProofOfReserveRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.admin_proof_of_reserve(payload.details, payload.admin_block_hash).await {
        Ok(block) => Ok(Json(ApiResponse {
            success: true,
            data: Some(serde_json::to_value(block).unwrap()),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

async fn sync_admin_handler(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut public_node = state.lock().await;
    match public_node.sync_with_admin_node(None).await {
        Ok(_) => Ok(Json(ApiResponse {
            success: true,
            data: Some("Admin sync requested".to_string()),
            error: None,
        })),
        Err(e) => Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })),
    }
}

// Smart contract execution request/response structures
#[derive(Deserialize)]
struct ContractExecuteRequest {
    contract_id: String,
    method: String,
    parameters: serde_json::Value,
    caller_did: String,
    gas_limit: Option<u64>,
    signature: String,
}

#[derive(Serialize)]
struct ContractExecuteResponse {
    success: bool,
    result: Option<serde_json::Value>,
    error: Option<String>,
    gas_used: u64,
    execution_time_ms: u64,
}

// =================== SMART CONTRACT HANDLERS ===================

async fn execute_contract_handler(
    State(state): State<AppState>,
    Json(req): Json<ContractExecuteRequest>,
) -> Result<Json<ContractExecuteResponse>, StatusCode> {
    use crate::smart_contract_executor::ContractExecutionRequest;
    
    let execution_request = ContractExecutionRequest {
        contract_id: req.contract_id,
        method: req.method,
        parameters: req.parameters,
        caller_did: req.caller_did,
        gas_limit: req.gas_limit,
        signature: req.signature,
    };
    
    let node = state.lock().await;
    
    match node.execute_smart_contract(execution_request).await {
        Ok(result) => {
            let response = ContractExecuteResponse {
                success: result.success,
                result: result.result,
                error: result.error,
                gas_used: result.gas_used,
                execution_time_ms: result.execution_time_ms,
            };
            Ok(Json(response))
        }
        Err(e) => {
            let error_response = ContractExecuteResponse {
                success: false,
                result: None,
                error: Some(e),
                gas_used: 0,
                execution_time_ms: 0,
            };
            Ok(Json(error_response))
        }
    }
}

async fn available_contracts_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let node = state.lock().await;
    let contracts = node.get_available_contracts();
    
    let response = serde_json::json!({
        "available_contracts": contracts,
        "count": contracts.len()
    });
    
    Ok(Json(response))
}

async fn contract_metadata_handler(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let node = state.lock().await;
    
    match node.get_contract_metadata(&contract_id) {
        Some(metadata) => Ok(Json(metadata)),
        None => {
            let error_response = serde_json::json!({
                "error": "Contract not found",
                "contract_id": contract_id
            });
            Ok(Json(error_response))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Booting E3-Core Public Node...");

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

    let public_node = PublicNode::new(db_path.to_string(), port).await?;
    
    // Start the P2P node and get the Arc<Mutex<PublicNode>>
    let app_state: AppState = public_node.start().await?;

    // Build HTTP API routes
    let app = Router::new()
        .route("/api/submit-tx", post(submit_tx_handler))
        .route("/api/submit-transaction", post(transfer_handler)) // Add the route you were trying to use
        .route("/api/transfer", post(transfer_handler))
        .route("/api/stake", post(stake_handler))
        .route("/api/unstake", post(unstake_handler))
        .route("/api/register-validator", post(register_validator_handler))
        .route("/api/validators", get(validators_handler))
        .route("/api/balance/:address", get(balance_handler))
        .route("/api/status", get(status_handler))
        .route("/api/block/:index", get(block_handler))
        .route("/api/events", get(events_handler))
        .route("/api/produce-block", post(produce_block_handler))
        .route("/api/admin-mint", post(admin_mint_handler))
        .route("/api/admin-burn", post(admin_burn_handler))
        .route("/api/admin-proof-of-reserve", post(admin_proof_of_reserve_handler))
        .route("/api/sync-admin", post(sync_admin_handler))
        // Smart contract endpoints
        .route("/api/contracts/execute", post(execute_contract_handler))
        .route("/api/contracts/available", get(available_contracts_handler))
        .route("/api/contracts/:id/metadata", get(contract_metadata_handler))
        .with_state(app_state.clone());

    // Calculate HTTP server port (node port + 1000)
    let http_port = port + 1000;
    let addr = format!("0.0.0.0:{}", http_port);
    let socket_addr: std::net::SocketAddr = addr.parse().map_err(|_| {
        format!("Invalid socket address: {}", addr)
    })?;
    
    println!("Public Node started on port {}", port);
    println!("HTTP API server starting on {}", addr);
    println!("Node ID: {}", hex::encode(app_state.lock().await.signing_key.public.to_bytes()));

    // Start HTTP server in background
    tokio::spawn(async move {
        println!("HTTP API listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(&socket_addr).await.unwrap();
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });

    // Auto block producer loop: produce a block if there are pending transactions
    let auto_block_state = app_state.clone();
    tokio::spawn(async move {
        loop {
            // Wait for a short interval (e.g., 5 seconds)
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let mut node = auto_block_state.lock().await;
            // Check if there are pending transactions in the transaction pool
            if !node.transaction_pool.is_empty() {
                match node.produce_block().await {
                    Ok(block) => println!(
                        "[Auto Producer] Block produced: #{} hash: {} ({} txs)",
                        block.index, block.hash, block.txs.len()
                    ),
                    Err(e) => println!("[Auto Producer] Block production failed: {}", e),
                }
            }
        }
    });

    // Demo actions
    // Print startup information
    println!("Public node successfully started!");
    println!("Available HTTP API endpoints:");
    println!("  POST /api/submit-transaction - Submit a transaction");
    println!("  POST /api/stake - Stake tokens to a validator");
    println!("  POST /api/unstake - Unstake tokens from a validator");
    println!("  POST /api/register-validator - Register as a validator");
    println!("  GET /api/validators - List all validators");
    println!("  GET /api/balance/:address - Get balance for an address");
    println!("  GET /api/block/:height - Get block by height");
    println!("  GET /api/events - Get recent events");
    println!("  GET /api/status - Get node status");
    println!("  POST /api/admin-mint - Admin mint operation");
    println!("  POST /api/admin-burn - Admin burn operation");
    println!("  POST /api/admin-proof-of-reserve - Admin proof of reserve");
    println!("  POST /api/sync-admin - Sync with admin node");

    // Use app_state for both HTTP and P2P
    let public_node_clone = app_state.clone();

    // Set up admin block listener for comprehensive admin event processing
    PublicNode::spawn_admin_block_listener(public_node_clone.clone());

    // Start Kafka consumer for admin events
    let kafka_consumer_state = app_state.clone();
    tokio::spawn(async move {
        match KafkaConsumer::new("localhost:9092", "public-node-group", "admin-events") {
            Ok(consumer) => {
                println!("Kafka consumer started for admin events");
                consumer.consume_admin_events(kafka_consumer_state).await;
            }
            Err(e) => {
                eprintln!("Failed to start Kafka consumer: {:?}", e);
                eprintln!("Falling back to HTTP-based admin sync");
            }
        }
    });

    // Keep the main thread alive
    tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;

    Ok(())
}