//! HTTP API Server for DAO Node
//!
//! Provides REST endpoints for governance operations

use std::sync::Arc;
use tokio::sync::RwLock;
use axum::{
    routing::{get, post},
    Router, Json, extract::{Path, Query, State},
    response::Json as ResponseJson,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_http::cors::CorsLayer;

use crate::governance::{
    dao_node::DaoNode,
    proposal::ProposalCategory,
    treasury::DisbursementCategory,
    reporting::{ReportType, ReportPeriod},
};

// API State
#[derive(Clone)]
pub struct ApiState {
    pub dao_node: Arc<RwLock<DaoNode>>,
}

// Request/Response structures
#[derive(Debug, Deserialize)]
pub struct SubmitProposalRequest {
    pub title: String,
    pub description: String,
    pub category: ProposalCategory,
    pub submitter_did: String,
    pub voting_duration_hours: u64,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitProposalResponse {
    pub proposal_id: String,
    pub status: String,
    pub voting_starts_at: Option<u64>,
    pub voting_ends_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct CastVoteRequest {
    pub proposal_id: String,
    pub did_id: String,
    pub choice: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct CastVoteResponse {
    pub vote_id: String,
    pub proposal_id: String,
    pub status: String,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize)]
pub struct RegisterDidRequest {
    pub method: String,
    pub network: String,
    pub public_key: String,
    pub wallet_address: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterDidResponse {
    pub did_id: String,
    pub status: String,
    pub eligible_to_vote: bool,
}

#[derive(Debug, Deserialize)]
pub struct DisbursementRequest {
    pub proposal_id: String,
    pub recipient: String,
    pub amount: f64,
    pub category: DisbursementCategory,
    pub description: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct DisbursementResponse {
    pub request_id: String,
    pub status: String,
    pub amount: f64,
}

#[derive(Debug, Deserialize)]
pub struct ProposalQuery {
    pub status: Option<String>,
    pub category: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    pub period: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: ErrorDetails,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetails {
    pub code: String,
    pub message: String,
    pub details: Option<String>,
}

// Smart contract request/response structures
#[derive(Debug, Deserialize)]
pub struct SubmitContractRequest {
    pub name: String,
    pub description: String,
    pub version: String,
    pub bytecode: String,                     // Base64 encoded bytecode
    pub allowed_methods: Vec<String>,
    pub permission_level: String,             // "Public", "Restricted", "Admin", "Governance"
    pub developer_did: String,
    pub gas_limit: u64,
    pub metadata: std::collections::HashMap<String, String>,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitContractResponse {
    pub contract_id: String,
    pub status: String,
    pub submission_timestamp: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateContractProposalRequest {
    pub contract_id: String,
    pub submitter_did: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct CreateContractProposalResponse {
    pub proposal_id: String,
    pub contract_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct DeployContractRequest {
    pub contract_id: String,
    pub deployer_did: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct DeployContractResponse {
    pub contract_id: String,
    pub status: String,
    pub deployment_timestamp: String,
}

#[derive(Debug, Deserialize)]
pub struct ContractQuery {
    pub status: Option<String>,
    pub developer_did: Option<String>,
    pub permission_level: Option<String>,
}

// API endpoint handlers
pub async fn submit_proposal(
    State(state): State<ApiState>,
    Json(request): Json<SubmitProposalRequest>,
) -> Result<ResponseJson<SubmitProposalResponse>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    // Convert signature from hex string to bytes
    let signature = hex::decode(&request.signature.trim_start_matches("0x"))
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "INVALID_SIGNATURE", "Invalid signature format"))?;
    
    match dao_node.submit_proposal(
        request.title,
        request.description,
        request.category,
        request.submitter_did,
        request.voting_duration_hours,
    ).await {
        Ok(proposal_id) => {
            // Get proposal details for response
            let proposal_manager = dao_node.proposal_manager.read().await;
            let proposal = proposal_manager.get_proposal(&proposal_id);
            
            let response = SubmitProposalResponse {
                proposal_id,
                status: "submitted".to_string(),
                voting_starts_at: proposal.and_then(|p| p.voting_starts_at),
                voting_ends_at: proposal.and_then(|p| p.voting_ends_at),
            };
            
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "PROPOSAL_SUBMISSION_FAILED", &e)),
    }
}

pub async fn get_proposal(
    State(state): State<ApiState>,
    Path(proposal_id): Path<String>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    let proposal_manager = dao_node.proposal_manager.read().await;
    
    match proposal_manager.get_proposal(&proposal_id) {
        Some(proposal) => {
            let proposal_json = serde_json::to_value(proposal)
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZATION_ERROR", "Failed to serialize proposal"))?;
            Ok(ResponseJson(proposal_json))
        }
        None => Err(api_error(StatusCode::NOT_FOUND, "PROPOSAL_NOT_FOUND", "Proposal not found")),
    }
}

pub async fn list_proposals(
    State(state): State<ApiState>,
    Query(query): Query<ProposalQuery>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    let proposal_manager = dao_node.proposal_manager.read().await;
    
    let proposals = proposal_manager.get_all_proposals();
    let limit = query.limit.unwrap_or(20);
    let offset = query.offset.unwrap_or(0);
    
    // Apply filters and pagination
    let mut filtered_proposals = proposals;
    
    if let Some(status) = &query.status {
        filtered_proposals.retain(|p| format!("{:?}", p.state).to_lowercase() == status.to_lowercase());
    }
    
    if let Some(category) = &query.category {
        filtered_proposals.retain(|p| format!("{:?}", p.category).to_lowercase() == category.to_lowercase());
    }
    
    let total = filtered_proposals.len();
    let paginated: Vec<_> = filtered_proposals.into_iter().skip(offset).take(limit).collect();
    
    let response = serde_json::json!({
        "proposals": paginated,
        "total": total,
        "limit": limit,
        "offset": offset
    });
    
    Ok(ResponseJson(response))
}

pub async fn open_voting(
    State(state): State<ApiState>,
    Path(proposal_id): Path<String>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    match dao_node.open_voting(proposal_id.clone()).await {
        Ok(_) => {
            let response = serde_json::json!({
                "proposal_id": proposal_id,
                "status": "voting_opened",
                "voting_starts_at": chrono::Utc::now().timestamp()
            });
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "VOTING_OPEN_FAILED", &e)),
    }
}

pub async fn finalize_proposal(
    State(state): State<ApiState>,
    Path(proposal_id): Path<String>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    match dao_node.finalize_proposal(proposal_id.clone()).await {
        Ok(consensus_result) => {
            // Get final tally
            let voting_results = dao_node.get_voting_results(proposal_id.clone()).await
                .unwrap_or_else(|_| serde_json::json!({}));
            
            let response = serde_json::json!({
                "proposal_id": proposal_id,
                "final_state": format!("{:?}", consensus_result),
                "consensus_result": format!("{:?}", consensus_result),
                "final_tally": voting_results
            });
            
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "FINALIZATION_FAILED", &e)),
    }
}

pub async fn cast_vote(
    State(state): State<ApiState>,
    Json(request): Json<CastVoteRequest>,
) -> Result<ResponseJson<CastVoteResponse>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    // Convert signature from hex string to bytes
    let signature = hex::decode(&request.signature.trim_start_matches("0x"))
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "INVALID_SIGNATURE", "Invalid signature format"))?;
    
    match dao_node.cast_vote(
        request.proposal_id.clone(),
        request.did_id,
        request.choice,
        signature,
    ).await {
        Ok(vote_id) => {
            let response = CastVoteResponse {
                vote_id,
                proposal_id: request.proposal_id,
                status: "recorded".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
            };
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "VOTE_CAST_FAILED", &e)),
    }
}

pub async fn get_voting_results(
    State(state): State<ApiState>,
    Path(proposal_id): Path<String>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    match dao_node.get_voting_results(proposal_id).await {
        Ok(results) => Ok(ResponseJson(results)),
        Err(e) => Err(api_error(StatusCode::NOT_FOUND, "RESULTS_NOT_FOUND", &e)),
    }
}

pub async fn generate_voting_proof(
    State(state): State<ApiState>,
    Path(proposal_id): Path<String>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    match dao_node.generate_voting_proof(proposal_id).await {
        Ok(proof) => Ok(ResponseJson(proof)),
        Err(e) => Err(api_error(StatusCode::NOT_FOUND, "PROOF_GENERATION_FAILED", &e)),
    }
}

pub async fn register_did(
    State(state): State<ApiState>,
    Json(request): Json<RegisterDidRequest>,
) -> Result<ResponseJson<RegisterDidResponse>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    // In a real implementation, we'd parse the public key and validate signature
    // For now, we'll create a placeholder DID
    use crate::governance::did::{Did, DidRegistry};
    
    let did_id = format!("did:{}:{}:{}", request.method, request.network, &request.public_key[..16]);
    
    let mut did_registry = dao_node.did_registry.write().await;
    // Note: This is simplified - in production, you'd properly parse and validate
    
    let response = RegisterDidResponse {
        did_id,
        status: "registered".to_string(),
        eligible_to_vote: true,
    };
    
    Ok(ResponseJson(response))
}

pub async fn get_did_info(
    State(state): State<ApiState>,
    Path(did_id): Path<String>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    let did_registry = dao_node.did_registry.read().await;
    
    match did_registry.get_did(&did_id) {
        Some(did) => {
            let did_json = serde_json::to_value(did)
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZATION_ERROR", "Failed to serialize DID"))?;
            Ok(ResponseJson(did_json))
        }
        None => Err(api_error(StatusCode::NOT_FOUND, "DID_NOT_FOUND", "DID not found")),
    }
}

pub async fn request_disbursement(
    State(state): State<ApiState>,
    Json(request): Json<DisbursementRequest>,
) -> Result<ResponseJson<DisbursementResponse>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    match dao_node.request_disbursement(
        request.proposal_id,
        request.recipient,
        request.amount,
        request.category,
        request.description,
    ).await {
        Ok(request_id) => {
            let response = DisbursementResponse {
                request_id,
                status: "pending".to_string(),
                amount: request.amount,
            };
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "DISBURSEMENT_REQUEST_FAILED", &e)),
    }
}

pub async fn get_treasury_status(
    State(state): State<ApiState>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    let treasury_manager = dao_node.treasury_manager.read().await;
    
    let stats = treasury_manager.get_treasury_stats();
    
    let mut accounts = serde_json::Map::new();
    for account_id in &["treasury_main", "treasury_reserve", "treasury_operations", "treasury_development", "treasury_community"] {
        if let Some(account) = treasury_manager.get_account(account_id) {
            accounts.insert(account_id.to_string(), serde_json::json!(account.balance));
        }
    }
    
    let response = serde_json::json!({
        "total_balance": stats.total_balance,
        "total_reserved": stats.total_reserved,
        "total_available": stats.total_available,
        "accounts": accounts
    });
    
    Ok(ResponseJson(response))
}

pub async fn generate_report(
    State(state): State<ApiState>,
    Path(report_type_str): Path<String>,
    Query(query): Query<ReportQuery>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    let report_type = match report_type_str.as_str() {
        "governance_activity" => ReportType::GovernanceActivity,
        "treasury_status" => ReportType::TreasuryStatus,
        "participation_metrics" => ReportType::ParticipationMetrics,
        "did_metrics" => ReportType::DIDMetrics,
        "financial_summary" => ReportType::FinancialSummary,
        _ => return Err(api_error(StatusCode::BAD_REQUEST, "INVALID_REPORT_TYPE", "Invalid report type")),
    };
    
    let period = match query.period.as_deref() {
        Some("daily") => ReportPeriod::Daily,
        Some("weekly") => ReportPeriod::Weekly,
        Some("monthly") => ReportPeriod::Monthly,
        Some("quarterly") => ReportPeriod::Quarterly,
        Some("yearly") => ReportPeriod::Yearly,
        _ => ReportPeriod::Monthly,
    };
    
    match dao_node.generate_report(report_type, period).await {
        Ok(report) => Ok(ResponseJson(report)),
        Err(e) => Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "REPORT_GENERATION_FAILED", &e)),
    }
}

pub async fn get_node_status(
    State(state): State<ApiState>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    let status = dao_node.get_status().await;
    Ok(ResponseJson(status))
}

// =================== SMART CONTRACT ENDPOINTS ===================

pub async fn submit_contract(
    State(state): State<ApiState>,
    Json(req): Json<SubmitContractRequest>,
) -> Result<ResponseJson<SubmitContractResponse>, (StatusCode, Json<ApiError>)> {
    use crate::smart_contract::{ContractSubmissionRequest, PermissionLevel};
    
    // Parse permission level
    let permission_level = match req.permission_level.to_lowercase().as_str() {
        "public" => PermissionLevel::Public,
        "restricted" => PermissionLevel::Restricted,
        "admin" => PermissionLevel::Admin,
        "governance" => PermissionLevel::Governance,
        _ => return Err(api_error(StatusCode::BAD_REQUEST, "INVALID_PERMISSION_LEVEL", "Invalid permission level")),
    };
    
    // Create contract submission request
    let submission_request = ContractSubmissionRequest {
        name: req.name,
        description: req.description,
        version: req.version,
        bytecode: req.bytecode,
        allowed_methods: req.allowed_methods,
        permission_level,
        developer_did: req.developer_did,
        gas_limit: req.gas_limit,
        metadata: req.metadata,
        signature: req.signature,
    };
    
    let dao_node = state.dao_node.read().await;
    
    match dao_node.submit_smart_contract(submission_request).await {
        Ok(contract_id) => {
            let response = SubmitContractResponse {
                contract_id,
                status: "submitted".to_string(),
                submission_timestamp: chrono::Utc::now().to_rfc3339(),
            };
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "CONTRACT_SUBMISSION_FAILED", &e)),
    }
}

pub async fn get_contract(
    State(state): State<ApiState>,
    Path(contract_id): Path<String>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    match dao_node.get_smart_contract(&contract_id).await {
        Some(contract) => {
            let contract_json = serde_json::to_value(contract)
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZATION_ERROR", "Failed to serialize contract"))?;
            Ok(ResponseJson(contract_json))
        }
        None => Err(api_error(StatusCode::NOT_FOUND, "CONTRACT_NOT_FOUND", "Contract not found")),
    }
}

pub async fn list_contracts(
    State(state): State<ApiState>,
    Query(query): Query<ContractQuery>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    use crate::smart_contract::ContractStatus;
    
    let dao_node = state.dao_node.read().await;
    
    let contracts = if let Some(status_str) = &query.status {
        let status = match status_str.to_lowercase().as_str() {
            "submitted" => ContractStatus::Submitted,
            "underreview" | "under_review" => ContractStatus::UnderReview,
            "approved" => ContractStatus::Approved,
            "deployed" => ContractStatus::Deployed,
            "rejected" => ContractStatus::Rejected,
            "deprecated" => ContractStatus::Deprecated,
            "disabled" => ContractStatus::Disabled,
            _ => return Err(api_error(StatusCode::BAD_REQUEST, "INVALID_STATUS", "Invalid contract status")),
        };
        dao_node.get_smart_contracts_by_status(status).await
    } else if let Some(developer_did) = &query.developer_did {
        dao_node.get_contracts_by_developer(developer_did).await
    } else {
        // Get all contracts by getting each status
        let mut all_contracts = Vec::new();
        for status in [
            ContractStatus::Submitted,
            ContractStatus::UnderReview,
            ContractStatus::Approved,
            ContractStatus::Deployed,
            ContractStatus::Rejected,
            ContractStatus::Deprecated,
            ContractStatus::Disabled,
        ] {
            let mut status_contracts = dao_node.get_smart_contracts_by_status(status).await;
            all_contracts.append(&mut status_contracts);
        }
        all_contracts
    };
    
    let contracts_json = serde_json::to_value(contracts)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZATION_ERROR", "Failed to serialize contracts"))?;
    
    Ok(ResponseJson(contracts_json))
}

pub async fn create_contract_proposal(
    State(state): State<ApiState>,
    Path(contract_id): Path<String>,
    Json(req): Json<CreateContractProposalRequest>,
) -> Result<ResponseJson<CreateContractProposalResponse>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    match dao_node.create_contract_approval_proposal(contract_id.clone(), req.submitter_did).await {
        Ok(proposal_id) => {
            let response = CreateContractProposalResponse {
                proposal_id,
                contract_id,
                status: "proposal_created".to_string(),
            };
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "PROPOSAL_CREATION_FAILED", &e)),
    }
}

pub async fn deploy_contract(
    State(state): State<ApiState>,
    Path(contract_id): Path<String>,
    Json(req): Json<DeployContractRequest>,
) -> Result<ResponseJson<DeployContractResponse>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    // TODO: Verify deployer has permission (governance role, etc.)
    
    match dao_node.deploy_smart_contract(contract_id.clone()).await {
        Ok(()) => {
            let response = DeployContractResponse {
                contract_id,
                status: "deployed".to_string(),
                deployment_timestamp: chrono::Utc::now().to_rfc3339(),
            };
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "DEPLOYMENT_FAILED", &e)),
    }
}

pub async fn disable_contract(
    State(state): State<ApiState>,
    Path(contract_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    let reason = req.get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or("No reason provided")
        .to_string();
    
    match dao_node.disable_smart_contract(contract_id.clone(), reason).await {
        Ok(()) => {
            let response = serde_json::json!({
                "contract_id": contract_id,
                "status": "disabled",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            Ok(ResponseJson(response))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, "DISABLE_FAILED", &e)),
    }
}

pub async fn get_deployed_contracts(
    State(state): State<ApiState>,
) -> Result<ResponseJson<Value>, (StatusCode, Json<ApiError>)> {
    let dao_node = state.dao_node.read().await;
    
    let deployed_contracts = dao_node.get_deployed_smart_contracts().await;
    
    let contracts_json = serde_json::to_value(deployed_contracts)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZATION_ERROR", "Failed to serialize deployed contracts"))?;
    
    Ok(ResponseJson(contracts_json))
}

// Helper function to create API errors
fn api_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    let error = ApiError {
        error: ErrorDetails {
            code: code.to_string(),
            message: message.to_string(),
            details: None,
        },
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    (status, Json(error))
}

// Create the router
pub fn create_router(dao_node: Arc<RwLock<DaoNode>>) -> Router {
    let state = ApiState { dao_node };
    
    Router::new()
        // Proposal endpoints
        .route("/api/v1/proposals", post(submit_proposal))
        .route("/api/v1/proposals", get(list_proposals))
        .route("/api/v1/proposals/:id", get(get_proposal))
        .route("/api/v1/proposals/:id/open-voting", post(open_voting))
        .route("/api/v1/proposals/:id/finalize", post(finalize_proposal))
        .route("/api/v1/proposals/:id/results", get(get_voting_results))
        .route("/api/v1/proposals/:id/proof", get(generate_voting_proof))
        
        // Voting endpoints
        .route("/api/v1/votes", post(cast_vote))
        
        // DID endpoints
        .route("/api/v1/dids", post(register_did))
        .route("/api/v1/dids/:id", get(get_did_info))
        
        // Smart contract endpoints
        .route("/api/v1/contracts", post(submit_contract))
        .route("/api/v1/contracts", get(list_contracts))
        .route("/api/v1/contracts/:id", get(get_contract))
        .route("/api/v1/contracts/:id/proposal", post(create_contract_proposal))
        .route("/api/v1/contracts/:id/deploy", post(deploy_contract))
        .route("/api/v1/contracts/:id/disable", post(disable_contract))
        .route("/api/v1/contracts/deployed", get(get_deployed_contracts))
        
        // Treasury endpoints
        .route("/api/v1/treasury/disbursements", post(request_disbursement))
        .route("/api/v1/treasury/status", get(get_treasury_status))
        
        // Reporting endpoints
        .route("/api/v1/reports/:type", get(generate_report))
        
        // Status endpoint
        .route("/api/v1/status", get(get_node_status))
        
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// Start the HTTP server
pub async fn start_api_server(dao_node: Arc<RwLock<DaoNode>>, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let app = create_router(dao_node);
    
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("🌐 DAO Node HTTP API listening on port {}", port);
    
    axum::serve(listener, app).await?;
    Ok(())
}
