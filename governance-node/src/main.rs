#[derive(Deserialize)]
struct ProposalInput {
    title: String,
    description: String,
    category: String,
    submitter_did: String,
    voting_duration_hours: u64,
    signature: String,
}

#[derive(Deserialize)]
struct VoteInput {
    did: String,
    proposal_id: String,
    vote_choice: String,
    timestamp: u64,
    nonce: String,
    signature: String,
}
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::Filter;
use serde::Deserialize;

mod dao_node;
mod proposal;
mod did;
mod vote;
mod treasury;
mod reporting;
mod smart_contract;
mod kafka_emitter;

use dao_node::DaoNode;
use proposal::ProposalCategory;
use treasury::DisbursementCategory;
use reporting::{ReportType, ReportPeriod};

#[derive(Deserialize)]
struct DidInput {
    method: String,
    network: String,
    public_key: String,
    wallet_address: String,
    signature: String,
}

#[tokio::main]
async fn main() {
    // Initialize DAO node before setting up filters
    let dao_node = Arc::new(RwLock::new(DaoNode::new(
        "governance-node".to_string(),
        Default::default(),
    )));
    {
        let mut node = dao_node.write().await;
        node.start().await.expect("Failed to start DAO node");
    }
    let dao_node_filter = warp::any().map(move || dao_node.clone());

    // Submit proposal endpoint
    let submit_proposal = warp::path!("api" / "v1" / "proposals")
        .and(warp::post())
        .and(warp::body::json())
        .and(dao_node_filter.clone())
        .and_then(|input: ProposalInput, dao_node: Arc<RwLock<DaoNode>>| async move {
            println!("[DEBUG] Received proposal submission: title='{}', category='{}', submitter_did='{}'", input.title, input.category, input.submitter_did);
            let category = ProposalCategory::from_string(&input.category)
                .map_err(|_| warp::reject::not_found())?;
            let result = dao_node.read().await.submit_proposal(
                input.title,
                input.description,
                category,
                input.submitter_did,
                input.voting_duration_hours,
            ).await;
            println!("[DEBUG] Proposal submission result: {:?}", result);
            match result {
                Ok(proposal_id) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({
                    "proposal_id": proposal_id,
                    "status": "submitted"
                }))),
                Err(e) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({
                    "status": "error",
                    "error": e
                }))),
            }
        });

    // Cast vote endpoint
    let cast_vote = warp::path!("api" / "v1" / "votes")
        .and(warp::post())
        .and(warp::body::json())
        .and(dao_node_filter.clone())
        .and_then(|input: VoteInput, dao_node: Arc<RwLock<DaoNode>>| async move {
            let result = dao_node.write().await.cast_vote_with_signature(
                input.proposal_id,
                input.did,
                input.vote_choice,
                input.timestamp,
                input.nonce,
                input.signature,
            ).await;
            match result {
                Ok(vote_id) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({
                    "vote_id": vote_id,
                    "status": "cast"
                }))),
                Err(e) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({
                    "status": "error",
                    "error": e
                }))),
            }
        });

    // Get active proposals endpoint
    let get_active_proposals = warp::path!("api" / "v1" / "proposals" / "active")
        .and(warp::get())
        .and(dao_node_filter.clone())
        .and_then(|dao_node: Arc<RwLock<DaoNode>>| async move {
            let proposals = dao_node.read().await.get_active_proposals().await;
            Result::<_, warp::Rejection>::Ok(warp::reply::json(&proposals))
        });

    // Get proposal results endpoint
    let proposal_results = warp::path!("api" / "v1" / "proposals" / String / "results")
        .and(warp::get())
        .and(dao_node_filter.clone())
        .and_then(|proposal_id: String, dao_node: Arc<RwLock<DaoNode>>| async move {
            let result = dao_node.read().await.get_voting_results(proposal_id).await;
            match result {
                Ok(results) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&results)),
                Err(e) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({
                    "status": "error",
                    "error": e
                }))),
            }
        });

    // Open voting endpoint
    let open_voting = warp::path!("api" / "v1" / "proposals" / String / "open-voting")
        .and(warp::post())
        .and(dao_node_filter.clone())
        .and_then(|proposal_id: String, dao_node: Arc<RwLock<DaoNode>>| async move {
            let result = dao_node.read().await.open_voting(proposal_id).await;
            match result {
                Ok(_) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({"status": "voting_opened"}))),
                Err(e) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({"status": "error", "error": e}))),
            }
        });

    // Finalize proposal endpoint
    let finalize_proposal = warp::path!("api" / "v1" / "proposals" / String / "finalize")
        .and(warp::post())
        .and(dao_node_filter.clone())
        .and_then(|proposal_id: String, dao_node: Arc<RwLock<DaoNode>>| async move {
            let result = dao_node.read().await.finalize_proposal(proposal_id).await;
            match result {
                Ok(consensus) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({"result": format!("{:?}", consensus)}))),
                Err(e) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({"status": "error", "error": e}))),
            }
        });

    // Node status endpoint
    let node_status = warp::path!("api" / "v1" / "status")
        .and(warp::get())
        .and(dao_node_filter.clone())
        .and_then(|dao_node: Arc<RwLock<DaoNode>>| async move {
            let status = dao_node.read().await.get_status().await;
            Ok::<_, warp::Rejection>(warp::reply::json(&status))
        });

    // Register DID endpoint
    let register_did = warp::path!("api" / "v1" / "dids")
        .and(warp::post())
        .and(warp::body::json())
        .and(dao_node_filter.clone())
        .and_then(|input: DidInput, dao_node: Arc<RwLock<DaoNode>>| async move {
            let result = dao_node
                .read()
                .await
                .register_did(
                    input.method,
                    input.network,
                    input.public_key,
                    input.wallet_address,
                    input.signature,
                )
                .await;
            match result {
                Ok(did_id) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({
                    "status": "registered",
                    "did_id": did_id
                }))),
                Err(e) => Result::<_, warp::Rejection>::Ok(warp::reply::json(&serde_json::json!({
                    "status": "error",
                    "error": e
                }))),
            }
        });

    // Treasury status endpoint
    let treasury_status = warp::path!("api" / "v1" / "treasury" / "status")
        .and(warp::get())
        .and(dao_node_filter.clone())
        .and_then(|dao_node: Arc<RwLock<DaoNode>>| async move {
            let stats = dao_node.read().await.get_treasury_status().await;
            Ok::<_, warp::Rejection>(warp::reply::json(&stats))
        });

    let routes = register_did
        .or(treasury_status)
        .or(cast_vote)
        .or(get_active_proposals)
        .or(proposal_results)
        .or(open_voting)
        .or(finalize_proposal)
        .or(node_status);

    // Move submit_proposal to the top to ensure correct route matching
    let routes = submit_proposal.or(routes);
    println!("🌐 HTTP server listening on 0.0.0.0:5003");
    warp::serve(routes).run(([0, 0, 0, 0], 5003)).await;
}
