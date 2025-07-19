//! Proposal Management Module
//!
//! Handles proposal lifecycle: submission, validation, state transitions

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::Utc;
use crate::kafka_emitter::KafkaEmitter;

// Proposal states
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalState {
    Draft,      // Initial state, not yet open for voting
    Voting,     // Open for voting
    Passed,     // Voting concluded, proposal passed
    Rejected,   // Voting concluded, proposal rejected
    Executed,   // Proposal has been executed
    Cancelled,  // Proposal cancelled by proposer or governance
}

// Proposal categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalCategory {
    Protocol,      // Protocol parameter changes
    Treasury,      // Treasury fund disbursements
    Authority,     // Authority/admin changes
    Social,        // Social policy and programs
    Emergency,     // Emergency governance actions
    SmartContract, // Smart contract approval/deployment
}

impl ProposalCategory {
    pub fn from_string(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "protocol" => Ok(ProposalCategory::Protocol),
            "treasury" => Ok(ProposalCategory::Treasury),
            "authority" => Ok(ProposalCategory::Authority),
            "social" => Ok(ProposalCategory::Social),
            "emergency" => Ok(ProposalCategory::Emergency),
            "smartcontract" | "smart_contract" => Ok(ProposalCategory::SmartContract),
            "governance" => Ok(ProposalCategory::Protocol), // Map governance to Protocol for now
            _ => Err(format!("Invalid proposal category: {}", s)),
        }
    }
}

// Main proposal structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: ProposalCategory,
    pub proposer_did: String,
    pub state: ProposalState,
    
    // Timing
    pub created_at: u64,
    pub voting_starts_at: Option<u64>,
    pub voting_ends_at: Option<u64>,
    pub executed_at: Option<u64>,
    
    // Voting configuration
    pub quorum_required: u64,     // Minimum number of votes needed
    pub approval_threshold: u64,  // Percentage needed to pass (e.g., 51, 66)
    
    // Execution data
    pub execution_data: serde_json::Value, // Data needed for execution
    
    // Vote tracking (will be managed by VotingEngine)
    pub vote_count_yes: u64,
    pub vote_count_no: u64,
    pub vote_count_abstain: u64,
    pub total_votes: u64,
}

impl Proposal {
    pub fn new(
        id: String,
        title: String,
        description: String,
        category: ProposalCategory,
        proposer_did: String,
        execution_data: serde_json::Value,
    ) -> Self {
        let now = Utc::now().timestamp() as u64;
        
        // Default quorum and approval thresholds based on category
        let (quorum_required, approval_threshold) = match category {
            ProposalCategory::Protocol => (1000, 66),      // High threshold for protocol changes
            ProposalCategory::Treasury => (500, 51),       // Simple majority for treasury
            ProposalCategory::Authority => (750, 75),      // High threshold for authority changes
            ProposalCategory::Social => (300, 51),         // Simple majority for social programs
            ProposalCategory::Emergency => (100, 51),      // Lower quorum for emergencies
            ProposalCategory::SmartContract => (400, 60),  // Moderate threshold for smart contracts
        };
        
        Proposal {
            id,
            title,
            description,
            category,
            proposer_did,
            state: ProposalState::Draft,
            created_at: now,
            voting_starts_at: None,
            voting_ends_at: None,
            executed_at: None,
            quorum_required,
            approval_threshold,
            execution_data,
            vote_count_yes: 0,
            vote_count_no: 0,
            vote_count_abstain: 0,
            total_votes: 0,
        }
    }
    
    pub fn can_transition_to(&self, new_state: &ProposalState) -> bool {
        match (&self.state, new_state) {
            (ProposalState::Draft, ProposalState::Voting) => true,
            (ProposalState::Draft, ProposalState::Cancelled) => true,
            (ProposalState::Voting, ProposalState::Passed) => true,
            (ProposalState::Voting, ProposalState::Rejected) => true,
            (ProposalState::Voting, ProposalState::Cancelled) => true,
            (ProposalState::Passed, ProposalState::Executed) => true,
            _ => false,
        }
    }
    
    pub fn is_voting_period_active(&self) -> bool {
        if self.state != ProposalState::Voting {
            return false;
        }
        
        let now = Utc::now().timestamp() as u64;
        match (self.voting_starts_at, self.voting_ends_at) {
            (Some(start), Some(end)) => now >= start && now <= end,
            _ => false,
        }
    }
    
    pub fn has_reached_quorum(&self) -> bool {
        self.total_votes >= self.quorum_required
    }
    
    pub fn calculate_result(&self) -> ProposalState {
        if !self.has_reached_quorum() {
            return ProposalState::Rejected;
        }
        
        let approval_percentage = if self.total_votes > 0 {
            (self.vote_count_yes * 100) / self.total_votes
        } else {
            0
        };
        
        if approval_percentage >= self.approval_threshold {
            ProposalState::Passed
        } else {
            ProposalState::Rejected
        }
    }
}

// Proposal Manager - handles proposal storage and lifecycle
pub struct ProposalManager {
    proposals: HashMap<String, Proposal>,
    next_proposal_id: u64,
}

impl ProposalManager {
    /// Debug: Print all proposals and their states, voting times, and now
    pub fn debug_print_all(&self) {
        let now = chrono::Utc::now().timestamp() as u64;
        println!("\n--- Proposal Debug Dump ---");
        for (id, proposal) in &self.proposals {
            println!(
                "{}: state={:?}, voting_starts_at={:?}, voting_ends_at={:?}, now={}, is_active={}",
                id,
                proposal.state,
                proposal.voting_starts_at,
                proposal.voting_ends_at,
                now,
                proposal.is_voting_period_active()
            );
        }
        println!("--------------------------\n");
    }
    pub fn new() -> Self {
        ProposalManager {
            proposals: HashMap::new(),
            next_proposal_id: 1,
        }
    }
    
    pub fn submit_proposal(
        &mut self,
        title: String,
        description: String,
        category: ProposalCategory,
        proposer_did: String,
        execution_data: serde_json::Value,
    ) -> Result<String, String> {
        // Generate unique proposal ID
        let proposal_id = format!("PROP_{}", self.next_proposal_id);
        self.next_proposal_id += 1;
        
        // Validate proposal
        if title.trim().is_empty() {
            return Err("Proposal title cannot be empty".to_string());
        }
        
        if description.trim().is_empty() {
            return Err("Proposal description cannot be empty".to_string());
        }
        
        // TODO: Validate proposer_did exists and is authorized
        
        // Create proposal
        let proposal = Proposal::new(
            proposal_id.clone(),
            title.clone(),
            description,
            category.clone(),
            proposer_did,
            execution_data,
        );
        
        self.proposals.insert(proposal_id.clone(), proposal);
        
        println!("📝 New proposal submitted: {} - {} (Category: {:?})", proposal_id, title, category);
        Ok(proposal_id)
    }
    
    pub fn open_voting(&mut self, proposal_id: &str, voting_duration_hours: u64) -> Result<(), String> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or("Proposal not found")?;
        
        if !proposal.can_transition_to(&ProposalState::Voting) {
            return Err(format!("Cannot open voting for proposal in state: {:?}", proposal.state));
        }
        
        let now = Utc::now().timestamp() as u64;
        proposal.state = ProposalState::Voting;
        proposal.voting_starts_at = Some(now);
        proposal.voting_ends_at = Some(now + (voting_duration_hours * 3600));
        
        println!("🗳️  Voting opened for proposal: {} - {}", proposal_id, proposal.title);
        Ok(())
    }
    
    pub async fn close_voting(&mut self, proposal_id: &str, kafka: Option<&KafkaEmitter>) -> Result<ProposalState, String> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or("Proposal not found")?;
        
        if proposal.state != ProposalState::Voting {
            return Err(format!("Proposal is not in voting state: {:?}", proposal.state));
        }
        
        let result = proposal.calculate_result();
        proposal.state = result.clone();

        println!("📊 Voting closed for proposal: {} - Result: {:?}", proposal_id, result);

        // Emit ProposalPassed event if passed
        if let Some(kafka) = kafka {
            if result == ProposalState::Passed {
                let event = serde_json::json!({
                    "proposal_id": proposal.id,
                    "title": proposal.title,
                    "category": format!("{:?}", proposal.category),
                    "timestamp": Utc::now().timestamp(),
                });
                kafka.emit_event("ProposalPassed", &event).await;
            }
        }
        Ok(result)
    }
    
    pub async fn execute_proposal(&mut self, proposal_id: &str, kafka: Option<&KafkaEmitter>) -> Result<(), String> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or("Proposal not found")?;
        
        if !proposal.can_transition_to(&ProposalState::Executed) {
            return Err(format!("Cannot execute proposal in state: {:?}", proposal.state));
        }
        
        proposal.state = ProposalState::Executed;
        proposal.executed_at = Some(Utc::now().timestamp() as u64);

        println!("✅ Proposal executed: {} - {}", proposal_id, proposal.title);

        // Emit ProposalExecuted event
        if let Some(kafka) = kafka {
            let event = serde_json::json!({
                "proposal_id": proposal.id,
                "title": proposal.title,
                "category": format!("{:?}", proposal.category),
                "timestamp": Utc::now().timestamp(),
            });
            kafka.emit_event("ProposalExecuted", &event).await;
        }
        Ok(())
    }
    
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&Proposal> {
        self.proposals.get(proposal_id)
    }
    
    pub fn get_proposal_mut(&mut self, proposal_id: &str) -> Option<&mut Proposal> {
        self.proposals.get_mut(proposal_id)
    }
    
    pub fn list_proposals(&self) -> Vec<&Proposal> {
        self.proposals.values().collect()
    }
    
    pub fn list_proposals_by_state(&self, state: &ProposalState) -> Vec<&Proposal> {
        self.proposals.values()
            .filter(|p| &p.state == state)
            .collect()
    }
    
    pub fn update_vote_counts(&mut self, proposal_id: &str, yes: u64, no: u64, abstain: u64) -> Result<(), String> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or("Proposal not found")?;
        
        proposal.vote_count_yes = yes;
        proposal.vote_count_no = no;
        proposal.vote_count_abstain = abstain;
        proposal.total_votes = yes + no + abstain;
        
        Ok(())
    }

    /// Get all proposals that are currently in voting state
    pub fn get_active_proposals(&self) -> Vec<Proposal> {
        self.proposals.values()
            .filter(|p| p.state == ProposalState::Voting && p.is_voting_period_active())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proposal_creation() {
        let proposal = Proposal::new(
            "PROP_1".to_string(),
            "Test Proposal".to_string(),
            "A test proposal description".to_string(),
            ProposalCategory::Treasury,
            "did:ellipe:test123".to_string(),
            serde_json::json!({"amount": 1000, "recipient": "test_address"}),
        );
        
        assert_eq!(proposal.id, "PROP_1");
        assert_eq!(proposal.state, ProposalState::Draft);
        assert_eq!(proposal.category, ProposalCategory::Treasury);
    }
    
    #[test]
    fn test_proposal_state_transitions() {
        let proposal = Proposal::new(
            "PROP_1".to_string(),
            "Test Proposal".to_string(),
            "Description".to_string(),
            ProposalCategory::Treasury,
            "did:ellipe:test123".to_string(),
            serde_json::json!({}),
        );
        
        assert!(proposal.can_transition_to(&ProposalState::Voting));
        assert!(proposal.can_transition_to(&ProposalState::Cancelled));
        assert!(!proposal.can_transition_to(&ProposalState::Executed));
    }
    
    #[test]
    fn test_proposal_manager() {
        let mut manager = ProposalManager::new();
        
        let proposal_id = manager.submit_proposal(
            "Test Proposal".to_string(),
            "A test proposal".to_string(),
            ProposalCategory::Treasury,
            "did:ellipe:test123".to_string(),
            serde_json::json!({}),
        ).unwrap();
        
        assert_eq!(proposal_id, "PROP_1");
        assert!(manager.get_proposal(&proposal_id).is_some());
        
        manager.open_voting(&proposal_id, 24).unwrap();
        let proposal = manager.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.state, ProposalState::Voting);
    }
}
