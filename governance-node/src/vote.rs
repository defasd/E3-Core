//! Voting Engine Module
//!
//! Handles vote validation, tallying, quorum checks, and consensus determination

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::Utc;

// Individual vote structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub vote_id: String,
    pub proposal_id: String,
    pub did_id: String,
    pub choice: VoteChoice,
    pub weight: f64,                    // Vote weight (default 1.0 for standard votes)
    pub timestamp: u64,
    pub signature: Vec<u8>,             // Cryptographic signature
    pub metadata: serde_json::Value,    // Additional vote metadata
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

impl VoteChoice {
    pub fn from_string(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "yes" | "y" | "approve" | "for" => Ok(VoteChoice::Yes),
            "no" | "n" | "reject" | "against" => Ok(VoteChoice::No),
            "abstain" | "a" | "neutral" => Ok(VoteChoice::Abstain),
            _ => Err(format!("Invalid vote choice: {}", s)),
        }
    }
    
    pub fn to_string(&self) -> String {
        match self {
            VoteChoice::Yes => "yes".to_string(),
            VoteChoice::No => "no".to_string(),
            VoteChoice::Abstain => "abstain".to_string(),
        }
    }
}

// Vote tally results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTally {
    pub proposal_id: String,
    pub yes_votes: f64,
    pub no_votes: f64,
    pub abstain_votes: f64,
    pub total_votes: f64,
    pub eligible_voters: usize,
    pub participation_rate: f64,        // percentage of eligible voters who voted
    pub yes_percentage: f64,
    pub no_percentage: f64,
    pub abstain_percentage: f64,
    pub calculated_at: u64,
}

impl VoteTally {
    pub fn calculate_percentages(&mut self) {
        if self.total_votes > 0.0 {
            self.yes_percentage = (self.yes_votes / self.total_votes) * 100.0;
            self.no_percentage = (self.no_votes / self.total_votes) * 100.0;
            self.abstain_percentage = (self.abstain_votes / self.total_votes) * 100.0;
        } else {
            self.yes_percentage = 0.0;
            self.no_percentage = 0.0;
            self.abstain_percentage = 0.0;
        }
        
        if self.eligible_voters > 0 {
            self.participation_rate = (self.total_votes / self.eligible_voters as f64) * 100.0;
        } else {
            self.participation_rate = 0.0;
        }
    }
}

// Quorum configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumConfig {
    pub minimum_participation: f64,     // Minimum % of eligible voters required
    pub minimum_approval: f64,          // Minimum % yes votes required to pass
    pub require_absolute_majority: bool, // Require >50% of eligible voters to vote yes
}

impl Default for QuorumConfig {
    fn default() -> Self {
        QuorumConfig {
            minimum_participation: 10.0,  // 10% participation required
            minimum_approval: 60.0,       // 60% approval required
            require_absolute_majority: false,
        }
    }
}

// Consensus result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsensusResult {
    Passed,
    Rejected,
    Failed,     // Failed to meet quorum/participation requirements
    Pending,    // Still in voting period
}

// Main voting engine
pub struct VotingEngine {
    votes: HashMap<String, Vec<Vote>>,          // proposal_id -> Vec<Vote>
    tallies: HashMap<String, VoteTally>,        // proposal_id -> VoteTally
    quorum_configs: HashMap<String, QuorumConfig>, // proposal_id -> QuorumConfig
    vote_counter: u64,                          // For generating unique vote IDs
}

impl VotingEngine {
    pub fn new() -> Self {
        VotingEngine {
            votes: HashMap::new(),
            tallies: HashMap::new(),
            quorum_configs: HashMap::new(),
            vote_counter: 0,
        }
    }
    
    pub fn cast_vote(
        &mut self,
        proposal_id: String,
        did_id: String,
        choice: VoteChoice,
        signature: Vec<u8>,
        weight: Option<f64>,
    ) -> Result<String, String> {
        self.vote_counter += 1;
        let vote_id = format!("VOTE_{:08}", self.vote_counter);
        
        let vote = Vote {
            vote_id: vote_id.clone(),
            proposal_id: proposal_id.clone(),
            did_id,
            choice,
            weight: weight.unwrap_or(1.0),
            timestamp: Utc::now().timestamp() as u64,
            signature,
            metadata: serde_json::json!({}),
        };
        
        // Store vote
        self.votes
            .entry(proposal_id.clone())
            .or_insert_with(Vec::new)
            .push(vote);
        
        // Recalculate tally
        self.update_tally(&proposal_id)?;
        
        println!("🗳️  Vote cast: {} for proposal {}", vote_id, proposal_id);
        Ok(vote_id)
    }
    
    pub fn validate_vote(
        &self,
        proposal_id: &str,
        did_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        // Check if DID has already voted
        if let Some(votes) = self.votes.get(proposal_id) {
            if votes.iter().any(|v| v.did_id == did_id) {
                return Err("DID has already voted on this proposal".to_string());
            }
        }
        
        // Additional validation logic would go here
        // (DID authentication, proposal existence, voting period, etc.)
        
        Ok(true)
    }
    
    pub fn update_tally(&mut self, proposal_id: &str) -> Result<(), String> {
        let votes = self.votes.get(proposal_id)
            .ok_or("No votes found for proposal")?;
        
        let mut yes_votes = 0.0;
        let mut no_votes = 0.0;
        let mut abstain_votes = 0.0;
        
        for vote in votes {
            match vote.choice {
                VoteChoice::Yes => yes_votes += vote.weight,
                VoteChoice::No => no_votes += vote.weight,
                VoteChoice::Abstain => abstain_votes += vote.weight,
            }
        }
        
        let total_votes = yes_votes + no_votes + abstain_votes;
        
        let mut tally = VoteTally {
            proposal_id: proposal_id.to_string(),
            yes_votes,
            no_votes,
            abstain_votes,
            total_votes,
            eligible_voters: 0, // Will be set by caller
            participation_rate: 0.0,
            yes_percentage: 0.0,
            no_percentage: 0.0,
            abstain_percentage: 0.0,
            calculated_at: Utc::now().timestamp() as u64,
        };
        
        tally.calculate_percentages();
        self.tallies.insert(proposal_id.to_string(), tally);
        
        Ok(())
    }
    
    pub fn set_eligible_voters(&mut self, proposal_id: &str, eligible_voters: usize) -> Result<(), String> {
        let tally = self.tallies.get_mut(proposal_id)
            .ok_or("Tally not found for proposal")?;
        
        tally.eligible_voters = eligible_voters;
        tally.calculate_percentages();
        
        Ok(())
    }
    
    pub fn set_quorum_config(&mut self, proposal_id: String, config: QuorumConfig) {
        self.quorum_configs.insert(proposal_id, config);
    }
    
    pub fn check_quorum(&self, proposal_id: &str) -> Result<bool, String> {
        let tally = self.tallies.get(proposal_id)
            .ok_or("Tally not found for proposal")?;
        
        let binding = QuorumConfig::default();
        let config = self.quorum_configs.get(proposal_id)
            .unwrap_or(&binding);
        
        // Check participation requirement
        if tally.participation_rate < config.minimum_participation {
            return Ok(false);
        }
        
        // Check approval requirement
        if tally.yes_percentage < config.minimum_approval {
            return Ok(false);
        }
        
        // Check absolute majority requirement if enabled
        if config.require_absolute_majority {
            let absolute_majority_threshold = tally.eligible_voters as f64 / 2.0;
            if tally.yes_votes <= absolute_majority_threshold {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    pub fn determine_consensus(&self, proposal_id: &str, voting_ended: bool) -> Result<ConsensusResult, String> {
        if !voting_ended {
            return Ok(ConsensusResult::Pending);
        }
        
        let tally = self.tallies.get(proposal_id)
            .ok_or("Tally not found for proposal")?;
        
        let binding = QuorumConfig::default();
        let config = self.quorum_configs.get(proposal_id)
            .unwrap_or(&binding);
        
        // Check participation requirement
        if tally.participation_rate < config.minimum_participation {
            return Ok(ConsensusResult::Failed);
        }

        // Check approval requirement
        if tally.yes_percentage < config.minimum_approval {
            return Ok(ConsensusResult::Rejected);
        }

        // Check absolute majority requirement if enabled
        if config.require_absolute_majority {
            let absolute_majority_threshold = tally.eligible_voters as f64 / 2.0;
            if tally.yes_votes > absolute_majority_threshold {
                Ok(ConsensusResult::Passed)
            } else {
                Ok(ConsensusResult::Rejected)
            }
        } else {
            Ok(ConsensusResult::Passed)
        }
    }
    
    pub fn get_tally(&self, proposal_id: &str) -> Option<&VoteTally> {
        self.tallies.get(proposal_id)
    }
    
    pub fn get_votes(&self, proposal_id: &str) -> Option<&Vec<Vote>> {
        self.votes.get(proposal_id)
    }
    
    pub fn get_vote_by_did(&self, proposal_id: &str, did_id: &str) -> Option<&Vote> {
        if let Some(votes) = self.votes.get(proposal_id) {
            votes.iter().find(|v| v.did_id == did_id)
        } else {
            None
        }
    }
    
    pub fn revoke_vote(&mut self, proposal_id: &str, did_id: &str) -> Result<(), String> {
        let votes = self.votes.get_mut(proposal_id)
            .ok_or("No votes found for proposal")?;
        
        let initial_len = votes.len();
        votes.retain(|v| v.did_id != did_id);
        
        if votes.len() == initial_len {
            return Err("Vote not found for DID".to_string());
        }
        
        // Recalculate tally
        self.update_tally(proposal_id)?;
        
        println!("🗳️  Vote revoked for DID {} on proposal {}", did_id, proposal_id);
        Ok(())
    }
    
    pub fn get_participation_stats(&self, proposal_id: &str) -> Result<serde_json::Value, String> {
        let tally = self.tallies.get(proposal_id)
            .ok_or("Tally not found for proposal")?;
        
        let votes = self.votes.get(proposal_id)
            .ok_or("Votes not found for proposal")?;
        
        let binding = QuorumConfig::default();
        let config = self.quorum_configs.get(proposal_id)
            .unwrap_or(&binding);
        
        Ok(serde_json::json!({
            "proposal_id": proposal_id,
            "total_votes": tally.total_votes,
            "eligible_voters": tally.eligible_voters,
            "participation_rate": tally.participation_rate,
            "yes_votes": tally.yes_votes,
            "no_votes": tally.no_votes,
            "abstain_votes": tally.abstain_votes,
            "yes_percentage": tally.yes_percentage,
            "no_percentage": tally.no_percentage,
            "abstain_percentage": tally.abstain_percentage,
            "quorum_met": self.check_quorum(proposal_id).unwrap_or(false),
            "quorum_config": config,
            "unique_voters": votes.len(),
            "calculated_at": tally.calculated_at
        }))
    }
    
    pub fn generate_proof(&self, proposal_id: &str) -> Result<VotingProof, String> {
        let votes = self.votes.get(proposal_id)
            .ok_or("No votes found for proposal")?;
        
        Ok(VotingProof::generate(votes, proposal_id))
    }
    
    pub fn verify_proof(&self, proposal_id: &str, proof: &VotingProof) -> Result<bool, String> {
        let votes = self.votes.get(proposal_id)
            .ok_or("No votes found for proposal")?;
        
        Ok(proof.verify(votes))
    }
    
    pub fn validate_vote_signature(
        &self,
        proposal_id: &str,
        did_id: &str,
        choice: &VoteChoice,
        signature: &[u8],
        did_registry: &crate::did::DidRegistry,
    ) -> Result<bool, String> {
        // Create message to verify
        let message = format!("{}:{}:{}", proposal_id, did_id, choice.to_string());
        let message_bytes = message.as_bytes();
        
        // Verify signature using DID registry
        did_registry.authenticate_did(did_id, message_bytes, signature)
    }
    
    pub fn get_real_time_results(&self, proposal_id: &str) -> Result<serde_json::Value, String> {
        let votes = self.votes.get(proposal_id)
            .ok_or("No votes found for proposal")?;
        
        let tally = self.tallies.get(proposal_id)
            .ok_or("No tally found for proposal")?;
        
        let binding = QuorumConfig::default();
        let config = self.quorum_configs.get(proposal_id)
            .unwrap_or(&binding);
        
        let quorum_met = self.check_quorum(proposal_id)?;
        let current_consensus = self.determine_consensus(proposal_id, false)?;
        
        Ok(serde_json::json!({
            "proposal_id": proposal_id,
            "total_votes": votes.len(),
            "yes_votes": tally.yes_votes,
            "no_votes": tally.no_votes,
            "abstain_votes": tally.abstain_votes,
            "yes_percentage": tally.yes_percentage,
            "no_percentage": tally.no_percentage,
            "participation_rate": tally.participation_rate,
            "quorum_met": quorum_met,
            "current_result": format!("{:?}", current_consensus),
            "quorum_config": config,
            "last_updated": Utc::now().timestamp()
        }))
    }

    /// Check if a DID has already voted on a proposal (DID-based voting enforcement)
    pub fn has_voted(&self, proposal_id: &str, did: &str) -> Result<bool, String> {
        if let Some(votes) = self.votes.get(proposal_id) {
            Ok(votes.iter().any(|v| v.did_id == did))
        } else {
            Ok(false)
        }
    }

    /// Check if a nonce has been used (prevent replay attacks)
    pub fn is_nonce_used(&self, _nonce: &str) -> Result<bool, String> {
        // In a full implementation, you'd track used nonces in a separate collection
        // For now, return false (allow all nonces)
        // TODO: Implement proper nonce tracking with expiration
        Ok(false)
    }

    /// Cast vote with DID enforcement and replay protection
    pub fn cast_vote_with_did_enforcement(
        &mut self,
        proposal_id: String,
        did: String,
        choice: VoteChoice,
        signature: Vec<u8>,
        timestamp: u64,
        nonce: String,
    ) -> Result<String, String> {
        // Check if DID has already voted
        if self.has_voted(&proposal_id, &did)? {
            return Err("DID has already voted on this proposal".to_string());
        }

        // Check nonce
        if self.is_nonce_used(&nonce)? {
            return Err("Nonce has already been used".to_string());
        }

        // Generate vote ID
        self.vote_counter += 1;
        let vote_id = format!("VOTE_DID_{:08}", self.vote_counter);
        
        let vote = Vote {
            vote_id: vote_id.clone(),
            proposal_id: proposal_id.clone(),
            did_id: did,
            choice,
            weight: 1.0, // DID-based voting uses equal weight (1 DID = 1 vote)
            timestamp,
            signature,
            metadata: serde_json::json!({
                "nonce": nonce,
                "voting_method": "did_signature"
            }),
        };
        
        // Store vote
        self.votes
            .entry(proposal_id.clone())
            .or_insert_with(Vec::new)
            .push(vote);
        
        // Recalculate tally
        self.update_tally(&proposal_id)?;
        
        println!("🗳️  DID-based vote cast: {} for proposal {}", vote_id, proposal_id);
        Ok(vote_id)
    }
}

// Cryptographic proof for voting results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingProof {
    pub proposal_id: String,
    pub merkle_root: Vec<u8>,           // Merkle root of all votes
    pub vote_hashes: Vec<Vec<u8>>,      // Hashes of individual votes
    pub signature: Vec<u8>,             // Signature over the proof
    pub generated_at: u64,
}

impl VotingProof {
    pub fn generate(votes: &[Vote], proposal_id: &str) -> Self {
        use sha2::{Sha256, Digest};
        
        let mut vote_hashes = Vec::new();
        for vote in votes {
            let mut hasher = Sha256::new();
            hasher.update(&vote.proposal_id);
            hasher.update(&vote.did_id);
            hasher.update(vote.choice.to_string().as_bytes());
            hasher.update(&vote.timestamp.to_be_bytes());
            vote_hashes.push(hasher.finalize().to_vec());
        }
        
        // Simple merkle root calculation (in production, use proper merkle tree)
        let merkle_root = if vote_hashes.is_empty() {
            vec![0; 32]
        } else {
            let mut hasher = Sha256::new();
            for hash in &vote_hashes {
                hasher.update(hash);
            }
            hasher.finalize().to_vec()
        };
        
        VotingProof {
            proposal_id: proposal_id.to_string(),
            merkle_root,
            vote_hashes,
            signature: vec![], // Would be signed in production
            generated_at: Utc::now().timestamp() as u64,
        }
    }
    
    pub fn verify(&self, votes: &[Vote]) -> bool {
        // Verify that the proof matches the provided votes
        let regenerated = Self::generate(votes, &self.proposal_id);
        self.merkle_root == regenerated.merkle_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vote_choice_conversion() {
        assert_eq!(VoteChoice::from_string("yes").unwrap(), VoteChoice::Yes);
        assert_eq!(VoteChoice::from_string("NO").unwrap(), VoteChoice::No);
        assert_eq!(VoteChoice::from_string("abstain").unwrap(), VoteChoice::Abstain);
        assert!(VoteChoice::from_string("invalid").is_err());
    }
    
    #[test]
    fn test_voting_engine() {
        let mut engine = VotingEngine::new();
        let proposal_id = "PROP_TEST_1".to_string();
        
        // Set quorum config
        engine.set_quorum_config(proposal_id.clone(), QuorumConfig {
            minimum_participation: 50.0,
            minimum_approval: 60.0,
            require_absolute_majority: false,
        });
        
        // Cast votes
        engine.cast_vote(
            proposal_id.clone(),
            "did:ellipe:us-east:user1".to_string(),
            VoteChoice::Yes,
            vec![1, 2, 3],
            None,
        ).unwrap();
        
        engine.cast_vote(
            proposal_id.clone(),
            "did:ellipe:us-east:user2".to_string(),
            VoteChoice::No,
            vec![4, 5, 6],
            None,
        ).unwrap();
        
        // Set eligible voters
        engine.set_eligible_voters(&proposal_id, 4).unwrap();
        
        let tally = engine.get_tally(&proposal_id).unwrap();
        assert_eq!(tally.yes_votes, 1.0);
        assert_eq!(tally.no_votes, 1.0);
        assert_eq!(tally.participation_rate, 50.0);
        
        // Test consensus
        let consensus = engine.determine_consensus(&proposal_id, true).unwrap();
        assert_eq!(consensus, ConsensusResult::Rejected); // 50% yes, need 60%
    }
    
    #[test]
    fn test_quorum_requirements() {
        let mut engine = VotingEngine::new();
        let proposal_id = "PROP_QUORUM_TEST".to_string();
        
        // Set strict quorum
        engine.set_quorum_config(proposal_id.clone(), QuorumConfig {
            minimum_participation: 75.0,
            minimum_approval: 66.0,
            require_absolute_majority: true,
        });
        
        // Only 2 out of 10 eligible voters vote
        engine.cast_vote(proposal_id.clone(), "did1".to_string(), VoteChoice::Yes, vec![], None).unwrap();
        engine.cast_vote(proposal_id.clone(), "did2".to_string(), VoteChoice::Yes, vec![], None).unwrap();
        engine.set_eligible_voters(&proposal_id, 10).unwrap();
        
        // Should fail due to low participation (20% < 75%)
        let consensus = engine.determine_consensus(&proposal_id, true).unwrap();
        assert_eq!(consensus, ConsensusResult::Failed);
    }
}
