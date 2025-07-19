use ed25519_dalek::Verifier;
// DID Management Module
//
/// Handles Decentralized Identifier (DID) issuance, validation, and authentication

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::Utc;
use ed25519_dalek::{PublicKey, Signature};

// DID structure based on DID_STRUCTURE.md
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Did {
    pub id: String,                    // e.g., "did:ellipe:us-east:6f9e12..."
    pub method: String,                // "ellipe"
    pub network: String,               // "us-east", "eu-west", etc.
    pub identifier: String,            // Unique identifier part
    pub public_key: Vec<u8>,          // ed25519 public key
    pub wallet_addresses: Vec<String>, // Associated wallet addresses
    pub created_at: u64,
    pub updated_at: u64,
    pub is_active: bool,
    pub metadata: serde_json::Value,   // Additional metadata
}

impl Did {
    pub fn new(
        method: String,
        network: String,
        public_key: PublicKey,
        wallet_address: String,
    ) -> Self {
        let identifier = hex::encode(&public_key.as_bytes()[..16]); // First 16 bytes as hex
        let id = format!("did:{}:{}:{}", method, network, identifier);
        let now = Utc::now().timestamp() as u64;
        
        Did {
            id,
            method,
            network,
            identifier,
            public_key: public_key.as_bytes().to_vec(),
            wallet_addresses: vec![wallet_address],
            created_at: now,
            updated_at: now,
            is_active: true,
            metadata: serde_json::json!({}),
        }
    }
    
    pub fn add_wallet_address(&mut self, address: String) -> Result<(), String> {
        if self.wallet_addresses.contains(&address) {
            return Err("Wallet address already associated with this DID".to_string());
        }
        
        self.wallet_addresses.push(address);
        self.updated_at = Utc::now().timestamp() as u64;
        Ok(())
    }
    
    pub fn remove_wallet_address(&mut self, address: &str) -> Result<(), String> {
        if self.wallet_addresses.len() <= 1 {
            return Err("Cannot remove the last wallet address from a DID".to_string());
        }
        
        let initial_len = self.wallet_addresses.len();
        self.wallet_addresses.retain(|addr| addr != address);
        
        if self.wallet_addresses.len() == initial_len {
            return Err("Wallet address not found".to_string());
        }
        
        self.updated_at = Utc::now().timestamp() as u64;
        Ok(())
    }
    
    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now().timestamp() as u64;
    }
    
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        let public_key = PublicKey::from_bytes(&self.public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        
        let signature = Signature::from_bytes(signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        
        match public_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// Vote eligibility tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteEligibility {
    pub did_id: String,
    pub is_eligible: bool,
    pub reason: Option<String>,           // Reason for ineligibility if applicable
    pub verified_at: u64,
    pub verification_method: String,      // How eligibility was verified
}

// DID Registry - manages all DIDs and enforces one-person-one-vote
pub struct DidRegistry {
    dids: HashMap<String, Did>,                           // did_id -> Did
    wallet_to_did: HashMap<String, String>,               // wallet_address -> did_id
    vote_eligibility: HashMap<String, VoteEligibility>,   // did_id -> VoteEligibility
    voting_history: HashMap<String, Vec<VoteRecord>>,     // did_id -> Vec<VoteRecord>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    pub proposal_id: String,
    pub timestamp: u64,
    pub choice: String, // "yes", "no", "abstain"
}

impl DidRegistry {
    pub fn new() -> Self {
        DidRegistry {
            dids: HashMap::new(),
            wallet_to_did: HashMap::new(),
            vote_eligibility: HashMap::new(),
            voting_history: HashMap::new(),
        }
    }
    
    pub fn issue_did(
        &mut self,
        method: String,
        network: String,
        public_key: PublicKey,
        wallet_address: String,
    ) -> Result<String, String> {
        // Check if wallet is already associated with a DID
        if self.wallet_to_did.contains_key(&wallet_address) {
            return Err("Wallet address already has an associated DID".to_string());
        }
        
        let did = Did::new(method, network, public_key, wallet_address.clone());
        let did_id = did.id.clone();
        
        // Store DID and create mappings
        self.dids.insert(did_id.clone(), did);
        self.wallet_to_did.insert(wallet_address, did_id.clone());
        
        // Default to eligible for voting
        self.vote_eligibility.insert(did_id.clone(), VoteEligibility {
            did_id: did_id.clone(),
            is_eligible: true,
            reason: None,
            verified_at: Utc::now().timestamp() as u64,
            verification_method: "default".to_string(),
        });
        
        self.voting_history.insert(did_id.clone(), Vec::new());
        
        println!("🆔 Issued new DID: {}", did_id);
        Ok(did_id)
    }
    
    pub fn get_did(&self, did_id: &str) -> Option<&Did> {
        self.dids.get(did_id)
    }
    
    pub fn get_did_by_wallet(&self, wallet_address: &str) -> Option<&Did> {
        if let Some(did_id) = self.wallet_to_did.get(wallet_address) {
            self.dids.get(did_id)
        } else {
            None
        }
    }
    
    pub fn link_wallet_to_did(&mut self, did_id: &str, wallet_address: String) -> Result<(), String> {
        // Check if wallet is already linked to another DID
        if let Some(existing_did) = self.wallet_to_did.get(&wallet_address) {
            if existing_did != did_id {
                return Err("Wallet address already linked to another DID".to_string());
            }
            return Ok(()); // Already linked to this DID
        }
        
        // Check if DID exists
        let did = self.dids.get_mut(did_id)
            .ok_or("DID not found")?;
        
        // Add wallet to DID
        did.add_wallet_address(wallet_address.clone())?;
        self.wallet_to_did.insert(wallet_address.clone(), did_id.to_string());
        
        println!("🔗 Linked wallet {} to DID {}", wallet_address, did_id);
        Ok(())
    }
    
    pub fn authenticate_did(&self, did_id: &str, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        let did = self.dids.get(did_id)
            .ok_or("DID not found")?;
        
        if !did.is_active {
            return Err("DID is deactivated".to_string());
        }
        
        did.verify_signature(message, signature)
    }
    
    pub fn can_vote(&self, did_id: &str, proposal_id: &str) -> Result<bool, String> {
        // Check if DID exists and is active
        let did = self.dids.get(did_id)
            .ok_or("DID not found")?;
        
        if !did.is_active {
            return Err("DID is deactivated".to_string());
        }
        
        // Check vote eligibility
        let eligibility = self.vote_eligibility.get(did_id)
            .ok_or("Vote eligibility not found")?;
        
        if !eligibility.is_eligible {
            return Err(format!("DID not eligible to vote: {:?}", eligibility.reason));
        }
        
        // Check if already voted on this proposal (one-person-one-vote)
        if let Some(vote_history) = self.voting_history.get(did_id) {
            if vote_history.iter().any(|v| v.proposal_id == proposal_id) {
                return Err("DID has already voted on this proposal".to_string());
            }
        }
        
        Ok(true)
    }
    
    pub fn record_vote(&mut self, did_id: &str, proposal_id: &str, choice: &str) -> Result<(), String> {
        // Validate vote eligibility first
        self.can_vote(did_id, proposal_id)?;
        
        let vote_record = VoteRecord {
            proposal_id: proposal_id.to_string(),
            timestamp: Utc::now().timestamp() as u64,
            choice: choice.to_string(),
        };
        
        self.voting_history
            .entry(did_id.to_string())
            .or_insert_with(Vec::new)
            .push(vote_record);
        
        println!("🗳️  Recorded vote for DID {} on proposal {}: {}", did_id, proposal_id, choice);
        Ok(())
    }
    
    pub fn set_vote_eligibility(
        &mut self,
        did_id: &str,
        is_eligible: bool,
        reason: Option<String>,
        verification_method: String,
    ) -> Result<(), String> {
        if !self.dids.contains_key(did_id) {
            return Err("DID not found".to_string());
        }
        
        let eligibility = VoteEligibility {
            did_id: did_id.to_string(),
            is_eligible,
            reason,
            verified_at: Utc::now().timestamp() as u64,
            verification_method,
        };
        
        self.vote_eligibility.insert(did_id.to_string(), eligibility);
        Ok(())
    }
    
    pub fn deactivate_did(&mut self, did_id: &str) -> Result<(), String> {
        let did = self.dids.get_mut(did_id)
            .ok_or("DID not found")?;
        
        did.deactivate();
        
        // Set as ineligible for voting
        self.set_vote_eligibility(
            did_id,
            false,
            Some("DID deactivated".to_string()),
            "admin_action".to_string(),
        )?;
        
        println!("❌ Deactivated DID: {}", did_id);
        Ok(())
    }
    
    pub fn get_vote_history(&self, did_id: &str) -> Option<&Vec<VoteRecord>> {
        self.voting_history.get(did_id)
    }
    
    pub fn list_active_dids(&self) -> Vec<&Did> {
        self.dids.values().filter(|did| did.is_active).collect()
    }
    
    pub fn get_total_eligible_voters(&self) -> usize {
        self.vote_eligibility.values()
            .filter(|e| e.is_eligible)
            .count()
    }

    /// Get DID public key for signature verification
    pub fn get_did_public_key(&self, did_id: &str) -> Result<String, String> {
        let did = self.dids.get(did_id)
            .ok_or("DID not found")?;
        
        if !did.is_active {
            return Err("DID is deactivated".to_string());
        }
        
        Ok(hex::encode(&did.public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::thread_rng;
    
    #[test]
    fn test_did_creation() {
        let signing_key = Keypair::generate(&mut thread_rng());
        let did = Did::new(
            "ellipe".to_string(),
            "us-east".to_string(),
            signing_key.public,
            "wallet123".to_string(),
        );
        
        assert!(did.id.starts_with("did:ellipe:us-east:"));
        assert_eq!(did.wallet_addresses.len(), 1);
        assert!(did.is_active);
    }
    
    #[test]
    fn test_did_registry() {
        let mut registry = DidRegistry::new();
        let signing_key = Keypair::generate(&mut thread_rng());
        
        let did_id = registry.issue_did(
            "ellipe".to_string(),
            "us-east".to_string(),
            signing_key.public,
            "wallet123".to_string(),
        ).unwrap();
        
        assert!(registry.get_did(&did_id).is_some());
        assert!(registry.get_did_by_wallet("wallet123").is_some());
        assert!(registry.can_vote(&did_id, "PROP_1").unwrap());
        
        // Test one-person-one-vote
        registry.record_vote(&did_id, "PROP_1", "yes").unwrap();
        assert!(registry.can_vote(&did_id, "PROP_1").is_err());
    }
}
