// admin/consensus_poa.rs
// Proof of Authority consensus for admin chain with on-chain authority management

use std::collections::{HashSet, HashMap};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Serialize, Deserialize};

// Wrapper types for PublicKey and Signature to implement required traits
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdminPublicKey(pub [u8; 32]);

impl From<PublicKey> for AdminPublicKey {
    fn from(pk: PublicKey) -> Self {
        AdminPublicKey(pk.to_bytes())
    }
}

impl From<&AdminPublicKey> for PublicKey {
    fn from(apk: &AdminPublicKey) -> Self {
        PublicKey::from_bytes(&apk.0).unwrap()
    }
}

impl Serialize for AdminPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for AdminPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid public key length"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(AdminPublicKey(array))
    }
}

#[derive(Clone, Debug)]
pub struct AdminSignature(pub [u8; 64]);

impl From<Signature> for AdminSignature {
    fn from(sig: Signature) -> Self {
        AdminSignature(sig.to_bytes())
    }
}

impl From<&AdminSignature> for Signature {
    fn from(asig: &AdminSignature) -> Self {
        Signature::from_bytes(&asig.0).expect("Invalid signature bytes")
    }
}

impl Serialize for AdminSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for AdminSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(AdminSignature(array))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AdminTx {
    Mint { to: String, amount: u64 },
    Burn { from: String, amount: u64 },
    Transfer { from: String, to: String, amount: u64 },
    ProofOfReserve { details: String },
    // Authority management
    ProposeAddAdmin { new_admin: AdminPublicKey },
    ProposeRemoveAdmin { admin: AdminPublicKey },
    VoteAuthorityChange { proposal_id: u64, approve: bool },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthorityProposal {
    pub id: u64,
    pub action: AuthorityAction,
    pub votes: HashSet<AdminPublicKey>,
    pub approvals: usize,
    pub rejections: usize,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AuthorityAction {
    AddAdmin(AdminPublicKey),
    RemoveAdmin(AdminPublicKey),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AdminBlock {
    pub index: u64,
    pub timestamp: u64,
    pub prev_hash: String,
    pub txs: Vec<AdminTx>,
    pub proposer: AdminPublicKey,
    pub signature: Option<AdminSignature>,
    pub hash: String,
}

impl AdminBlock {
    pub fn new(index: u64, timestamp: u64, prev_hash: String, txs: Vec<AdminTx>, proposer: AdminPublicKey) -> Self {
        let mut block = Self {
            index,
            timestamp,
            prev_hash,
            txs,
            proposer,
            signature: None,
            hash: String::new(),
        };
        block.hash = block.calculate_hash();
        block
    }

    pub fn calculate_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(serde_json::to_string(&self.txs).unwrap().as_bytes());
        hasher.update(&self.proposer.0);
        hex::encode(hasher.finalize())
    }

    pub fn sign(&mut self, signing_key: &ed25519_dalek::Keypair) {
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(self.hash.as_bytes());
        self.signature = Some(AdminSignature::from(signature));
    }

    pub fn verify_signature(&self) -> bool {
        if let Some(signature) = &self.signature {
            let pk: PublicKey = (&self.proposer).into();
            let sig: Signature = signature.into();
            pk.verify(self.hash.as_bytes(), &sig).is_ok()
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct AuthoritySet {
    pub authorities: HashSet<AdminPublicKey>,
    pub threshold: usize, // Minimum votes needed for authority changes
}

impl AuthoritySet {
    pub fn new(initial_authorities: HashSet<AdminPublicKey>) -> Self {
        let threshold = (initial_authorities.len() / 2) + 1; // >50%
        Self {
            authorities: initial_authorities,
            threshold,
        }
    }

    pub fn is_authority(&self, key: &AdminPublicKey) -> bool {
        self.authorities.contains(key)
    }

    pub fn add_authority(&mut self, key: AdminPublicKey) {
        self.authorities.insert(key);
        self.threshold = (self.authorities.len() / 2) + 1;
    }

    pub fn remove_authority(&mut self, key: &AdminPublicKey) {
        self.authorities.remove(key);
        self.threshold = (self.authorities.len() / 2) + 1;
    }

    pub fn size(&self) -> usize {
        self.authorities.len()
    }
}

#[derive(Clone)]
pub struct PoAConsensus {
    pub authority_set: AuthoritySet,
    pub proposals: HashMap<u64, AuthorityProposal>,
    pub proposal_counter: u64,
    pub chain: Vec<AdminBlock>,
    pub event_log: Vec<AdminTx>,
}

impl PoAConsensus {
    pub fn new(initial_authorities: HashSet<AdminPublicKey>) -> Self {
        Self {
            authority_set: AuthoritySet::new(initial_authorities),
            proposals: HashMap::new(),
            proposal_counter: 0,
            chain: Vec::new(),
            event_log: Vec::new(),
        }
    }

    pub fn init_genesis(&mut self) {
        let genesis = AdminBlock::new(
            0,
            0,
            "0".to_string(),
            vec![],
            self.authority_set.authorities.iter().next().unwrap().clone(),
        );
        self.chain.push(genesis);
    }

    pub fn propose_block(&mut self, proposer_signing_key: &ed25519_dalek::Keypair, txs: Vec<AdminTx>) -> Result<AdminBlock, String> {
        let proposer_admin_key = AdminPublicKey::from(proposer_signing_key.public);
        
        if !self.authority_set.is_authority(&proposer_admin_key) {
            return Err("Not an authorized proposer".to_string());
        }

        let latest = self.chain.last().ok_or("No genesis block")?;
        let timestamp = chrono::Utc::now().timestamp() as u64;
        
        let mut block = AdminBlock::new(
            latest.index + 1,
            timestamp,
            latest.hash.clone(),
            txs.clone(),
            proposer_admin_key,
        );

        block.sign(proposer_signing_key);

        if !block.verify_signature() {
            return Err("Invalid block signature".to_string());
        }

        // Process transactions and update state
        self.process_transactions(&txs)?;
        
        self.chain.push(block.clone());
        self.event_log.extend(txs);

        Ok(block)
    }

    pub fn validate_block(&self, block: &AdminBlock) -> Result<(), String> {
        if !self.authority_set.is_authority(&block.proposer) {
            return Err("Block proposer is not an authority".to_string());
        }

        if !block.verify_signature() {
            return Err("Invalid block signature".to_string());
        }

        let latest = self.chain.last().ok_or("No genesis block")?;
        if block.index != latest.index + 1 {
            return Err("Invalid block index".to_string());
        }

        if block.prev_hash != latest.hash {
            return Err("Invalid previous hash".to_string());
        }

        Ok(())
    }

    pub fn process_transactions(&mut self, txs: &[AdminTx]) -> Result<(), String> {
        for tx in txs {
            match tx {
                AdminTx::ProposeAddAdmin { new_admin } => {
                    self.proposal_counter += 1;
                    let proposal = AuthorityProposal {
                        id: self.proposal_counter,
                        action: AuthorityAction::AddAdmin(new_admin.clone()),
                        votes: HashSet::new(),
                        approvals: 0,
                        rejections: 0,
                        created_at: chrono::Utc::now().timestamp() as u64,
                    };
                    self.proposals.insert(self.proposal_counter, proposal);
                },
                AdminTx::ProposeRemoveAdmin { admin } => {
                    self.proposal_counter += 1;
                    let proposal = AuthorityProposal {
                        id: self.proposal_counter,
                        action: AuthorityAction::RemoveAdmin(admin.clone()),
                        votes: HashSet::new(),
                        approvals: 0,
                        rejections: 0,
                        created_at: chrono::Utc::now().timestamp() as u64,
                    };
                    self.proposals.insert(self.proposal_counter, proposal);
                },
                AdminTx::VoteAuthorityChange { proposal_id: _, approve: _ } => {
                    // Note: We need the voter's public key, which should be passed separately
                    // This is a simplified version - in practice, you'd extract voter from block proposer
                },
                _ => {
                    // Handle other transaction types (Mint, Burn, ProofOfReserve)
                }
            }
        }
        Ok(())
    }

    pub fn vote_on_proposal(&mut self, voter: &AdminPublicKey, proposal_id: u64, approve: bool) -> Result<bool, String> {
        if !self.authority_set.is_authority(voter) {
            return Err("Voter is not an authority".to_string());
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or("Proposal not found")?;

        if !proposal.votes.insert(voter.clone()) {
            return Err("Already voted on this proposal".to_string());
        }

        if approve {
            proposal.approvals += 1;
        } else {
            proposal.rejections += 1;
        }

        // Check if proposal passes
        if proposal.approvals >= self.authority_set.threshold {
            match &proposal.action {
                AuthorityAction::AddAdmin(new_admin) => {
                    self.authority_set.add_authority(new_admin.clone());
                },
                AuthorityAction::RemoveAdmin(admin) => {
                    self.authority_set.remove_authority(admin);
                }
            }
            self.proposals.remove(&proposal_id);
            return Ok(true); // Proposal executed
        }

        Ok(false) // Proposal still pending
    }

    pub fn get_latest_block(&self) -> Option<&AdminBlock> {
        self.chain.last()
    }

    pub fn get_authorities(&self) -> &HashSet<AdminPublicKey> {
        &self.authority_set.authorities
    }

    pub fn get_pending_proposals(&self) -> &HashMap<u64, AuthorityProposal> {
        &self.proposals
    }

    pub fn get_event_log(&self) -> &[AdminTx] {
        &self.event_log
    }
}

impl AdminPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        AdminPublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AuthorityProposal {
    pub fn is_completed(&self) -> bool {
        false // For now, proposals are removed when completed, so existing ones are always pending
    }
}
