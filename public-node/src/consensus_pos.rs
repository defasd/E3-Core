// public/consensus_pos.rs
// Proof of Stake consensus for public chain

use std::collections::HashMap;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};

// Wrapper types for PublicKey and Signature to implement required traits
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ValidatorPublicKey(pub [u8; 32]);

impl From<PublicKey> for ValidatorPublicKey {
    fn from(pk: PublicKey) -> Self {
        ValidatorPublicKey(pk.to_bytes())
    }
}

impl From<&ValidatorPublicKey> for PublicKey {
    fn from(vpk: &ValidatorPublicKey) -> Self {
        PublicKey::from_bytes(&vpk.0).unwrap()
    }
}

impl ValidatorPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ValidatorPublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for ValidatorPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ValidatorPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid validator public key length"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(ValidatorPublicKey(array))
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorSignature(pub [u8; 64]);

impl From<Signature> for ValidatorSignature {
    fn from(sig: Signature) -> Self {
        ValidatorSignature(sig.to_bytes())
    }
}

impl From<&ValidatorSignature> for Signature {
    fn from(vsig: &ValidatorSignature) -> Self {
        Signature::from_bytes(&vsig.0).expect("Invalid signature bytes")
    }
}

impl Serialize for ValidatorSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ValidatorSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid validator signature length"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(ValidatorSignature(array))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PublicTx {
    Transfer { from: String, to: String, amount: u64, token: TokenType },
    Stake { staker: ValidatorPublicKey, amount: u64 },
    Unstake { staker: ValidatorPublicKey, amount: u64 },
    ValidatorRegistration { validator: ValidatorPublicKey, stake: u64 },
    // Cross-chain transactions from admin chain
    AdminMint { to: String, amount: u64, admin_block_hash: String },
    AdminBurn { from: String, amount: u64, admin_block_hash: String },
    AdminProofOfReserve { details: String, admin_block_hash: String },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Validator {
    pub public_key: ValidatorPublicKey,
    pub stake: u64,
    pub is_active: bool,
    pub last_block_time: u64,
    pub slash_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicBlock {
    pub index: u64,
    pub timestamp: u64,
    pub prev_hash: String,
    pub txs: Vec<PublicTx>,
    pub proposer: ValidatorPublicKey,
    pub signature: Option<ValidatorSignature>,
    pub hash: String,
    pub state_root: String,
}

impl PublicBlock {
    pub fn new(index: u64, timestamp: u64, prev_hash: String, txs: Vec<PublicTx>, proposer: ValidatorPublicKey) -> Self {
        let mut block = Self {
            index,
            timestamp,
            prev_hash,
            txs,
            proposer,
            signature: None,
            hash: String::new(),
            state_root: String::new(),
        };
        block.hash = block.calculate_hash();
        block.state_root = block.calculate_state_root();
        block
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(serde_json::to_string(&self.txs).unwrap().as_bytes());
        hasher.update(&self.proposer.0);
        hex::encode(hasher.finalize())
    }

    pub fn calculate_state_root(&self) -> String {
        // Simplified state root calculation
        let mut hasher = Sha256::new();
        hasher.update(self.hash.as_bytes());
        hasher.update("state".as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn sign(&mut self, signing_key: &ed25519_dalek::Keypair) {
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(self.hash.as_bytes());
        self.signature = Some(ValidatorSignature::from(signature));
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

pub struct ValidatorSet {
    pub validators: HashMap<ValidatorPublicKey, Validator>,
    pub total_stake: u64,
    pub min_stake: u64,
}

impl ValidatorSet {
    pub fn new(min_stake: u64) -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: 0,
            min_stake,
        }
    }

    pub fn add_validator(&mut self, validator: Validator) -> Result<(), String> {
        if validator.stake < self.min_stake {
            return Err("Insufficient stake to become validator".to_string());
        }
        
        self.total_stake += validator.stake;
        self.validators.insert(validator.public_key.clone(), validator);
        Ok(())
    }

    pub fn remove_validator(&mut self, validator_key: &ValidatorPublicKey) -> Result<(), String> {
        if let Some(validator) = self.validators.remove(validator_key) {
            self.total_stake -= validator.stake;
            Ok(())
        } else {
            Err("Validator not found".to_string())
        }
    }

    pub fn is_validator(&self, key: &ValidatorPublicKey) -> bool {
        self.validators.contains_key(key) && 
        self.validators.get(key).map_or(false, |v| v.is_active)
    }

    pub fn get_active_validators(&self) -> Vec<&Validator> {
        self.validators.values().filter(|v| v.is_active).collect()
    }

    pub fn select_proposer(&self, block_number: u64) -> Option<&ValidatorPublicKey> {
        let active_validators: Vec<_> = self.validators.iter()
            .filter(|(_, v)| v.is_active)
            .collect();
        
        if active_validators.is_empty() {
            return None;
        }
        
        // Simple round-robin selection based on block number
        let index = (block_number as usize) % active_validators.len();
        Some(active_validators[index].0)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TokenType {
    SU,
    GU,
}

pub struct PoSConsensus {
    pub validator_set: ValidatorSet,
    pub chain: Vec<PublicBlock>,
    pub event_log: Vec<PublicTx>,
    pub balances: HashMap<String, HashMap<TokenType, u64>>,
    pub nonces: HashMap<String, u64>,
}

impl PoSConsensus {
    pub fn new(min_stake: u64) -> Self {
        Self {
            validator_set: ValidatorSet::new(min_stake),
            chain: Vec::new(),
            event_log: Vec::new(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
        }
    }

    pub fn init_genesis(&mut self) {
        let genesis = PublicBlock::new(
            0,
            0,
            "0".to_string(),
            vec![],
            ValidatorPublicKey([0u8; 32]), // Dummy proposer for genesis
        );
        self.chain.push(genesis);
    }

    pub fn propose_block(&mut self, proposer_signing_key: &ed25519_dalek::Keypair, txs: Vec<PublicTx>) -> Result<PublicBlock, String> {
        let proposer_key = ValidatorPublicKey::from(proposer_signing_key.public);
        
        println!("DEBUG: propose_block - proposer: {}, chain_len: {}, validators: {}, active_validators: {}", 
                 hex::encode(proposer_key.as_bytes()), self.chain.len(), 
                 self.validator_set.validators.len(), self.validator_set.get_active_validators().len());
        
        // Allow bootstrap block when chain is empty or only has genesis
        if self.chain.len() <= 1 {
            println!("Producing bootstrap block to activate validator set");
        } 
        // For subsequent blocks, check if proposer is a registered validator
        // Allow the proposer if they are the only validator or if there are no active validators yet
        else if !self.validator_set.is_validator(&proposer_key) && 
                 !self.validator_set.validators.is_empty() && 
                 !self.validator_set.get_active_validators().is_empty() {
            return Err(format!("Not an authorized validator. Proposer: {}, Active validators: {}", 
                hex::encode(proposer_key.as_bytes()),
                self.validator_set.get_active_validators().len()));
        } 
        // If no active validators but there are registered validators, allow the proposer to produce a block
        else if !self.validator_set.validators.is_empty() && 
                 self.validator_set.get_active_validators().is_empty() {
            println!("No active validators yet, allowing block production to activate validators");
        }

        let timestamp = chrono::Utc::now().timestamp() as u64;
        
        // Handle genesis block creation
        let (index, prev_hash) = if self.chain.is_empty() {
            (0, "genesis".to_string())
        } else {
            let latest = self.chain.last().unwrap();
            (latest.index + 1, latest.hash.clone())
        };
        
        println!("DEBUG: Creating block #{} with {} transactions", index, txs.len());
        
        let mut block = PublicBlock::new(
            index,
            timestamp,
            prev_hash,
            txs.clone(),
            proposer_key,
        );
    

        block.sign(proposer_signing_key);

        if !block.verify_signature() {
            return Err("Invalid block signature".to_string());
        }

        // Process transactions and update state
        self.process_transactions(&txs)?;
        
        self.chain.push(block.clone());
        self.event_log.extend(txs);

        println!("DEBUG: Block #{} successfully created and added to chain", block.index);
        Ok(block)
    }

    pub fn validate_block(&self, block: &PublicBlock) -> Result<(), String> {
        // Allow genesis block (index 0) to be proposed by anyone
        if block.index > 0 && !self.validator_set.is_validator(&block.proposer) {
            return Err("Block proposer is not a validator".to_string());
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

    pub fn process_transactions(&mut self, txs: &[PublicTx]) -> Result<(), String> {
        let mut errors = Vec::new();
        for tx in txs {
            println!("DEBUG: Processing transaction: {:?}", tx);
            let result = match tx {
                PublicTx::Transfer { from, to, amount, token } => self.transfer(from, to, *amount, token.clone()),
                PublicTx::Stake { staker, amount } => self.stake_tokens(staker, *amount),
                PublicTx::Unstake { staker, amount } => self.unstake_tokens(staker, *amount),
                PublicTx::ValidatorRegistration { validator, stake } => self.register_validator(validator.clone(), *stake),
                PublicTx::AdminMint { to, amount, .. } => {
                    let su_amount = amount.saturating_mul(20);
                    let entry = self.balances.entry(to.clone()).or_default();
                    *entry.entry(TokenType::SU).or_insert(0) += su_amount;
                    *entry.entry(TokenType::GU).or_insert(0) += *amount;
                    Ok(())
                },
                PublicTx::AdminBurn { from, amount, .. } => {
                    let entry = self.balances.entry(from.clone()).or_default();
                    let su_balance = entry.entry(TokenType::SU).or_insert(0);
                    if *su_balance < *amount {
                        Err("Insufficient balance for burn".to_string())
                    } else {
                        *su_balance -= *amount;
                        Ok(())
                    }
                },
                PublicTx::AdminProofOfReserve { .. } => Ok(()),
            };
            if let Err(e) = result {
                println!("Transaction failed: {:?} - {:?}", tx, e);
                errors.push(e);
            }
        }
        // DEBUG: Print validator set after processing transactions
        println!("DEBUG: Validators after processing txs: {:?}", self.validator_set.validators);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("Some transactions failed: {:?}", errors))
        }
    }

    fn transfer(&mut self, from: &str, to: &str, amount: u64, token: TokenType) -> Result<(), String> {
        // Avoid double mutable borrow by splitting logic
        let from_balance = self.balances
            .get(from)
            .and_then(|m| m.get(&token))
            .cloned()
            .unwrap_or(0);
        if from_balance < amount {
            return Err("Insufficient balance".to_string());
        }
        // Subtract from sender
        self.balances
            .entry(from.to_string())
            .or_default()
            .entry(token.clone())
            .and_modify(|v| *v -= amount)
            .or_insert(0);
        // Add to recipient
        self.balances
            .entry(to.to_string())
            .or_default()
            .entry(token)
            .and_modify(|v| *v += amount)
            .or_insert(amount);
        Ok(())
    }

    fn stake_tokens(&mut self, staker: &ValidatorPublicKey, amount: u64) -> Result<(), String> {
        // Logic for staking tokens
        if let Some(validator) = self.validator_set.validators.get_mut(staker) {
            validator.stake += amount;
            self.validator_set.total_stake += amount;
        }
        Ok(())
    }

    fn unstake_tokens(&mut self, staker: &ValidatorPublicKey, amount: u64) -> Result<(), String> {
        // Logic for unstaking tokens
        if let Some(validator) = self.validator_set.validators.get_mut(staker) {
            if validator.stake < amount {
                return Err("Insufficient staked amount".to_string());
            }
            validator.stake -= amount;
            self.validator_set.total_stake -= amount;
            
            if validator.stake < self.validator_set.min_stake {
                validator.is_active = false;
            }
        }
        Ok(())
    }

    fn register_validator(&mut self, validator_key: ValidatorPublicKey, stake: u64) -> Result<(), String> {
        let validator = Validator {
            public_key: validator_key.clone(),
            stake,
            is_active: true,
            last_block_time: chrono::Utc::now().timestamp() as u64,
            slash_count: 0,
        };
        self.validator_set.add_validator(validator)
    }

    pub fn get_latest_block(&self) -> Option<&PublicBlock> {
        self.chain.last()
    }

    pub fn get_validators(&self) -> &HashMap<ValidatorPublicKey, Validator> {
        &self.validator_set.validators
    }

    pub fn get_event_log(&self) -> &[PublicTx] {
        &self.event_log
    }

    pub fn get_balance(&self, address: &str, token: TokenType) -> u64 {
        self.balances
            .get(address)
            .and_then(|m| m.get(&token))
            .cloned()
            .unwrap_or(0)
    }

    /// Returns all token balances for a given address, always including SU and GU (default 0 if missing)
    pub fn get_all_balances(&self, address: &str) -> HashMap<TokenType, u64> {
        let mut map = HashMap::new();
        let inner = self.balances.get(address);
        map.insert(TokenType::SU, inner.and_then(|m| m.get(&TokenType::SU)).cloned().unwrap_or(0));
        map.insert(TokenType::GU, inner.and_then(|m| m.get(&TokenType::GU)).cloned().unwrap_or(0));
        map
    }

    pub fn get_block(&self, index: u64) -> Option<&PublicBlock> {
        self.chain.iter().find(|block| block.index == index)
    }
}
