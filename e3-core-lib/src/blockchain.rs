use crate::storage::Storage;
use sha2::{Digest, Sha256};
use serde::{Serialize, Deserialize};
use crate::block::Block;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub token_type: String, // e.g. "ST" or "GT"
    pub signature: String,  // placeholder for now
}

impl Block {
    pub fn new(index: u64, timestamp: u64, transactions: Vec<Transaction>, prev_hash: String) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(index.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        for tx in &transactions {
            hasher.update(serde_json::to_string(tx).unwrap().as_bytes());
        }
        hasher.update(prev_hash.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Self {
            index,
            timestamp,
            transactions,
            prev_hash,
            hash,
        }
    }
}

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub storage: Storage,
}

impl Blockchain {
    pub fn new(storage: Storage) -> Self {
        let genesis = Block::new(0, 0, vec![], "0".into());
        let chain = vec![genesis];
        // TODO: load from storage in future
        Self { chain, storage }
    }

    pub fn latest(&self) -> &Block {
        self.chain.last().unwrap()
    }

    pub fn validate_block(&self, block: &Block) -> bool {
        let latest = self.latest();
        block.index == latest.index + 1 && block.prev_hash == latest.hash
    }

    pub fn add_block(&mut self, transactions: Vec<Transaction>) {
        let latest = self.latest();
        let block = Block::new(
            latest.index + 1,
            chrono::Utc::now().timestamp() as u64,
            transactions,
            latest.hash.clone(),
        );
        if self.validate_block(&block) {
            self.chain.push(block.clone());
            self.storage
                .save_data(&block.index.to_string(), &serde_json::to_string(&block).unwrap())
                .unwrap();
        } else {
            println!("Block validation failed!");
        }
    }

    pub fn add_block_with_time(&mut self, transactions: Vec<Transaction>, timestamp: u64) {
        let latest = self.latest();
        let block = Block::new(
            latest.index + 1,
            timestamp,
            transactions,
            latest.hash.clone(),
        );
        if self.validate_block(&block) {
            self.chain.push(block.clone());
            self.storage
                .save_data(&block.index.to_string(), &serde_json::to_string(&block).unwrap())
                .unwrap();
        } else {
            println!("Block validation failed!");
        }
    }

    pub fn get_block_hash(&self, index: u64) -> Option<String> {
        self.chain.get(index as usize).map(|block| block.hash.clone())
    }

    // Sync logic methods
    pub fn get_chain_summary(&self) -> (u64, String, usize) {
        let latest = self.latest();
        (latest.index, latest.hash.clone(), self.chain.len())
    }

    pub fn is_chain_longer(&self, other_length: usize) -> bool {
        other_length > self.chain.len()
    }

    pub fn validate_chain(&self, chain: &[Block]) -> bool {
        if chain.is_empty() {
            return false;
        }

        // Check genesis block
        let genesis = &chain[0];
        if genesis.index != 0 || genesis.prev_hash != "0" {
            return false;
        }

        // Validate each subsequent block
        for i in 1..chain.len() {
            let current = &chain[i];
            let previous = &chain[i - 1];

            if current.index != previous.index + 1 {
                return false;
            }

            if current.prev_hash != previous.hash {
                return false;
            }

            // Validate block hash
            let expected_hash = self.calculate_block_hash(current);
            if current.hash != expected_hash {
                return false;
            }
        }

        true
    }

    pub fn calculate_block_hash(&self, block: &Block) -> String {
        let mut hasher = Sha256::new();
        hasher.update(block.index.to_le_bytes());
        hasher.update(block.timestamp.to_le_bytes());
        for tx in &block.transactions {
            hasher.update(serde_json::to_string(tx).unwrap().as_bytes());
        }
        hasher.update(block.prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn replace_chain(&mut self, new_chain: Vec<Block>) -> Result<(), String> {
        if !self.validate_chain(&new_chain) {
            return Err("Invalid chain received".to_string());
        }

        if new_chain.len() <= self.chain.len() {
            return Err("New chain is not longer than current chain".to_string());
        }

        println!("Replacing local chain with longer valid chain");
        self.chain = new_chain;

        // Save new chain to storage
        for block in &self.chain {
            let _ = self.storage.save_data(
                &block.index.to_string(),
                &serde_json::to_string(block).unwrap(),
            );
        }

        println!("Chain replaced successfully with {} blocks", self.chain.len());
        Ok(())
    }

    pub fn try_add_block(&mut self, block: Block) -> Result<(), String> {
        // Validate the block
        if !self.validate_block(&block) {
            return Err("Block validation failed".to_string());
        }

        // Check if we already have this block
        if let Some(existing_block) = self.chain.get(block.index as usize) {
            if existing_block.hash == block.hash {
                return Err("Block already exists".to_string());
            } else {
                return Err("Block index conflict".to_string());
            }
        }

        // Check if this block extends our chain
        if block.index != self.chain.len() as u64 {
            return Err("Block index does not extend chain".to_string());
        }

        self.chain.push(block.clone());
        self.storage
            .save_data(&block.index.to_string(), &serde_json::to_string(&block).unwrap())
            .unwrap();

        println!("Successfully added new block at index {}", block.index);
        Ok(())
    }

    pub fn get_blocks_range(&self, start_index: u64, end_index: u64) -> Vec<Block> {
        let start = start_index as usize;
        let end = std::cmp::min(end_index as usize + 1, self.chain.len());
        
        if start >= self.chain.len() || start > end {
            return vec![];
        }

        self.chain[start..end].to_vec()
    }

    pub fn needs_sync(&self, peer_height: u64, peer_hash: &str) -> bool {
        let local_height = self.latest().index;
        
        // If peer has more blocks, we need to sync
        if peer_height > local_height {
            return true;
        }

        // If same height but different hash, we have a conflict
        if peer_height == local_height && peer_hash != &self.latest().hash {
            return true;
        }

        false
    }

    pub fn resolve_chain_conflict(&mut self, peer_chain: Vec<Block>) -> Result<bool, String> {
        if !self.validate_chain(&peer_chain) {
            return Err("Peer chain is invalid".to_string());
        }

        let local_length = self.chain.len();
        let peer_length = peer_chain.len();

        if peer_length > local_length {
            // Peer has longer chain, replace ours
            self.replace_chain(peer_chain)?;
            Ok(true)
        } else if peer_length == local_length {
            // Same length, use the chain with the "better" hash (lexicographically smaller)
            let local_hash = &self.latest().hash;
            let peer_hash = &peer_chain.last().unwrap().hash;
            
            if peer_hash < local_hash {
                self.replace_chain(peer_chain)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            // Our chain is longer, keep it
            Ok(false)
        }
    }
}

pub enum AdminProposal {
    MintGT { amount: u64 },
    ChangePeg { new_rate: u64 },
}

impl AdminProposal {
    pub fn simulate_voting(&self) -> bool {
        match self {
            AdminProposal::MintGT { amount } => {
                println!("Voting on MintGT proposal for amount: {}", amount);
                true // Simulate approval
            }
            AdminProposal::ChangePeg { new_rate } => {
                println!("Voting on ChangePeg proposal for new rate: {}", new_rate);
                true // Simulate approval
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use std::fs;

    #[test]
    fn test_block_addition() {
        // Use a unique test database path
        let test_db_path = "test_db_block_addition";
        
        // Clean up any existing test database
        let _ = fs::remove_dir_all(test_db_path);
        
        let storage = Storage::new(test_db_path);
        let mut blockchain = Blockchain::new(storage);
        
        let tx = Transaction {
            sender: "TestSender".to_string(),
            receiver: "TestReceiver".to_string(),
            amount: 5,
            token_type: "ST".to_string(),
            signature: "test_signature".to_string(),
        };
        
        blockchain.add_block(vec![tx]);
        assert_eq!(blockchain.chain.len(), 2); // Genesis + Test block
        
        // Clean up test database
        let _ = fs::remove_dir_all(test_db_path);
    }

    #[test]
    fn test_block_validation() {
        let test_db_path = "test_db_validation";
        let _ = fs::remove_dir_all(test_db_path);
        
        let storage = Storage::new(test_db_path);
        let blockchain = Blockchain::new(storage);
        let genesis = blockchain.latest();
        
        let block = Block::new(
            genesis.index + 1,
            1234567890,
            vec![],
            genesis.hash.clone(),
        );
        
        assert!(blockchain.validate_block(&block));
        
        let _ = fs::remove_dir_all(test_db_path);
    }
}

pub struct MinimalBlockchain {
    pub chain: Vec<Block>,
}

impl MinimalBlockchain {
    pub fn new() -> Self {
        Self { chain: vec![] }
    }

    pub fn add_block(&mut self, block: Block) {
        self.chain.push(block);
    }

    pub fn latest_block(&self) -> Option<&Block> {
        self.chain.last()
    }
}
