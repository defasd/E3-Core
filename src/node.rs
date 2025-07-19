// src/node.rs
// Shared Node struct and logic for both AdminNode and PublicNode

use crate::blockchain::{Blockchain, Transaction};
use crate::storage::Storage;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Node {
    pub blockchain: Arc<Mutex<Blockchain>>,
    pub db_path: String,
    pub port: u16,
}

impl Node {
    pub fn new(db_path: String, port: u16) -> Self {
        let storage = Storage::new(&db_path);
        let blockchain = Arc::new(Mutex::new(Blockchain::new(storage)));
        Node {
            blockchain,
            db_path,
            port,
        }
    }

    // Add more shared methods as needed
    pub fn add_block_with_time(&self, transactions: Vec<Transaction>, timestamp: u64) {
        let mut bc = self.blockchain.lock().unwrap();
        bc.add_block_with_time(transactions, timestamp);
    }

    pub fn handle_admin_mint(&mut self, to: &str, amount: u64) {
        // Handle admin mint operation
        let transaction = Transaction {
            sender: "admin".to_string(),
            receiver: to.to_string(),
            amount,
            token_type: "ST".to_string(), // Standard token
            signature: "admin_mint".to_string(),
        };
        
        let mut blockchain = self.blockchain.lock().unwrap();
        blockchain.add_block(vec![transaction]);
        println!("Admin mint processed: {} tokens to {}", amount, to);
    }

    pub fn handle_admin_burn(&mut self, from: &str, amount: u64) {
        // Handle admin burn operation
        let transaction = Transaction {
            sender: from.to_string(),
            receiver: "admin_burn".to_string(),
            amount,
            token_type: "ST".to_string(), // Standard token
            signature: "admin_burn".to_string(),
        };
        
        let mut blockchain = self.blockchain.lock().unwrap();
        blockchain.add_block(vec![transaction]);
        println!("Admin burn processed: {} tokens from {}", amount, from);
    }

    pub fn print_chain(&self) {
        for block in self.blockchain.lock().unwrap().chain.iter() {
            println!("{:#?}", block);
        }
    }
    
    pub fn get_chain_summary(&self) -> String {
        let blockchain = self.blockchain.lock().unwrap();
        if let Some(latest_block) = blockchain.chain.last() {
            format!("Latest block: {}, Chain length: {}", latest_block.hash, blockchain.chain.len())
        } else {
            "Empty chain".to_string()
        }
    }
}
