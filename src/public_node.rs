// src/public/public_node.rs
// PublicNode struct: user/public logic

use crate::node::Node;
use crate::blockchain::Transaction;

pub struct PublicNode {
    pub node: Node,
    // Add public-specific fields here (e.g., tokenomics state, chain health)
}

impl PublicNode {
    pub fn new(db_path: String, port: u16) -> Self {
        PublicNode {
            node: Node::new(db_path, port),
        }
    }

    // Example: submit a user transaction
    pub fn submit_transaction(&self, sender: String, receiver: String, amount: u64, token_type: String) {
        let tx = Transaction {
            sender,
            receiver,
            amount,
            token_type,
            signature: "user_signature".to_string(),
        };
        self.node.add_block_with_time(vec![tx], 0); // Use real timestamp in production
        println!("User transaction submitted.");
    }

    // Add more public-only methods (challenge admin, request redemption, etc.)

    pub fn print_chain(&self) {
        self.node.print_chain();
    }
}
