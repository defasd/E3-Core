// src/admin/admin_node.rs
// AdminNode struct: privileged admin logic

use crate::node::Node;
use crate::blockchain::{Transaction, AdminProposal};

pub struct AdminNode {
    pub node: Node,
    // Add admin-specific fields here (e.g., admin keys, proof state)
}

impl AdminNode {
    pub fn new(db_path: String, port: u16) -> Self {
        AdminNode {
            node: Node::new(db_path, port),
        }
    }

    // Example: privileged mint GT (Gold Token)
    pub fn mint_gt(&self, amount: u64) {
        // Simulate proof of reserve and voting
        let proposal = AdminProposal::MintGT { amount };
        if proposal.simulate_voting() {
            let tx = Transaction {
                sender: "Admin".to_string(),
                receiver: "Treasury".to_string(),
                amount,
                token_type: "GT".to_string(),
                signature: "admin_signature".to_string(),
            };
            self.node.add_block_with_time(vec![tx], 0); // Use real timestamp in production
            println!("Minted {} GT after admin approval.", amount);
        } else {
            println!("Mint GT proposal was rejected.");
        }
    }

    // Add more admin-only methods (proof of reserve, proposals, etc.)

    pub fn print_chain(&self) {
        self.node.print_chain();
    }
}
