use crate::wallet::types::{WalletError, TokenBalance};
use crate::wallet::signature::WalletSignature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Cancelled,
}

/// Transaction type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    Transfer,
    Mint,
    Burn,
    Stake,
    Unstake,
    Reward,
    Fee,
    MultiSigApproval,
}

/// Token type for transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    GU, // Gold Units
    SU, // Standard Units
}

impl ToString for TokenType {
    fn to_string(&self) -> String {
        match self {
            TokenType::GU => "GU".to_string(),
            TokenType::SU => "SU".to_string(),
        }
    }
}

/// Core transaction structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub transaction_type: TransactionType,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub token_type: TokenType,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: Option<WalletSignature>,
    pub status: TransactionStatus,
    pub fee: u64,
    pub metadata: HashMap<String, String>,
    pub block_height: Option<u64>,
    pub confirmation_time: Option<u64>,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        transaction_type: TransactionType,
        sender: String,
        recipient: String,
        amount: u64,
        token_type: TokenType,
        nonce: u64,
        timestamp: u64,
        fee: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            transaction_type,
            sender,
            recipient,
            amount,
            token_type,
            nonce,
            timestamp,
            signature: None,
            status: TransactionStatus::Pending,
            fee,
            metadata: HashMap::new(),
            block_height: None,
            confirmation_time: None,
        }
    }

    /// Add signature to transaction
    pub fn with_signature(mut self, signature: WalletSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Add metadata to transaction
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Mark transaction as confirmed
    pub fn confirm(&mut self, block_height: u64, confirmation_time: u64) {
        self.status = TransactionStatus::Confirmed;
        self.block_height = Some(block_height);
        self.confirmation_time = Some(confirmation_time);
    }

    /// Mark transaction as failed
    pub fn fail(&mut self) {
        self.status = TransactionStatus::Failed;
    }

    /// Check if transaction is ready for processing
    pub fn is_ready_for_processing(&self) -> bool {
        self.signature.is_some() && self.status == TransactionStatus::Pending
    }

    /// Get transaction hash for signing
    pub fn get_signing_data(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(self.sender.as_bytes());
        hasher.update(self.recipient.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(self.token_type.to_string().as_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

/// Transaction builder for easier creation
pub struct TransactionBuilder {
    transaction_type: TransactionType,
    sender: Option<String>,
    recipient: Option<String>,
    amount: Option<u64>,
    token_type: Option<TokenType>,
    nonce: Option<u64>,
    timestamp: Option<u64>,
    fee: Option<u64>,
    metadata: HashMap<String, String>,
}

impl TransactionBuilder {
    pub fn new(transaction_type: TransactionType) -> Self {
        Self {
            transaction_type,
            sender: None,
            recipient: None,
            amount: None,
            token_type: None,
            nonce: None,
            timestamp: None,
            fee: None,
            metadata: HashMap::new(),
        }
    }

    pub fn sender(mut self, sender: String) -> Self {
        self.sender = Some(sender);
        self
    }

    pub fn recipient(mut self, recipient: String) -> Self {
        self.recipient = Some(recipient);
        self
    }

    pub fn amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn token_type(mut self, token_type: TokenType) -> Self {
        self.token_type = Some(token_type);
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    pub fn metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub fn build(self) -> Result<Transaction, WalletError> {
        let sender = self.sender.ok_or(WalletError::InvalidAddress)?;
        let recipient = self.recipient.ok_or(WalletError::InvalidAddress)?;
        let amount = self.amount.ok_or(WalletError::InvalidAmount)?;
        let token_type = self.token_type.ok_or(WalletError::InvalidAmount)?;
        let nonce = self.nonce.ok_or(WalletError::InvalidAmount)?;
        let timestamp = self.timestamp.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        let fee = self.fee.unwrap_or(0);

        let mut transaction = Transaction::new(
            self.transaction_type,
            sender,
            recipient,
            amount,
            token_type,
            nonce,
            timestamp,
            fee,
        );

        // Add metadata
        for (key, value) in self.metadata {
            transaction.metadata.insert(key, value);
        }

        Ok(transaction)
    }
}

/// Transaction history and management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistory {
    pub wallet_id: String,
    pub transactions: Vec<Transaction>,
    pub total_sent: TokenBalance,
    pub total_received: TokenBalance,
    pub total_fees_paid: u64,
}

impl TransactionHistory {
    pub fn new(wallet_id: String) -> Self {
        Self {
            wallet_id,
            transactions: Vec::new(),
            total_sent: TokenBalance::new(),
            total_received: TokenBalance::new(),
            total_fees_paid: 0,
        }
    }

    /// Add a transaction to history
    pub fn add_transaction(&mut self, transaction: Transaction) {
        // Update totals based on transaction
        if transaction.sender == self.wallet_id {
            // Outgoing transaction
            match transaction.token_type {
                TokenType::GU => self.total_sent.gu_balance += transaction.amount,
                TokenType::SU => self.total_sent.su_balance += transaction.amount,
            }
            self.total_fees_paid += transaction.fee;
        }

        if transaction.recipient == self.wallet_id {
            // Incoming transaction
            match transaction.token_type {
                TokenType::GU => self.total_received.gu_balance += transaction.amount,
                TokenType::SU => self.total_received.su_balance += transaction.amount,
            }
        }

        self.transactions.push(transaction);
        
        // Keep only last 1000 transactions (can be configurable)
        if self.transactions.len() > 1000 {
            self.transactions.drain(..self.transactions.len() - 1000);
        }
    }

    /// Get transactions by status
    pub fn get_transactions_by_status(&self, status: TransactionStatus) -> Vec<&Transaction> {
        self.transactions.iter()
            .filter(|tx| tx.status == status)
            .collect()
    }

    /// Get recent transactions (last n)
    pub fn get_recent_transactions(&self, count: usize) -> Vec<&Transaction> {
        let start = if self.transactions.len() > count {
            self.transactions.len() - count
        } else {
            0
        };
        self.transactions[start..].iter().collect()
    }

    /// Get transactions within a time range
    pub fn get_transactions_in_range(&self, start_time: u64, end_time: u64) -> Vec<&Transaction> {
        self.transactions.iter()
            .filter(|tx| tx.timestamp >= start_time && tx.timestamp <= end_time)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let tx = TransactionBuilder::new(TransactionType::Transfer)
            .sender("sender_address".to_string())
            .recipient("recipient_address".to_string())
            .amount(1000)
            .token_type(TokenType::GU)
            .nonce(1)
            .fee(10)
            .build()
            .unwrap();

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.token_type, TokenType::GU);
        assert_eq!(tx.status, TransactionStatus::Pending);
    }

    #[test]
    fn test_transaction_history() {
        let mut history = TransactionHistory::new("wallet_123".to_string());
        
        let tx = TransactionBuilder::new(TransactionType::Transfer)
            .sender("wallet_123".to_string())
            .recipient("other_wallet".to_string())
            .amount(500)
            .token_type(TokenType::GU)
            .nonce(1)
            .fee(5)
            .build()
            .unwrap();

        history.add_transaction(tx);
        
        assert_eq!(history.total_sent.gu_balance, 500);
        assert_eq!(history.total_fees_paid, 5);
        assert_eq!(history.transactions.len(), 1);
    }
}
