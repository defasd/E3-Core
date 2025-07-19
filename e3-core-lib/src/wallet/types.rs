use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Wallet-related errors
#[derive(Debug, Clone)]
pub enum WalletError {
    InvalidSignature,
    InsufficientBalance,
    InvalidAmount,
    InvalidAddress,
    NonceAlreadyUsed,
    UnauthorizedOperation,
    WalletNotFound,
    InvalidWalletType,
    MultiSigThresholdNotMet,
    ProofOfReserveInvalid,
    TransactionFailed,
    KeyGenerationFailed,
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WalletError::InvalidSignature => write!(f, "Invalid signature"),
            WalletError::InsufficientBalance => write!(f, "Insufficient balance"),
            WalletError::InvalidAmount => write!(f, "Invalid amount"),
            WalletError::InvalidAddress => write!(f, "Invalid address"),
            WalletError::NonceAlreadyUsed => write!(f, "Nonce already used"),
            WalletError::UnauthorizedOperation => write!(f, "Unauthorized operation"),
            WalletError::WalletNotFound => write!(f, "Wallet not found"),
            WalletError::InvalidWalletType => write!(f, "Invalid wallet type"),
            WalletError::MultiSigThresholdNotMet => write!(f, "Multi-signature threshold not met"),
            WalletError::ProofOfReserveInvalid => write!(f, "Proof of reserve validation failed"),
            WalletError::TransactionFailed => write!(f, "Transaction failed"),
            WalletError::KeyGenerationFailed => write!(f, "Key generation failed"),
            WalletError::EncryptionFailed => write!(f, "Encryption failed"),
            WalletError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl Error for WalletError {}

/// Types of wallets in the E3 system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WalletType {
    User,
    Treasury,
    Validator,
    Merchant,
}

/// Token balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub gu_balance: u64,  // Gold Units
    pub su_balance: u64,  // Standard Units
}

impl TokenBalance {
    pub fn new() -> Self {
        Self {
            gu_balance: 0,
            su_balance: 0,
        }
    }

    pub fn total_balance(&self) -> u64 {
        self.gu_balance + self.su_balance
    }
}

/// Address information for multi-address wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddress {
    pub address: String,
    pub label: Option<String>,
    pub is_primary: bool,
    pub created_at: u64,
    pub balance: TokenBalance,
    pub nonce: u64,
}

impl WalletAddress {
    pub fn new(address: String, is_primary: bool, timestamp: u64) -> Self {
        Self {
            address,
            label: None,
            is_primary,
            created_at: timestamp,
            balance: TokenBalance::new(),
            nonce: 0,
        }
    }

    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }
}

/// Base wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub wallet_id: String,
    pub wallet_type: WalletType,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_active: bool,
    pub metadata: HashMap<String, String>,
}

impl WalletConfig {
    pub fn new(wallet_id: String, wallet_type: WalletType, timestamp: u64) -> Self {
        Self {
            wallet_id,
            wallet_type,
            created_at: timestamp,
            updated_at: timestamp,
            is_active: true,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Multi-signature configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigConfig {
    pub required_signatures: u32,
    pub total_signers: u32,
    pub signer_addresses: Vec<String>,
    pub pending_transactions: HashMap<String, PendingMultiSigTransaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMultiSigTransaction {
    pub transaction_id: String,
    pub signatures_received: u32,
    pub signers: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

impl MultiSigConfig {
    pub fn new(required_signatures: u32, signer_addresses: Vec<String>) -> Result<Self, WalletError> {
        let total_signers = signer_addresses.len() as u32;
        
        if required_signatures == 0 || required_signatures > total_signers {
            return Err(WalletError::InvalidAmount);
        }

        Ok(Self {
            required_signatures,
            total_signers,
            signer_addresses,
            pending_transactions: HashMap::new(),
        })
    }

    pub fn is_threshold_met(&self, signatures_count: u32) -> bool {
        signatures_count >= self.required_signatures
    }
}

/// Audit log entry for wallet operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub entry_id: String,
    pub wallet_id: String,
    pub operation: String,
    pub details: HashMap<String, String>,
    pub timestamp: u64,
    pub block_height: Option<u64>,
    pub transaction_hash: Option<String>,
}

impl AuditLogEntry {
    pub fn new(
        entry_id: String,
        wallet_id: String,
        operation: String,
        timestamp: u64,
    ) -> Self {
        Self {
            entry_id,
            wallet_id,
            operation,
            details: HashMap::new(),
            timestamp,
            block_height: None,
            transaction_hash: None,
        }
    }

    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }

    pub fn with_block_info(mut self, block_height: u64, transaction_hash: String) -> Self {
        self.block_height = Some(block_height);
        self.transaction_hash = Some(transaction_hash);
        self
    }
}
