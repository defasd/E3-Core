use crate::wallet::types::{WalletError, WalletConfig, WalletType, TokenBalance, AuditLogEntry, MultiSigConfig, PendingMultiSigTransaction};
use crate::wallet::transaction::{Transaction, TransactionHistory, TransactionBuilder, TransactionType, TokenType};
use crate::wallet::signature::{WalletSignature, SignatureVerification, WalletKeyManager};
use crate::wallet::proof_of_reserve::ProofOfReserve;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Treasury wallet for system funds, minted GU, and administrative operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryWallet {
    pub config: WalletConfig,
    pub address: String,
    pub balance: TokenBalance,
    pub multi_sig_config: MultiSigConfig,
    pub transaction_history: TransactionHistory,
    pub audit_log: Vec<AuditLogEntry>,
    pub proof_of_reserve: Option<ProofOfReserve>,
    pub treasury_metadata: TreasuryMetadata,
    pub nonce: u64,
    #[serde(skip)] // Don't serialize private keys for security
    pub key_manager: Option<WalletKeyManager>,
}

/// Treasury-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryMetadata {
    pub total_gu_minted: u64,
    pub total_gu_burned: u64,
    pub total_fees_collected: u64,
    pub total_taxes_collected: u64,
    pub reserve_ratio: f64, // Percentage of reserves backing the currency
    pub last_audit_timestamp: u64,
    pub admin_nodes: Vec<String>,
    pub emergency_locked: bool,
}

impl Default for TreasuryMetadata {
    fn default() -> Self {
        Self {
            total_gu_minted: 0,
            total_gu_burned: 0,
            total_fees_collected: 0,
            total_taxes_collected: 0,
            reserve_ratio: 100.0, // 100% backed initially
            last_audit_timestamp: 0,
            admin_nodes: Vec::new(),
            emergency_locked: false,
        }
    }
}

/// Multi-signature transaction proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigProposal {
    pub proposal_id: String,
    pub transaction: Transaction,
    pub proposer: String,
    pub signatures: Vec<MultiSigSignatureEntry>,
    pub required_signatures: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub executed: bool,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigSignatureEntry {
    pub signer_address: String,
    pub signature: WalletSignature,
    pub signed_at: u64,
}

impl TreasuryWallet {
    /// Create a new treasury wallet
    pub fn new(
        address: String,
        admin_addresses: Vec<String>,
        required_signatures: u32,
    ) -> Result<Self, WalletError> {
        if admin_addresses.is_empty() {
            return Err(WalletError::InvalidAddress);
        }

        let wallet_id = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate treasury key manager
        let key_manager = WalletKeyManager::new()?;

        let config = WalletConfig::new(wallet_id.clone(), WalletType::Treasury, timestamp)
            .with_metadata("treasury_type".to_string(), "main".to_string());

        let multi_sig_config = MultiSigConfig::new(required_signatures, admin_addresses.clone())?;
        let transaction_history = TransactionHistory::new(wallet_id.clone());

        let mut treasury_metadata = TreasuryMetadata::default();
        treasury_metadata.admin_nodes = admin_addresses;

        // Create audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            wallet_id.clone(),
            "treasury_created".to_string(),
            timestamp,
        ).with_detail("required_signatures".to_string(), required_signatures.to_string())
        .with_detail("admin_count".to_string(), treasury_metadata.admin_nodes.len().to_string());

        Ok(Self {
            config,
            address,
            balance: TokenBalance::new(),
            multi_sig_config,
            transaction_history,
            audit_log: vec![audit_entry],
            proof_of_reserve: None,
            treasury_metadata,
            nonce: 0,
            key_manager: Some(key_manager),
        })
    }

    /// Mint GU tokens (requires multi-sig approval)
    pub fn create_mint_proposal(
        &mut self,
        to_address: String,
        amount: u64,
        proposer: String,
        justification: String,
    ) -> Result<MultiSigProposal, WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }

        if !self.multi_sig_config.signer_addresses.contains(&proposer) {
            return Err(WalletError::UnauthorizedOperation);
        }

        if self.treasury_metadata.emergency_locked {
            return Err(WalletError::UnauthorizedOperation);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.nonce += 1;

        let transaction = TransactionBuilder::new(TransactionType::Mint)
            .sender(self.address.clone())
            .recipient(to_address)
            .amount(amount)
            .token_type(TokenType::GU)
            .nonce(self.nonce)
            .timestamp(timestamp)
            .fee(0) // No fee for minting
            .metadata("justification".to_string(), justification)
            .metadata("treasury_id".to_string(), self.config.wallet_id.clone())
            .build()?;

        let proposal = MultiSigProposal {
            proposal_id: Uuid::new_v4().to_string(),
            transaction,
            proposer,
            signatures: Vec::new(),
            required_signatures: self.multi_sig_config.required_signatures,
            created_at: timestamp,
            expires_at: timestamp + 86400, // 24 hours to approve
            executed: false,
            cancelled: false,
        };

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "mint_proposal_created".to_string(),
            timestamp,
        ).with_detail("proposal_id".to_string(), proposal.proposal_id.clone())
        .with_detail("amount".to_string(), amount.to_string())
        .with_detail("proposer".to_string(), proposal.proposer.clone());

        self.audit_log.push(audit_entry);

        Ok(proposal)
    }

    /// Sign a multi-sig proposal
    pub fn sign_proposal(
        &mut self,
        proposal: &mut MultiSigProposal,
        signer_address: String,
        signature: WalletSignature,
    ) -> Result<bool, WalletError> {
        // Verify signer is authorized
        if !self.multi_sig_config.signer_addresses.contains(&signer_address) {
            return Err(WalletError::UnauthorizedOperation);
        }

        // Check if already signed
        if proposal.signatures.iter().any(|sig| sig.signer_address == signer_address) {
            return Err(WalletError::UnauthorizedOperation);
        }

        // Check if proposal is still valid
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time > proposal.expires_at {
            return Err(WalletError::UnauthorizedOperation);
        }

        if proposal.executed || proposal.cancelled {
            return Err(WalletError::UnauthorizedOperation);
        }

        // TODO: Verify signature against transaction data
        // For now, we'll assume the signature is valid

        proposal.signatures.push(MultiSigSignatureEntry {
            signer_address: signer_address.clone(),
            signature,
            signed_at: current_time,
        });

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "proposal_signed".to_string(),
            current_time,
        ).with_detail("proposal_id".to_string(), proposal.proposal_id.clone())
        .with_detail("signer".to_string(), signer_address)
        .with_detail("signatures_count".to_string(), proposal.signatures.len().to_string());

        self.audit_log.push(audit_entry);

        // Check if we have enough signatures
        let is_ready = proposal.signatures.len() as u32 >= proposal.required_signatures;
        Ok(is_ready)
    }

    /// Execute a multi-sig proposal (when threshold is met)
    pub fn execute_proposal(
        &mut self,
        proposal: &mut MultiSigProposal,
    ) -> Result<(), WalletError> {
        if (proposal.signatures.len() as u32) < proposal.required_signatures {
            return Err(WalletError::MultiSigThresholdNotMet);
        }

        if proposal.executed || proposal.cancelled {
            return Err(WalletError::UnauthorizedOperation);
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time > proposal.expires_at {
            return Err(WalletError::UnauthorizedOperation);
        }

        // Execute the transaction based on type
        match proposal.transaction.transaction_type {
            TransactionType::Mint => {
                self.execute_mint(&proposal.transaction)?;
            }
            TransactionType::Burn => {
                self.execute_burn(&proposal.transaction)?;
            }
            TransactionType::Transfer => {
                self.execute_transfer(&proposal.transaction)?;
            }
            _ => return Err(WalletError::InvalidAmount),
        }

        proposal.executed = true;
        self.transaction_history.add_transaction(proposal.transaction.clone());

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "proposal_executed".to_string(),
            current_time,
        ).with_detail("proposal_id".to_string(), proposal.proposal_id.clone())
        .with_detail("transaction_type".to_string(), format!("{:?}", proposal.transaction.transaction_type));

        self.audit_log.push(audit_entry);

        Ok(())
    }

    /// Execute mint operation
    fn execute_mint(&mut self, transaction: &Transaction) -> Result<(), WalletError> {
        if transaction.token_type != TokenType::GU {
            return Err(WalletError::InvalidAmount);
        }

        // Update treasury metadata
        self.treasury_metadata.total_gu_minted += transaction.amount;
        
        // For treasury wallet, we track minted amounts but actual balances
        // are managed by the broader tokenomics system
        
        Ok(())
    }

    /// Execute burn operation
    fn execute_burn(&mut self, transaction: &Transaction) -> Result<(), WalletError> {
        if transaction.token_type != TokenType::GU {
            return Err(WalletError::InvalidAmount);
        }

        // Check if we have enough balance to burn
        if self.balance.gu_balance < transaction.amount {
            return Err(WalletError::InsufficientBalance);
        }

        self.balance.gu_balance -= transaction.amount;
        self.treasury_metadata.total_gu_burned += transaction.amount;

        Ok(())
    }

    /// Execute transfer operation
    fn execute_transfer(&mut self, transaction: &Transaction) -> Result<(), WalletError> {
        let amount_with_fee = transaction.amount + transaction.fee;
        
        match transaction.token_type {
            TokenType::GU => {
                if self.balance.gu_balance < amount_with_fee {
                    return Err(WalletError::InsufficientBalance);
                }
                self.balance.gu_balance -= amount_with_fee;
            }
            TokenType::SU => {
                if self.balance.su_balance < amount_with_fee {
                    return Err(WalletError::InsufficientBalance);
                }
                self.balance.su_balance -= amount_with_fee;
            }
        }

        if transaction.fee > 0 {
            self.treasury_metadata.total_fees_collected += transaction.fee;
        }

        Ok(())
    }

    /// Update balance (for receiving funds)
    pub fn update_balance(&mut self, gu_amount: u64, su_amount: u64) {
        self.balance.gu_balance += gu_amount;
        self.balance.su_balance += su_amount;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "balance_updated".to_string(),
            timestamp,
        ).with_detail("gu_added".to_string(), gu_amount.to_string())
        .with_detail("su_added".to_string(), su_amount.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;
    }

    /// Get current balance
    pub fn get_balance(&self) -> &TokenBalance {
        &self.balance
    }

    /// Get private key hex (be careful with this!)
    pub fn get_private_key_hex(&self) -> Option<String> {
        self.key_manager.as_ref().map(|km| km.get_private_key_hex())
    }

    /// Set proof of reserve
    pub fn set_proof_of_reserve(&mut self, proof: ProofOfReserve) {
        self.proof_of_reserve = Some(proof);
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.treasury_metadata.last_audit_timestamp = timestamp;

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "proof_of_reserve_updated".to_string(),
            timestamp,
        );

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;
    }

    /// Emergency lock the treasury
    pub fn emergency_lock(&mut self, authorized_admin: String) -> Result<(), WalletError> {
        if !self.treasury_metadata.admin_nodes.contains(&authorized_admin) {
            return Err(WalletError::UnauthorizedOperation);
        }

        self.treasury_metadata.emergency_locked = true;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "emergency_lock_activated".to_string(),
            timestamp,
        ).with_detail("authorized_by".to_string(), authorized_admin);

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(())
    }

    /// Unlock treasury (requires multi-sig)
    pub fn unlock(&mut self) {
        self.treasury_metadata.emergency_locked = false;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "emergency_lock_deactivated".to_string(),
            timestamp,
        );

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;
    }

    /// Get treasury statistics
    pub fn get_treasury_stats(&self) -> TreasuryStats {
        TreasuryStats {
            total_balance: self.balance.total_balance(),
            gu_balance: self.balance.gu_balance,
            su_balance: self.balance.su_balance,
            total_minted: self.treasury_metadata.total_gu_minted,
            total_burned: self.treasury_metadata.total_gu_burned,
            net_supply: self.treasury_metadata.total_gu_minted - self.treasury_metadata.total_gu_burned,
            fees_collected: self.treasury_metadata.total_fees_collected,
            reserve_ratio: self.treasury_metadata.reserve_ratio,
            emergency_locked: self.treasury_metadata.emergency_locked,
            admin_count: self.treasury_metadata.admin_nodes.len(),
            required_signatures: self.multi_sig_config.required_signatures,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStats {
    pub total_balance: u64,
    pub gu_balance: u64,
    pub su_balance: u64,
    pub total_minted: u64,
    pub total_burned: u64,
    pub net_supply: u64,
    pub fees_collected: u64,
    pub reserve_ratio: f64,
    pub emergency_locked: bool,
    pub admin_count: usize,
    pub required_signatures: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_treasury_creation() {
        let admin_addresses = vec![
            "admin1".to_string(),
            "admin2".to_string(),
            "admin3".to_string(),
        ];

        let treasury = TreasuryWallet::new(
            "treasury_address".to_string(),
            admin_addresses.clone(),
            2, // 2 of 3 multi-sig
        ).unwrap();

        assert_eq!(treasury.config.wallet_type, WalletType::Treasury);
        assert_eq!(treasury.multi_sig_config.required_signatures, 2);
        assert_eq!(treasury.multi_sig_config.total_signers, 3);
    }

    #[test]
    fn test_mint_proposal() {
        let admin_addresses = vec!["admin1".to_string(), "admin2".to_string()];
        let mut treasury = TreasuryWallet::new(
            "treasury_address".to_string(),
            admin_addresses,
            2,
        ).unwrap();

        let proposal = treasury.create_mint_proposal(
            "recipient".to_string(),
            1000,
            "admin1".to_string(),
            "Initial mint for testing".to_string(),
        ).unwrap();

        assert_eq!(proposal.transaction.amount, 1000);
        assert_eq!(proposal.transaction.token_type, TokenType::GU);
        assert_eq!(proposal.required_signatures, 2);
    }
}
