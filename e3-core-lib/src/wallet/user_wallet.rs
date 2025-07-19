use crate::wallet::types::{WalletError, WalletConfig, WalletType, WalletAddress, TokenBalance, AuditLogEntry};
use crate::wallet::transaction::{Transaction, TransactionHistory, TransactionBuilder, TransactionType, TokenType, TransactionStatus};
use crate::wallet::signature::{WalletKeyManager, SignatureVerification, WalletSignature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// User wallet for personal transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserWallet {
    pub config: WalletConfig,
    pub did_id: Option<String>, // Decentralized Identifier
    pub addresses: Vec<WalletAddress>,
    pub primary_address_index: usize,
    pub transaction_history: TransactionHistory,
    pub audit_log: Vec<AuditLogEntry>,
    pub settings: UserWalletSettings,
    #[serde(skip)] // Don't serialize private keys for security
    pub key_manager: Option<WalletKeyManager>,
}

/// User wallet settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserWalletSettings {
    pub auto_backup: bool,
    pub transaction_notifications: bool,
    pub max_transaction_amount: Option<u64>,
    pub daily_spending_limit: Option<u64>,
    pub require_confirmation_above: Option<u64>,
    pub preferred_token: TokenType,
}

impl Default for UserWalletSettings {
    fn default() -> Self {
        Self {
            auto_backup: true,
            transaction_notifications: true,
            max_transaction_amount: None,
            daily_spending_limit: None,
            require_confirmation_above: Some(10000), // Require confirmation for amounts > 10000
            preferred_token: TokenType::SU,
        }
    }
}

impl UserWallet {
    /// Create a new user wallet
    pub fn new(did_id: Option<String>) -> Result<Self, WalletError> {
        let wallet_id = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate primary address
        let key_manager = WalletKeyManager::new()?;
        let primary_address = WalletAddress::new(
            key_manager.get_address().to_string(),
            true,
            timestamp,
        ).with_label("Primary".to_string());

        let config = WalletConfig::new(wallet_id.clone(), WalletType::User, timestamp);
        let transaction_history = TransactionHistory::new(wallet_id.clone());

        // Create audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            wallet_id.clone(),
            "wallet_created".to_string(),
            timestamp,
        ).with_detail("did_id".to_string(), did_id.clone().unwrap_or("none".to_string()));

        Ok(Self {
            config,
            did_id,
            addresses: vec![primary_address],
            primary_address_index: 0,
            transaction_history,
            audit_log: vec![audit_entry],
            settings: UserWalletSettings::default(),
            key_manager: Some(key_manager),
        })
    }

    /// Create from existing configuration
    pub fn from_config(
        config: WalletConfig,
        did_id: Option<String>,
        addresses: Vec<WalletAddress>,
        primary_address_index: usize,
    ) -> Result<Self, WalletError> {
        if addresses.is_empty() {
            return Err(WalletError::InvalidAddress);
        }
        
        if primary_address_index >= addresses.len() {
            return Err(WalletError::InvalidAddress);
        }

        let transaction_history = TransactionHistory::new(config.wallet_id.clone());

        Ok(Self {
            config,
            did_id,
            addresses,
            primary_address_index,
            transaction_history,
            audit_log: Vec::new(),
            settings: UserWalletSettings::default(),
            key_manager: None, // No key manager for from_config constructor
        })
    }

    /// Get primary address
    pub fn get_primary_address(&self) -> &WalletAddress {
        &self.addresses[self.primary_address_index]
    }

    /// Get primary address string
    pub fn get_primary_address_string(&self) -> &str {
        &self.addresses[self.primary_address_index].address
    }

    /// Add a new address to the wallet
    pub fn add_address(&mut self, label: Option<String>) -> Result<String, WalletError> {
        let key_manager = WalletKeyManager::new()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut new_address = WalletAddress::new(
            key_manager.get_address().to_string(),
            false,
            timestamp,
        );

        if let Some(label) = label {
            new_address = new_address.with_label(label);
        }

        let address_string = new_address.address.clone();
        self.addresses.push(new_address);

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "address_added".to_string(),
            timestamp,
        ).with_detail("new_address".to_string(), address_string.clone());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(address_string)
    }

    /// Get total balance across all addresses
    pub fn get_total_balance(&self) -> TokenBalance {
        let mut total = TokenBalance::new();
        
        for address in &self.addresses {
            total.gu_balance += address.balance.gu_balance;
            total.su_balance += address.balance.su_balance;
        }
        
        total
    }

    /// Get private key hex (be careful with this!)
    pub fn get_private_key_hex(&self) -> Option<String> {
        self.key_manager.as_ref().map(|km| km.get_private_key_hex())
    }

    /// Get balance for a specific address
    pub fn get_address_balance(&self, address: &str) -> Result<&TokenBalance, WalletError> {
        let wallet_address = self.addresses.iter()
            .find(|addr| addr.address == address)
            .ok_or(WalletError::InvalidAddress)?;
        
        Ok(&wallet_address.balance)
    }

    /// Update balance for an address
    pub fn update_address_balance(
        &mut self,
        address: &str,
        gu_balance: u64,
        su_balance: u64,
    ) -> Result<(), WalletError> {
        let wallet_address = self.addresses.iter_mut()
            .find(|addr| addr.address == address)
            .ok_or(WalletError::InvalidAddress)?;

        wallet_address.balance.gu_balance = gu_balance;
        wallet_address.balance.su_balance = su_balance;

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
        ).with_detail("address".to_string(), address.to_string())
        .with_detail("gu_balance".to_string(), gu_balance.to_string())
        .with_detail("su_balance".to_string(), su_balance.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(())
    }

    /// Get next nonce for an address
    pub fn get_next_nonce(&mut self, address: &str) -> Result<u64, WalletError> {
        let wallet_address = self.addresses.iter_mut()
            .find(|addr| addr.address == address)
            .ok_or(WalletError::InvalidAddress)?;

        wallet_address.nonce += 1;
        Ok(wallet_address.nonce)
    }

    /// Create a transfer transaction
    pub fn create_transfer(
        &mut self,
        from_address: &str,
        to_address: &str,
        amount: u64,
        token_type: TokenType,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        // Validate amount
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }

        // Check if we have the address
        let from_wallet_address = self.addresses.iter()
            .find(|addr| addr.address == from_address)
            .ok_or(WalletError::InvalidAddress)?;

        // Check balance
        let available_balance = match token_type {
            TokenType::GU => from_wallet_address.balance.gu_balance,
            TokenType::SU => from_wallet_address.balance.su_balance,
        };

        if available_balance < amount + fee {
            return Err(WalletError::InsufficientBalance);
        }

        // Check spending limits
        if let Some(max_amount) = self.settings.max_transaction_amount {
            if amount > max_amount {
                return Err(WalletError::UnauthorizedOperation);
            }
        }

        let nonce = self.get_next_nonce(from_address)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let transaction = TransactionBuilder::new(TransactionType::Transfer)
            .sender(from_address.to_string())
            .recipient(to_address.to_string())
            .amount(amount)
            .token_type(token_type.clone())
            .nonce(nonce)
            .timestamp(timestamp)
            .fee(fee)
            .metadata("wallet_id".to_string(), self.config.wallet_id.clone())
            .build()?;

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "transaction_created".to_string(),
            timestamp,
        ).with_detail("transaction_id".to_string(), transaction.id.clone())
        .with_detail("amount".to_string(), amount.to_string())
        .with_detail("token_type".to_string(), token_type.to_string());

        self.audit_log.push(audit_entry);

        Ok(transaction)
    }

    /// Sign a transaction (requires private key - this is simplified)
    pub fn sign_transaction(
        &self,
        transaction: &mut Transaction,
        key_manager: &WalletKeyManager,
    ) -> Result<(), WalletError> {
        // Verify the transaction sender matches one of our addresses
        if !self.addresses.iter().any(|addr| addr.address == transaction.sender) {
            return Err(WalletError::UnauthorizedOperation);
        }

        // Verify the key manager address matches the transaction sender
        if key_manager.get_address() != transaction.sender {
            return Err(WalletError::UnauthorizedOperation);
        }

        let signature = key_manager.sign_transaction(
            &transaction.recipient,
            transaction.amount,
            &transaction.token_type.to_string(),
            transaction.nonce,
            transaction.timestamp,
        )?;

        transaction.signature = Some(signature);
        Ok(())
    }

    /// Add a transaction to history
    pub fn add_transaction_to_history(&mut self, transaction: Transaction) {
        self.transaction_history.add_transaction(transaction);
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.config.updated_at = timestamp;
    }

    /// Get transaction history
    pub fn get_transaction_history(&self) -> &TransactionHistory {
        &self.transaction_history
    }

    /// Update wallet settings
    pub fn update_settings(&mut self, settings: UserWalletSettings) {
        self.settings = settings;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "settings_updated".to_string(),
            timestamp,
        );

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;
    }

    /// Check if wallet is active
    pub fn is_active(&self) -> bool {
        self.config.is_active
    }

    /// Deactivate wallet
    pub fn deactivate(&mut self) {
        self.config.is_active = false;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "wallet_deactivated".to_string(),
            timestamp,
        );

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;
    }

    /// Get audit log
    pub fn get_audit_log(&self) -> &[AuditLogEntry] {
        &self.audit_log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_wallet_creation() {
        let wallet = UserWallet::new(Some("did:e3:user123".to_string())).unwrap();
        
        assert_eq!(wallet.config.wallet_type, WalletType::User);
        assert_eq!(wallet.addresses.len(), 1);
        assert!(wallet.addresses[0].is_primary);
        assert!(wallet.is_active());
    }

    #[test]
    fn test_add_address() {
        let mut wallet = UserWallet::new(None).unwrap();
        let new_address = wallet.add_address(Some("Secondary".to_string())).unwrap();
        
        assert_eq!(wallet.addresses.len(), 2);
        assert!(!wallet.addresses[1].is_primary);
        assert_eq!(wallet.addresses[1].label, Some("Secondary".to_string()));
    }

    #[test]
    fn test_create_transfer() {
        let mut wallet = UserWallet::new(None).unwrap();
        let primary_address = wallet.get_primary_address_string().to_string();
        
        // Set some balance first
        wallet.update_address_balance(&primary_address, 1000, 500).unwrap();
        
        let transaction = wallet.create_transfer(
            &primary_address,
            "recipient_address",
            100,
            TokenType::GU,
            10,
        ).unwrap();
        
        assert_eq!(transaction.amount, 100);
        assert_eq!(transaction.token_type, TokenType::GU);
        assert_eq!(transaction.sender, primary_address);
    }
}
