use crate::wallet::*;
use crate::wallet::transaction::{TransactionType, TokenType};
use crate::tokens::{GoldUnit, StandardUnit};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Central wallet management system for E3
#[derive(Debug)]
pub struct WalletManager {
    user_wallets: Arc<Mutex<HashMap<String, UserWallet>>>,
    treasury_wallets: Arc<Mutex<HashMap<String, TreasuryWallet>>>,
    validator_wallets: Arc<Mutex<HashMap<String, ValidatorWallet>>>,
    merchant_wallets: Arc<Mutex<HashMap<String, MerchantWallet>>>,
    signature_verification: SignatureVerification,
}

impl WalletManager {
    /// Create a new wallet manager
    pub fn new() -> Self {
        Self {
            user_wallets: Arc::new(Mutex::new(HashMap::new())),
            treasury_wallets: Arc::new(Mutex::new(HashMap::new())),
            validator_wallets: Arc::new(Mutex::new(HashMap::new())),
            merchant_wallets: Arc::new(Mutex::new(HashMap::new())),
            signature_verification: SignatureVerification,
        }
    }

    /// Create a new user wallet
    pub fn create_user_wallet(&self, did_id: Option<String>) -> Result<String, WalletError> {
        let wallet = UserWallet::new(did_id)?;
        let wallet_id = wallet.config.wallet_id.clone();
        
        let mut user_wallets = self.user_wallets.lock().unwrap();
        user_wallets.insert(wallet_id.clone(), wallet);
        
        Ok(wallet_id)
    }

    /// Create a new treasury wallet
    pub fn create_treasury_wallet(
        &self,
        address: String,
        admin_addresses: Vec<String>,
        required_signatures: u32,
    ) -> Result<String, WalletError> {
        let wallet = TreasuryWallet::new(address, admin_addresses, required_signatures)?;
        let wallet_id = wallet.config.wallet_id.clone();
        
        let mut treasury_wallets = self.treasury_wallets.lock().unwrap();
        treasury_wallets.insert(wallet_id.clone(), wallet);
        
        Ok(wallet_id)
    }

    /// Create a new validator wallet
    pub fn create_validator_wallet(
        &self,
        operator_id: String,
        validator_name: String,
        public_key: Vec<u8>,
        minimum_stake: u64,
        commission_rate: f64,
    ) -> Result<String, WalletError> {
        let wallet = ValidatorWallet::new(
            operator_id,
            validator_name,
            public_key,
            minimum_stake,
            commission_rate,
        )?;
        let wallet_id = wallet.config.wallet_id.clone();
        
        let mut validator_wallets = self.validator_wallets.lock().unwrap();
        validator_wallets.insert(wallet_id.clone(), wallet);
        
        Ok(wallet_id)
    }

    /// Create a new merchant wallet
    pub fn create_merchant_wallet(
        &self,
        merchant_info: crate::wallet::merchant_wallet::MerchantInfo,
    ) -> Result<String, WalletError> {
        let wallet = MerchantWallet::new(merchant_info)?;
        let wallet_id = wallet.config.wallet_id.clone();
        
        let mut merchant_wallets = self.merchant_wallets.lock().unwrap();
        merchant_wallets.insert(wallet_id.clone(), wallet);
        
        Ok(wallet_id)
    }

    /// Create a new user wallet and return the wallet ID and private key
    pub fn create_user_wallet_with_key(&self, did_id: Option<String>) -> Result<(String, String), WalletError> {
        let wallet = UserWallet::new(did_id)?;
        let wallet_id = wallet.config.wallet_id.clone();
        let private_key = wallet.get_private_key_hex().unwrap_or_else(|| "no_key".to_string());
        
        let mut user_wallets = self.user_wallets.lock().unwrap();
        user_wallets.insert(wallet_id.clone(), wallet);
        
        Ok((wallet_id, private_key))
    }

    /// Create a new treasury wallet and return the wallet ID and private key
    pub fn create_treasury_wallet_with_key(
        &self,
        address: String,
        admin_addresses: Vec<String>,
        required_signatures: u32,
    ) -> Result<(String, String), WalletError> {
        let wallet = TreasuryWallet::new(address, admin_addresses, required_signatures)?;
        let wallet_id = wallet.config.wallet_id.clone();
        let private_key = wallet.get_private_key_hex().unwrap_or_else(|| "no_key".to_string());
        
        let mut treasury_wallets = self.treasury_wallets.lock().unwrap();
        treasury_wallets.insert(wallet_id.clone(), wallet);
        
        Ok((wallet_id, private_key))
    }

    /// Create a new validator wallet and return the wallet ID and private key
    pub fn create_validator_wallet_with_key(
        &self,
        operator_id: String,
        validator_name: String,
        public_key: Vec<u8>,
        minimum_stake: u64,
        commission_rate: f64,
    ) -> Result<(String, String), WalletError> {
        let wallet = ValidatorWallet::new(
            operator_id,
            validator_name,
            public_key,
            minimum_stake,
            commission_rate,
        )?;
        let wallet_id = wallet.config.wallet_id.clone();
        let private_key = wallet.get_private_key_hex().unwrap_or_else(|| "no_key".to_string());
        
        let mut validator_wallets = self.validator_wallets.lock().unwrap();
        validator_wallets.insert(wallet_id.clone(), wallet);
        
        Ok((wallet_id, private_key))
    }

    /// Create a new merchant wallet and return the wallet ID and private key
    pub fn create_merchant_wallet_with_key(
        &self,
        merchant_info: crate::wallet::merchant_wallet::MerchantInfo,
    ) -> Result<(String, String), WalletError> {
        let wallet = MerchantWallet::new(merchant_info)?;
        let wallet_id = wallet.config.wallet_id.clone();
        let private_key = wallet.get_private_key_hex().unwrap_or_else(|| "no_key".to_string());
        
        let mut merchant_wallets = self.merchant_wallets.lock().unwrap();
        merchant_wallets.insert(wallet_id.clone(), wallet);
        
        Ok((wallet_id, private_key))
    }

    /// Process a transaction between wallets
    pub fn process_transaction(&self, transaction: &Transaction) -> Result<TransactionReceipt, WalletError> {
        // Verify the transaction signature
        self.verify_transaction_signature(transaction)?;

        // Process based on transaction type
        match transaction.transaction_type {
            TransactionType::Transfer => self.process_transfer(transaction),
            TransactionType::Mint => self.process_mint(transaction),
            TransactionType::Burn => self.process_burn(transaction),
            TransactionType::Stake => self.process_stake(transaction),
            TransactionType::Unstake => self.process_unstake(transaction),
            _ => Err(WalletError::InvalidAmount),
        }
    }

    /// Verify transaction signature
    fn verify_transaction_signature(&self, transaction: &Transaction) -> Result<(), WalletError> {
        let signature = transaction.signature.as_ref()
            .ok_or(WalletError::InvalidSignature)?;

        // Get sender's public key based on wallet type
        let sender_public_key = self.get_wallet_public_key(&transaction.sender)?;

        let is_valid = SignatureVerification::verify_transaction_signature(
            signature,
            &transaction.sender,
            &transaction.recipient,
            transaction.amount,
            &transaction.token_type.to_string(),
            transaction.nonce,
            transaction.timestamp,
            &sender_public_key,
        )?;

        if !is_valid {
            return Err(WalletError::InvalidSignature);
        }

        Ok(())
    }

    /// Get public key for a wallet address (simplified - in production this would query the appropriate wallet)
    fn get_wallet_public_key(&self, address: &str) -> Result<Vec<u8>, WalletError> {
        // This is a simplified implementation
        // In practice, you'd need to look up the wallet by address and get its public key
        // For now, we'll return a placeholder
        Ok(vec![0; 32]) // Placeholder public key
    }

    /// Process a transfer transaction
    fn process_transfer(&self, transaction: &Transaction) -> Result<TransactionReceipt, WalletError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Deduct from sender
        self.deduct_balance(&transaction.sender, transaction.amount, &transaction.token_type)?;

        // Add to recipient
        self.add_balance(&transaction.recipient, transaction.amount, &transaction.token_type)?;

        Ok(TransactionReceipt {
            transaction_id: transaction.id.clone(),
            status: TransactionStatus::Confirmed,
            block_height: None, // Would be set by blockchain
            confirmation_time: timestamp,
            gas_used: 0,
            fee_paid: transaction.fee,
        })
    }

    /// Process a mint transaction (treasury only)
    fn process_mint(&self, transaction: &Transaction) -> Result<TransactionReceipt, WalletError> {
        // Only treasury wallets can mint
        let mut treasury_wallets = self.treasury_wallets.lock().unwrap();
        let treasury = treasury_wallets.get_mut(&transaction.sender)
            .ok_or(WalletError::UnauthorizedOperation)?;

        // Mint tokens (this would integrate with the broader tokenomics system)
        treasury.update_balance(
            if transaction.token_type == TokenType::GU { transaction.amount } else { 0 },
            if transaction.token_type == TokenType::SU { transaction.amount } else { 0 },
        );

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(TransactionReceipt {
            transaction_id: transaction.id.clone(),
            status: TransactionStatus::Confirmed,
            block_height: None,
            confirmation_time: timestamp,
            gas_used: 0,
            fee_paid: transaction.fee,
        })
    }

    /// Process a burn transaction
    fn process_burn(&self, transaction: &Transaction) -> Result<TransactionReceipt, WalletError> {
        // Deduct tokens from sender (effectively burning them)
        self.deduct_balance(&transaction.sender, transaction.amount, &transaction.token_type)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(TransactionReceipt {
            transaction_id: transaction.id.clone(),
            status: TransactionStatus::Confirmed,
            block_height: None,
            confirmation_time: timestamp,
            gas_used: 0,
            fee_paid: transaction.fee,
        })
    }

    /// Process a stake transaction
    fn process_stake(&self, transaction: &Transaction) -> Result<TransactionReceipt, WalletError> {
        let mut validator_wallets = self.validator_wallets.lock().unwrap();
        let validator = validator_wallets.get_mut(&transaction.sender)
            .ok_or(WalletError::WalletNotFound)?;

        // The stake transaction should already be processed by the validator wallet
        // This just confirms it was successful
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(TransactionReceipt {
            transaction_id: transaction.id.clone(),
            status: TransactionStatus::Confirmed,
            block_height: None,
            confirmation_time: timestamp,
            gas_used: 0,
            fee_paid: transaction.fee,
        })
    }

    /// Process an unstake transaction
    fn process_unstake(&self, transaction: &Transaction) -> Result<TransactionReceipt, WalletError> {
        let mut validator_wallets = self.validator_wallets.lock().unwrap();
        let validator = validator_wallets.get_mut(&transaction.sender)
            .ok_or(WalletError::WalletNotFound)?;

        // The unstake transaction should already be processed by the validator wallet
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(TransactionReceipt {
            transaction_id: transaction.id.clone(),
            status: TransactionStatus::Confirmed,
            block_height: None,
            confirmation_time: timestamp,
            gas_used: 0,
            fee_paid: transaction.fee,
        })
    }

    /// Deduct balance from a wallet
    fn deduct_balance(&self, address: &str, amount: u64, token_type: &TokenType) -> Result<(), WalletError> {
        // Try user wallets first
        {
            let mut user_wallets = self.user_wallets.lock().unwrap();
            for wallet in user_wallets.values_mut() {
                if wallet.addresses.iter().any(|addr| addr.address == address) {
                    let current_balance = match token_type {
                        TokenType::GU => wallet.get_address_balance(address)?.gu_balance,
                        TokenType::SU => wallet.get_address_balance(address)?.su_balance,
                    };
                    
                    if current_balance < amount {
                        return Err(WalletError::InsufficientBalance);
                    }

                    let new_gu = if *token_type == TokenType::GU {
                        current_balance - amount
                    } else {
                        wallet.get_address_balance(address)?.gu_balance
                    };

                    let new_su = if *token_type == TokenType::SU {
                        current_balance - amount
                    } else {
                        wallet.get_address_balance(address)?.su_balance
                    };

                    wallet.update_address_balance(address, new_gu, new_su)?;
                    return Ok(());
                }
            }
        }

        // Try treasury wallets
        {
            let mut treasury_wallets = self.treasury_wallets.lock().unwrap();
            if let Some(wallet) = treasury_wallets.values_mut().find(|w| w.address == address) {
                let current_balance = match token_type {
                    TokenType::GU => wallet.balance.gu_balance,
                    TokenType::SU => wallet.balance.su_balance,
                };
                
                if current_balance < amount {
                    return Err(WalletError::InsufficientBalance);
                }

                match token_type {
                    TokenType::GU => wallet.balance.gu_balance -= amount,
                    TokenType::SU => wallet.balance.su_balance -= amount,
                }
                return Ok(());
            }
        }

        // Try validator wallets
        {
            let mut validator_wallets = self.validator_wallets.lock().unwrap();
            if let Some(wallet) = validator_wallets.values_mut().find(|w| w.address == address) {
                let current_balance = match token_type {
                    TokenType::GU => wallet.balance.gu_balance,
                    TokenType::SU => wallet.balance.su_balance,
                };
                
                if current_balance < amount {
                    return Err(WalletError::InsufficientBalance);
                }

                match token_type {
                    TokenType::GU => wallet.balance.gu_balance -= amount,
                    TokenType::SU => wallet.balance.su_balance -= amount,
                }
                return Ok(());
            }
        }

        // Try merchant wallets
        {
            let mut merchant_wallets = self.merchant_wallets.lock().unwrap();
            if let Some(wallet) = merchant_wallets.values_mut().find(|w| w.address == address) {
                let current_balance = match token_type {
                    TokenType::GU => wallet.balance.gu_balance,
                    TokenType::SU => wallet.balance.su_balance,
                };
                
                if current_balance < amount {
                    return Err(WalletError::InsufficientBalance);
                }

                match token_type {
                    TokenType::GU => wallet.balance.gu_balance -= amount,
                    TokenType::SU => wallet.balance.su_balance -= amount,
                }
                return Ok(());
            }
        }

        Err(WalletError::WalletNotFound)
    }

    /// Add balance to a wallet
    fn add_balance(&self, address: &str, amount: u64, token_type: &TokenType) -> Result<(), WalletError> {
        // Try user wallets first
        {
            let mut user_wallets = self.user_wallets.lock().unwrap();
            for wallet in user_wallets.values_mut() {
                if wallet.addresses.iter().any(|addr| addr.address == address) {
                    let current_gu = wallet.get_address_balance(address)?.gu_balance;
                    let current_su = wallet.get_address_balance(address)?.su_balance;

                    let new_gu = if *token_type == TokenType::GU {
                        current_gu + amount
                    } else {
                        current_gu
                    };

                    let new_su = if *token_type == TokenType::SU {
                        current_su + amount
                    } else {
                        current_su
                    };

                    wallet.update_address_balance(address, new_gu, new_su)?;
                    return Ok(());
                }
            }
        }

        // Try treasury wallets
        {
            let mut treasury_wallets = self.treasury_wallets.lock().unwrap();
            if let Some(wallet) = treasury_wallets.values_mut().find(|w| w.address == address) {
                match token_type {
                    TokenType::GU => wallet.balance.gu_balance += amount,
                    TokenType::SU => wallet.balance.su_balance += amount,
                }
                return Ok(());
            }
        }

        // Try validator wallets
        {
            let mut validator_wallets = self.validator_wallets.lock().unwrap();
            if let Some(wallet) = validator_wallets.values_mut().find(|w| w.address == address) {
                match token_type {
                    TokenType::GU => wallet.balance.gu_balance += amount,
                    TokenType::SU => wallet.balance.su_balance += amount,
                }
                return Ok(());
            }
        }

        // Try merchant wallets
        {
            let mut merchant_wallets = self.merchant_wallets.lock().unwrap();
            if let Some(wallet) = merchant_wallets.values_mut().find(|w| w.address == address) {
                match token_type {
                    TokenType::GU => wallet.balance.gu_balance += amount,
                    TokenType::SU => wallet.balance.su_balance += amount,
                }
                return Ok(());
            }
        }

        Err(WalletError::WalletNotFound)
    }

    /// Get the balance of a specific wallet by its ID
    pub fn get_wallet_balance(&self, wallet_id: &str) -> Result<TokenBalance, WalletError> {
        // Check user wallets
        {
            let user_wallets = self.user_wallets.lock().unwrap();
            if let Some(wallet) = user_wallets.get(wallet_id) {
                return Ok(wallet.get_total_balance());
            }
        }

        // Check treasury wallets
        {
            let treasury_wallets = self.treasury_wallets.lock().unwrap();
            if let Some(wallet) = treasury_wallets.get(wallet_id) {
                return Ok(wallet.get_balance().clone());
            }
        }

        // Check validator wallets
        {
            let validator_wallets = self.validator_wallets.lock().unwrap();
            if let Some(wallet) = validator_wallets.get(wallet_id) {
                return Ok(wallet.get_balance().clone());
            }
        }

        // Check merchant wallets
        {
            let merchant_wallets = self.merchant_wallets.lock().unwrap();
            if let Some(wallet) = merchant_wallets.get(wallet_id) {
                return Ok(wallet.get_balance().clone());
            }
        }

        Err(WalletError::WalletNotFound)
    }

    /// Get wallet statistics across all wallet types
    pub fn get_system_stats(&self) -> WalletSystemStats {
        let user_wallets = self.user_wallets.lock().unwrap();
        let treasury_wallets = self.treasury_wallets.lock().unwrap();
        let validator_wallets = self.validator_wallets.lock().unwrap();
        let merchant_wallets = self.merchant_wallets.lock().unwrap();

        let total_user_wallets = user_wallets.len();
        let total_treasury_wallets = treasury_wallets.len();
        let total_validator_wallets = validator_wallets.len();
        let total_merchant_wallets = merchant_wallets.len();

        // Calculate total balances
        let mut total_gu_balance = 0u64;
        let mut total_su_balance = 0u64;

        for wallet in user_wallets.values() {
            let balance = wallet.get_total_balance();
            total_gu_balance += balance.gu_balance;
            total_su_balance += balance.su_balance;
        }

        for wallet in treasury_wallets.values() {
            total_gu_balance += wallet.balance.gu_balance;
            total_su_balance += wallet.balance.su_balance;
        }

        for wallet in validator_wallets.values() {
            total_gu_balance += wallet.balance.gu_balance;
            total_su_balance += wallet.balance.su_balance;
        }

        for wallet in merchant_wallets.values() {
            total_gu_balance += wallet.balance.gu_balance;
            total_su_balance += wallet.balance.su_balance;
        }

        WalletSystemStats {
            total_user_wallets,
            total_treasury_wallets,
            total_validator_wallets,
            total_merchant_wallets,
            total_wallets: total_user_wallets + total_treasury_wallets + total_validator_wallets + total_merchant_wallets,
            total_gu_balance,
            total_su_balance,
            total_balance: total_gu_balance + total_su_balance,
        }
    }
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub block_height: Option<u64>,
    pub confirmation_time: u64,
    pub gas_used: u64,
    pub fee_paid: u64,
}

/// System-wide wallet statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSystemStats {
    pub total_user_wallets: usize,
    pub total_treasury_wallets: usize,
    pub total_validator_wallets: usize,
    pub total_merchant_wallets: usize,
    pub total_wallets: usize,
    pub total_gu_balance: u64,
    pub total_su_balance: u64,
    pub total_balance: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_manager_creation() {
        let manager = WalletManager::new();
        let stats = manager.get_system_stats();
        
        assert_eq!(stats.total_wallets, 0);
        assert_eq!(stats.total_balance, 0);
    }

    #[test]
    fn test_create_user_wallet() {
        let manager = WalletManager::new();
        let wallet_id = manager.create_user_wallet(Some("did:e3:user123".to_string())).unwrap();
        
        assert!(!wallet_id.is_empty());
        
        let stats = manager.get_system_stats();
        assert_eq!(stats.total_user_wallets, 1);
    }

    #[test]
    fn test_create_treasury_wallet() {
        let manager = WalletManager::new();
        let admin_addresses = vec!["admin1".to_string(), "admin2".to_string()];
        
        let wallet_id = manager.create_treasury_wallet(
            "treasury_address".to_string(),
            admin_addresses,
            2,
        ).unwrap();
        
        assert!(!wallet_id.is_empty());
        
        let stats = manager.get_system_stats();
        assert_eq!(stats.total_treasury_wallets, 1);
    }
}
