use crate::wallet::types::{WalletError, WalletConfig, WalletType, TokenBalance, AuditLogEntry};
use crate::wallet::transaction::{Transaction, TransactionHistory, TransactionBuilder, TransactionType, TokenType};
use crate::wallet::signature::{WalletKeyManager, WalletSignature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Validator wallet for staking, rewards, and validator operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorWallet {
    pub config: WalletConfig,
    pub address: String,
    pub operator_id: String,
    pub balance: TokenBalance,
    pub staking_info: StakingInfo,
    pub validator_metadata: ValidatorMetadata,
    pub transaction_history: TransactionHistory,
    pub audit_log: Vec<AuditLogEntry>,
    pub performance_metrics: PerformanceMetrics,
    pub nonce: u64,
    #[serde(skip)] // Don't serialize private keys for security
    pub key_manager: Option<WalletKeyManager>,
}

/// Staking information for the validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingInfo {
    pub staked_amount: u64,
    pub minimum_stake: u64,
    pub delegated_stakes: HashMap<String, DelegatedStake>, // delegator_address -> stake info
    pub total_delegated: u64,
    pub staking_rewards: u64,
    pub commission_rate: f64, // Percentage taken from delegator rewards
    pub last_reward_claim: u64,
    pub stake_lock_period: u64, // Time in seconds before unstaking is allowed
    pub unstaking_requests: Vec<UnstakingRequest>,
}

/// Information about delegated stakes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedStake {
    pub delegator_address: String,
    pub amount: u64,
    pub delegation_date: u64,
    pub last_reward_claim: u64,
    pub pending_rewards: u64,
}

/// Unstaking request with time lock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnstakingRequest {
    pub request_id: String,
    pub address: String, // Validator or delegator address
    pub amount: u64,
    pub request_date: u64,
    pub unlock_date: u64,
    pub is_delegation: bool, // true if it's a delegator unstaking
}

/// Validator-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetadata {
    pub validator_name: String,
    pub description: Option<String>,
    pub website: Option<String>,
    pub contact_email: Option<String>,
    pub public_key: Vec<u8>,
    pub is_active: bool,
    pub registration_date: u64,
    pub last_active: u64,
    pub validator_status: ValidatorStatus,
    pub slashing_history: Vec<SlashingEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed,
    Slashed,
    Retiring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub event_id: String,
    pub reason: String,
    pub amount_slashed: u64,
    pub timestamp: u64,
    pub block_height: u64,
}

/// Performance metrics for the validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub blocks_proposed: u64,
    pub blocks_signed: u64,
    pub total_blocks: u64,
    pub uptime_percentage: f64,
    pub avg_response_time: u64, // in milliseconds
    pub last_performance_update: u64,
    pub penalties: u64,
    pub bonuses: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            blocks_proposed: 0,
            blocks_signed: 0,
            total_blocks: 0,
            uptime_percentage: 100.0,
            avg_response_time: 0,
            last_performance_update: 0,
            penalties: 0,
            bonuses: 0,
        }
    }
}

impl ValidatorWallet {
    /// Create a new validator wallet
    pub fn new(
        operator_id: String,
        validator_name: String,
        public_key: Vec<u8>,
        minimum_stake: u64,
        commission_rate: f64,
    ) -> Result<Self, WalletError> {
        if commission_rate < 0.0 || commission_rate > 100.0 {
            return Err(WalletError::InvalidAmount);
        }

        let wallet_id = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate validator address
        let key_manager = WalletKeyManager::new()?;
        let address = key_manager.get_address().to_string();

        let config = WalletConfig::new(wallet_id.clone(), WalletType::Validator, timestamp)
            .with_metadata("operator_id".to_string(), operator_id.clone())
            .with_metadata("commission_rate".to_string(), commission_rate.to_string());

        let staking_info = StakingInfo {
            staked_amount: 0,
            minimum_stake,
            delegated_stakes: HashMap::new(),
            total_delegated: 0,
            staking_rewards: 0,
            commission_rate,
            last_reward_claim: timestamp,
            stake_lock_period: 1209600, // 14 days default
            unstaking_requests: Vec::new(),
        };

        let validator_metadata = ValidatorMetadata {
            validator_name,
            description: None,
            website: None,
            contact_email: None,
            public_key,
            is_active: false, // Starts inactive until staked
            registration_date: timestamp,
            last_active: timestamp,
            validator_status: ValidatorStatus::Inactive,
            slashing_history: Vec::new(),
        };

        let transaction_history = TransactionHistory::new(wallet_id.clone());

        // Create audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            wallet_id.clone(),
            "validator_created".to_string(),
            timestamp,
        ).with_detail("operator_id".to_string(), operator_id.clone())
        .with_detail("minimum_stake".to_string(), minimum_stake.to_string());

        Ok(Self {
            config,
            address,
            operator_id,
            balance: TokenBalance::new(),
            staking_info,
            validator_metadata,
            transaction_history,
            audit_log: vec![audit_entry],
            performance_metrics: PerformanceMetrics::default(),
            nonce: 0,
            key_manager: Some(key_manager),
        })
    }

    /// Stake tokens to become an active validator
    pub fn stake(
        &mut self,
        amount: u64,
        token_type: TokenType,
    ) -> Result<Transaction, WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }

        // Check if we have enough balance
        let available_balance = match token_type {
            TokenType::GU => self.balance.gu_balance,
            TokenType::SU => self.balance.su_balance,
        };

        if available_balance < amount {
            return Err(WalletError::InsufficientBalance);
        }

        self.nonce += 1;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create stake transaction
        let transaction = TransactionBuilder::new(TransactionType::Stake)
            .sender(self.address.clone())
            .recipient(self.address.clone()) // Staking to self
            .amount(amount)
            .token_type(token_type.clone())
            .nonce(self.nonce)
            .timestamp(timestamp)
            .fee(0) // No fee for staking
            .metadata("validator_id".to_string(), self.config.wallet_id.clone())
            .build()?;

        // Update staking info
        self.staking_info.staked_amount += amount;

        // Update balance
        match token_type {
            TokenType::GU => self.balance.gu_balance -= amount,
            TokenType::SU => self.balance.su_balance -= amount,
        }

        // Check if validator can become active
        if self.staking_info.staked_amount >= self.staking_info.minimum_stake {
            self.validator_metadata.is_active = true;
            self.validator_metadata.validator_status = ValidatorStatus::Active;
        }

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "stake_added".to_string(),
            timestamp,
        ).with_detail("amount".to_string(), amount.to_string())
        .with_detail("total_staked".to_string(), self.staking_info.staked_amount.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(transaction)
    }

    /// Request to unstake tokens
    pub fn request_unstake(&mut self, amount: u64) -> Result<String, WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }

        if self.staking_info.staked_amount < amount {
            return Err(WalletError::InsufficientBalance);
        }

        // Check if unstaking would make validator inactive
        let remaining_stake = self.staking_info.staked_amount - amount;
        if remaining_stake < self.staking_info.minimum_stake && remaining_stake > 0 {
            return Err(WalletError::InvalidAmount);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let request_id = Uuid::new_v4().to_string();
        let unlock_date = timestamp + self.staking_info.stake_lock_period;

        let unstaking_request = UnstakingRequest {
            request_id: request_id.clone(),
            address: self.address.clone(),
            amount,
            request_date: timestamp,
            unlock_date,
            is_delegation: false,
        };

        self.staking_info.unstaking_requests.push(unstaking_request);

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "unstake_requested".to_string(),
            timestamp,
        ).with_detail("amount".to_string(), amount.to_string())
        .with_detail("unlock_date".to_string(), unlock_date.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(request_id)
    }

    /// Process unstaking request (when lock period is over)
    pub fn process_unstake(&mut self, request_id: &str) -> Result<Transaction, WalletError> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Find the unstaking request
        let request_index = self.staking_info.unstaking_requests.iter()
            .position(|req| req.request_id == request_id)
            .ok_or(WalletError::InvalidAmount)?;

        let request_amount = self.staking_info.unstaking_requests[request_index].amount;
        let unlock_date = self.staking_info.unstaking_requests[request_index].unlock_date;

        // Check if unlock period has passed
        if current_time < unlock_date {
            return Err(WalletError::UnauthorizedOperation);
        }

        self.nonce += 1;

        // Create unstake transaction
        let transaction = TransactionBuilder::new(TransactionType::Unstake)
            .sender(self.address.clone())
            .recipient(self.address.clone())
            .amount(request_amount)
            .token_type(TokenType::SU) // Assuming SU for staking
            .nonce(self.nonce)
            .timestamp(current_time)
            .fee(0)
            .metadata("request_id".to_string(), request_id.to_string())
            .build()?;

        // Update staking info
        self.staking_info.staked_amount -= request_amount;
        self.balance.su_balance += request_amount;

        // Check if validator should become inactive
        if self.staking_info.staked_amount < self.staking_info.minimum_stake {
            self.validator_metadata.is_active = false;
            self.validator_metadata.validator_status = ValidatorStatus::Inactive;
        }

        // Remove the processed request
        self.staking_info.unstaking_requests.remove(request_index);

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "unstake_processed".to_string(),
            current_time,
        ).with_detail("amount".to_string(), request_amount.to_string())
        .with_detail("remaining_stake".to_string(), self.staking_info.staked_amount.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = current_time;

        Ok(transaction)
    }

    /// Add delegation from another address
    pub fn add_delegation(
        &mut self,
        delegator_address: String,
        amount: u64,
    ) -> Result<(), WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }

        if !self.validator_metadata.is_active {
            return Err(WalletError::UnauthorizedOperation);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let delegation = DelegatedStake {
            delegator_address: delegator_address.clone(),
            amount,
            delegation_date: timestamp,
            last_reward_claim: timestamp,
            pending_rewards: 0,
        };

        // Update existing delegation or add new one
        if let Some(existing) = self.staking_info.delegated_stakes.get_mut(&delegator_address) {
            existing.amount += amount;
        } else {
            self.staking_info.delegated_stakes.insert(delegator_address.clone(), delegation);
        }

        self.staking_info.total_delegated += amount;

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "delegation_added".to_string(),
            timestamp,
        ).with_detail("delegator".to_string(), delegator_address)
        .with_detail("amount".to_string(), amount.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(())
    }

    /// Distribute rewards to validator and delegators
    pub fn distribute_rewards(&mut self, total_reward: u64) -> Result<Vec<RewardDistribution>, WalletError> {
        if total_reward == 0 {
            return Ok(Vec::new());
        }

        let mut distributions = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Calculate commission
        let commission = (total_reward as f64 * self.staking_info.commission_rate / 100.0) as u64;
        let delegator_rewards = total_reward - commission;

        // Validator gets commission plus their stake proportion
        let total_stake = self.staking_info.staked_amount + self.staking_info.total_delegated;
        let validator_share = if total_stake > 0 {
            (delegator_rewards as f64 * self.staking_info.staked_amount as f64 / total_stake as f64) as u64
        } else {
            0
        };

        let validator_total = commission + validator_share;

        // Add to validator rewards
        self.staking_info.staking_rewards += validator_total;
        self.balance.su_balance += validator_total; // Assuming rewards are paid in SU

        distributions.push(RewardDistribution {
            recipient: self.address.clone(),
            amount: validator_total,
            reward_type: RewardType::ValidatorReward,
            timestamp,
        });

        // Distribute to delegators
        let remaining_for_delegators = delegator_rewards - validator_share;
        
        for (delegator_address, delegation) in &mut self.staking_info.delegated_stakes {
            if self.staking_info.total_delegated > 0 {
                let delegator_reward = (remaining_for_delegators as f64 * delegation.amount as f64 / self.staking_info.total_delegated as f64) as u64;
                
                delegation.pending_rewards += delegator_reward;
                
                distributions.push(RewardDistribution {
                    recipient: delegator_address.clone(),
                    amount: delegator_reward,
                    reward_type: RewardType::DelegationReward,
                    timestamp,
                });
            }
        }

        self.staking_info.last_reward_claim = timestamp;

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "rewards_distributed".to_string(),
            timestamp,
        ).with_detail("total_reward".to_string(), total_reward.to_string())
        .with_detail("validator_reward".to_string(), validator_total.to_string())
        .with_detail("delegator_count".to_string(), self.staking_info.delegated_stakes.len().to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(distributions)
    }

    /// Update performance metrics
    pub fn update_performance(
        &mut self,
        blocks_proposed: u64,
        blocks_signed: u64,
        total_blocks: u64,
        response_time: u64,
    ) {
        self.performance_metrics.blocks_proposed += blocks_proposed;
        self.performance_metrics.blocks_signed += blocks_signed;
        self.performance_metrics.total_blocks += total_blocks;

        // Calculate uptime percentage
        if self.performance_metrics.total_blocks > 0 {
            self.performance_metrics.uptime_percentage = 
                (self.performance_metrics.blocks_signed as f64 / self.performance_metrics.total_blocks as f64) * 100.0;
        }

        // Update average response time
        self.performance_metrics.avg_response_time = 
            (self.performance_metrics.avg_response_time + response_time) / 2;

        self.performance_metrics.last_performance_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.validator_metadata.last_active = self.performance_metrics.last_performance_update;
    }

    /// Apply slashing penalty
    pub fn apply_slashing(
        &mut self,
        reason: String,
        penalty_amount: u64,
        block_height: u64,
    ) -> Result<(), WalletError> {
        if penalty_amount > self.staking_info.staked_amount {
            return Err(WalletError::InsufficientBalance);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Record slashing event
        let slashing_event = SlashingEvent {
            event_id: Uuid::new_v4().to_string(),
            reason: reason.clone(),
            amount_slashed: penalty_amount,
            timestamp,
            block_height,
        };

        self.validator_metadata.slashing_history.push(slashing_event);
        self.validator_metadata.validator_status = ValidatorStatus::Slashed;

        // Apply penalty
        self.staking_info.staked_amount -= penalty_amount;
        self.performance_metrics.penalties += penalty_amount;

        // Check if validator should be jailed or become inactive
        if self.staking_info.staked_amount < self.staking_info.minimum_stake {
            self.validator_metadata.is_active = false;
            self.validator_metadata.validator_status = ValidatorStatus::Jailed;
        }

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "slashing_applied".to_string(),
            timestamp,
        ).with_detail("reason".to_string(), reason)
        .with_detail("penalty_amount".to_string(), penalty_amount.to_string())
        .with_detail("block_height".to_string(), block_height.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(())
    }

    /// Get validator statistics
    pub fn get_validator_stats(&self) -> ValidatorStats {
        ValidatorStats {
            address: self.address.clone(),
            operator_id: self.operator_id.clone(),
            validator_name: self.validator_metadata.validator_name.clone(),
            is_active: self.validator_metadata.is_active,
            status: self.validator_metadata.validator_status.clone(),
            staked_amount: self.staking_info.staked_amount,
            total_delegated: self.staking_info.total_delegated,
            commission_rate: self.staking_info.commission_rate,
            uptime_percentage: self.performance_metrics.uptime_percentage,
            blocks_proposed: self.performance_metrics.blocks_proposed,
            blocks_signed: self.performance_metrics.blocks_signed,
            total_rewards: self.staking_info.staking_rewards,
            slashing_count: self.validator_metadata.slashing_history.len(),
            registration_date: self.validator_metadata.registration_date,
        }
    }

    /// Get current balance
    pub fn get_balance(&self) -> &TokenBalance {
        &self.balance
    }

    /// Get total balance (for compatibility)
    pub fn get_total_balance(&self) -> TokenBalance {
        self.balance.clone()
    }

    /// Get private key hex (be careful with this!)
    pub fn get_private_key_hex(&self) -> Option<String> {
        self.key_manager.as_ref().map(|km| km.get_private_key_hex())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    pub recipient: String,
    pub amount: u64,
    pub reward_type: RewardType,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RewardType {
    ValidatorReward,
    DelegationReward,
    PerformanceBonus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStats {
    pub address: String,
    pub operator_id: String,
    pub validator_name: String,
    pub is_active: bool,
    pub status: ValidatorStatus,
    pub staked_amount: u64,
    pub total_delegated: u64,
    pub commission_rate: f64,
    pub uptime_percentage: f64,
    pub blocks_proposed: u64,
    pub blocks_signed: u64,
    pub total_rewards: u64,
    pub slashing_count: usize,
    pub registration_date: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let validator = ValidatorWallet::new(
            "operator123".to_string(),
            "TestValidator".to_string(),
            vec![1, 2, 3, 4], // Mock public key
            1000, // Minimum stake
            5.0, // 5% commission
        ).unwrap();

        assert_eq!(validator.validator_metadata.validator_name, "TestValidator");
        assert_eq!(validator.staking_info.commission_rate, 5.0);
        assert!(!validator.validator_metadata.is_active); // Starts inactive
    }

    #[test]
    fn test_staking() {
        let mut validator = ValidatorWallet::new(
            "operator123".to_string(),
            "TestValidator".to_string(),
            vec![1, 2, 3, 4],
            1000,
            5.0,
        ).unwrap();

        // Set some balance
        validator.balance.su_balance = 2000;

        let transaction = validator.stake(1500, TokenType::SU).unwrap();
        
        assert_eq!(validator.staking_info.staked_amount, 1500);
        assert!(validator.validator_metadata.is_active); // Should be active now
        assert_eq!(transaction.amount, 1500);
    }
}
