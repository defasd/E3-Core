use crate::wallet::types::{WalletError, WalletConfig, WalletType, TokenBalance, AuditLogEntry};
use crate::wallet::transaction::{Transaction, TransactionHistory, TransactionBuilder, TransactionType, TokenType};
use crate::wallet::signature::{WalletKeyManager, WalletSignature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Merchant wallet for stores, benefits, and promotional programs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantWallet {
    pub config: WalletConfig,
    pub address: String,
    pub merchant_info: MerchantInfo,
    pub balance: TokenBalance,
    pub smart_contract_hooks: Vec<SmartContractHook>,
    pub loyalty_program: Option<LoyaltyProgram>,
    pub promotional_campaigns: Vec<PromotionalCampaign>,
    pub transaction_history: TransactionHistory,
    pub audit_log: Vec<AuditLogEntry>,
    pub merchant_settings: MerchantSettings,
    pub nonce: u64,
    #[serde(skip)] // Don't serialize private keys for security
    pub key_manager: Option<WalletKeyManager>,
}

/// Merchant business information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantInfo {
    pub business_name: String,
    pub business_type: BusinessType,
    pub registration_number: Option<String>,
    pub tax_id: Option<String>,
    pub address: MerchantAddress,
    pub contact_info: ContactInfo,
    pub verification_status: VerificationStatus,
    pub registration_date: u64,
    pub last_active: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessType {
    Retail,
    Restaurant,
    OnlineStore,
    Service,
    Entertainment,
    Healthcare,
    Education,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantAddress {
    pub street: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub email: String,
    pub phone: Option<String>,
    pub website: Option<String>,
    pub social_media: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    Pending,
    Verified,
    Rejected,
    Suspended,
}

/// Smart contract hook for merchant-specific logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartContractHook {
    pub hook_id: String,
    pub hook_type: HookType,
    pub trigger_condition: TriggerCondition,
    pub action: HookAction,
    pub is_active: bool,
    pub created_at: u64,
    pub execution_count: u64,
    pub last_executed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookType {
    TransactionProcessor,
    LoyaltyPointCalculator,
    DiscountApplicator,
    RewardDistributor,
    ComplianceChecker,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerCondition {
    OnTransaction,
    OnAmountThreshold(u64),
    OnTimeInterval(u64), // seconds
    OnCustomerAction(String),
    OnPromotionStart,
    OnPromotionEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookAction {
    AwardLoyaltyPoints(u64),
    ApplyDiscount(f64), // percentage
    SendNotification(String),
    ExecuteCustomLogic(String),
    TransferTokens { to: String, amount: u64, token_type: TokenType },
    CreatePromotion(String),
}

/// Loyalty program configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoyaltyProgram {
    pub program_id: String,
    pub program_name: String,
    pub points_per_unit: f64, // Points earned per unit spent
    pub redemption_rate: f64, // How many points = 1 token unit
    pub member_tiers: Vec<LoyaltyTier>,
    pub expiration_policy: Option<ExpirationPolicy>,
    pub is_active: bool,
    pub created_at: u64,
    pub total_members: u64,
    pub total_points_issued: u64,
    pub total_points_redeemed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoyaltyTier {
    pub tier_name: String,
    pub minimum_points: u64,
    pub benefits: Vec<String>,
    pub multiplier: f64, // Points earning multiplier
    pub special_rewards: Vec<SpecialReward>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialReward {
    pub reward_name: String,
    pub cost_in_points: u64,
    pub description: String,
    pub expiry_date: Option<u64>,
    pub quantity_available: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationPolicy {
    pub expiry_duration: u64, // in seconds
    pub warning_period: u64, // seconds before expiry to warn
}

/// Promotional campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionalCampaign {
    pub campaign_id: String,
    pub campaign_name: String,
    pub description: String,
    pub campaign_type: CampaignType,
    pub start_date: u64,
    pub end_date: u64,
    pub budget: u64, // Total tokens allocated for campaign
    pub spent: u64, // Tokens spent so far
    pub target_audience: TargetAudience,
    pub conditions: Vec<CampaignCondition>,
    pub rewards: Vec<CampaignReward>,
    pub is_active: bool,
    pub metrics: CampaignMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CampaignType {
    Discount,
    Cashback,
    BuyOneGetOne,
    LoyaltyBonus,
    NewCustomerBonus,
    SeasonalPromotion,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAudience {
    pub customer_tiers: Vec<String>,
    pub age_range: Option<(u32, u32)>,
    pub location_restrictions: Vec<String>,
    pub spending_history: Option<SpendingCriteria>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingCriteria {
    pub minimum_spent: u64,
    pub time_period: u64, // in seconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CampaignCondition {
    MinimumPurchase(u64),
    SpecificProducts(Vec<String>),
    TimeWindow { start: u64, end: u64 },
    FirstTimeCustomer,
    LoyaltyTier(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReward {
    pub reward_type: RewardType,
    pub value: u64,
    pub max_per_customer: Option<u64>,
    pub total_available: Option<u64>,
    pub used_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RewardType {
    DiscountPercentage,
    DiscountFixed,
    CashbackPercentage,
    CashbackFixed,
    LoyaltyPoints,
    FreeProduct(String),
    FreeShipping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignMetrics {
    pub participants: u64,
    pub total_savings_provided: u64,
    pub conversion_rate: f64,
    pub customer_acquisition: u64,
    pub repeat_customers: u64,
}

/// Merchant-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantSettings {
    pub auto_process_transactions: bool,
    pub loyalty_program_enabled: bool,
    pub promotional_notifications: bool,
    pub transaction_fees_policy: FeesPolicy,
    pub refund_policy: RefundPolicy,
    pub supported_currencies: Vec<TokenType>,
    pub business_hours: Option<BusinessHours>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeesPolicy {
    pub customer_pays_fees: bool,
    pub merchant_fee_percentage: f64,
    pub minimum_fee: u64,
    pub maximum_fee: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundPolicy {
    pub refunds_enabled: bool,
    pub refund_period_days: u32,
    pub automatic_refunds: bool,
    pub refund_fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessHours {
    pub timezone: String,
    pub weekly_schedule: HashMap<String, DaySchedule>, // day_name -> schedule
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaySchedule {
    pub is_open: bool,
    pub open_time: Option<String>, // "HH:MM" format
    pub close_time: Option<String>,
    pub break_periods: Vec<BreakPeriod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakPeriod {
    pub start_time: String,
    pub end_time: String,
    pub reason: String,
}

impl Default for MerchantSettings {
    fn default() -> Self {
        Self {
            auto_process_transactions: true,
            loyalty_program_enabled: false,
            promotional_notifications: true,
            transaction_fees_policy: FeesPolicy {
                customer_pays_fees: true,
                merchant_fee_percentage: 2.5,
                minimum_fee: 1,
                maximum_fee: Some(100),
            },
            refund_policy: RefundPolicy {
                refunds_enabled: true,
                refund_period_days: 30,
                automatic_refunds: false,
                refund_fee: 5,
            },
            supported_currencies: vec![TokenType::GU, TokenType::SU],
            business_hours: None,
        }
    }
}

impl MerchantWallet {
    /// Create a new merchant wallet
    pub fn new(
        merchant_info: MerchantInfo,
    ) -> Result<Self, WalletError> {
        let wallet_id = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate merchant address
        let key_manager = WalletKeyManager::new()?;
        let address = key_manager.get_address().to_string();

        let config = WalletConfig::new(wallet_id.clone(), WalletType::Merchant, timestamp)
            .with_metadata("business_name".to_string(), merchant_info.business_name.clone())
            .with_metadata("business_type".to_string(), format!("{:?}", merchant_info.business_type));

        let transaction_history = TransactionHistory::new(wallet_id.clone());

        // Create audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            wallet_id.clone(),
            "merchant_wallet_created".to_string(),
            timestamp,
        ).with_detail("business_name".to_string(), merchant_info.business_name.clone());

        Ok(Self {
            config,
            address,
            merchant_info,
            balance: TokenBalance::new(),
            smart_contract_hooks: Vec::new(),
            loyalty_program: None,
            promotional_campaigns: Vec::new(),
            transaction_history,
            audit_log: vec![audit_entry],
            merchant_settings: MerchantSettings::default(),
            nonce: 0,
            key_manager: Some(key_manager),
        })
    }

    /// Add a smart contract hook
    pub fn add_smart_contract_hook(
        &mut self,
        hook_type: HookType,
        trigger_condition: TriggerCondition,
        action: HookAction,
    ) -> Result<String, WalletError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hook_id = Uuid::new_v4().to_string();

        let hook = SmartContractHook {
            hook_id: hook_id.clone(),
            hook_type,
            trigger_condition,
            action,
            is_active: true,
            created_at: timestamp,
            execution_count: 0,
            last_executed: None,
        };

        self.smart_contract_hooks.push(hook);

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "smart_contract_hook_added".to_string(),
            timestamp,
        ).with_detail("hook_id".to_string(), hook_id.clone());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(hook_id)
    }

    /// Execute smart contract hooks based on trigger
    pub fn execute_hooks(
        &mut self,
        trigger: &TriggerCondition,
        context: &HookExecutionContext,
    ) -> Result<Vec<HookExecutionResult>, WalletError> {
        let mut results = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // First, collect hooks that need to be executed
        let mut hooks_to_execute = Vec::new();
        
        for (index, hook) in self.smart_contract_hooks.iter().enumerate() {
            if !hook.is_active {
                continue;
            }

            // Check if trigger matches
            let should_execute = match (&hook.trigger_condition, trigger) {
                (TriggerCondition::OnTransaction, TriggerCondition::OnTransaction) => true,
                (TriggerCondition::OnAmountThreshold(hook_threshold), TriggerCondition::OnAmountThreshold(trigger_threshold)) => {
                    trigger_threshold >= hook_threshold
                }
                _ => false, // Add more matching logic as needed
            };

            if should_execute {
                hooks_to_execute.push((index, hook.hook_id.clone(), hook.action.clone()));
            }
        }

        // Then execute the hooks and update them
        for (index, hook_id, action) in hooks_to_execute {
            let result = self.execute_hook_action(&action, context)?;
            
            // Update the hook after execution
            if let Some(hook) = self.smart_contract_hooks.get_mut(index) {
                hook.execution_count += 1;
                hook.last_executed = Some(timestamp);
            }

            results.push(HookExecutionResult {
                hook_id,
                success: result.success,
                message: result.message,
                data: result.data,
            });
        }

        Ok(results)
    }

    /// Execute a specific hook action
    fn execute_hook_action(
        &mut self,
        action: &HookAction,
        context: &HookExecutionContext,
    ) -> Result<ActionExecutionResult, WalletError> {
        match action {
            HookAction::AwardLoyaltyPoints(points) => {
                if let Some(customer_address) = &context.customer_address {
                    // Award loyalty points (this would interact with loyalty system)
                    Ok(ActionExecutionResult {
                        success: true,
                        message: format!("Awarded {} loyalty points", points),
                        data: Some(format!("customer:{},points:{}", customer_address, points)),
                    })
                } else {
                    Ok(ActionExecutionResult {
                        success: false,
                        message: "No customer address provided".to_string(),
                        data: None,
                    })
                }
            }
            HookAction::ApplyDiscount(percentage) => {
                Ok(ActionExecutionResult {
                    success: true,
                    message: format!("Applied {}% discount", percentage),
                    data: Some(format!("discount_percentage:{}", percentage)),
                })
            }
            HookAction::SendNotification(message) => {
                // Send notification (this would integrate with notification system)
                Ok(ActionExecutionResult {
                    success: true,
                    message: format!("Notification sent: {}", message),
                    data: Some(message.clone()),
                })
            }
            HookAction::TransferTokens { to, amount, token_type } => {
                // Execute token transfer
                self.create_transfer_transaction(to.clone(), *amount, token_type.clone())
                    .map(|tx| ActionExecutionResult {
                        success: true,
                        message: format!("Transferred {} {:?} to {}", amount, token_type, to),
                        data: Some(tx.id),
                    })
            }
            HookAction::ExecuteCustomLogic(logic) => {
                // Execute custom business logic (placeholder)
                Ok(ActionExecutionResult {
                    success: true,
                    message: format!("Executed custom logic: {}", logic),
                    data: Some(logic.clone()),
                })
            }
            HookAction::CreatePromotion(promotion_name) => {
                // Create a new promotional campaign (simplified)
                Ok(ActionExecutionResult {
                    success: true,
                    message: format!("Created promotion: {}", promotion_name),
                    data: Some(promotion_name.clone()),
                })
            }
        }
    }

    /// Create a transfer transaction
    pub fn create_transfer_transaction(
        &mut self,
        to_address: String,
        amount: u64,
        token_type: TokenType,
    ) -> Result<Transaction, WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }

        // Check balance
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

        let fee = self.calculate_transaction_fee(amount);

        let transaction = TransactionBuilder::new(TransactionType::Transfer)
            .sender(self.address.clone())
            .recipient(to_address)
            .amount(amount)
            .token_type(token_type.clone())
            .nonce(self.nonce)
            .timestamp(timestamp)
            .fee(fee)
            .metadata("merchant_id".to_string(), self.config.wallet_id.clone())
            .build()?;

        // Update balance
        let total_deduction = amount + fee;
        match token_type {
            TokenType::GU => self.balance.gu_balance -= total_deduction,
            TokenType::SU => self.balance.su_balance -= total_deduction,
        }

        Ok(transaction)
    }

    /// Calculate transaction fee based on merchant settings
    fn calculate_transaction_fee(&self, amount: u64) -> u64 {
        let fee_percentage = self.merchant_settings.transaction_fees_policy.merchant_fee_percentage;
        let calculated_fee = (amount as f64 * fee_percentage / 100.0) as u64;
        
        let min_fee = self.merchant_settings.transaction_fees_policy.minimum_fee;
        let max_fee = self.merchant_settings.transaction_fees_policy.maximum_fee;

        let fee = calculated_fee.max(min_fee);
        
        if let Some(max) = max_fee {
            fee.min(max)
        } else {
            fee
        }
    }

    /// Setup loyalty program
    pub fn setup_loyalty_program(
        &mut self,
        program_name: String,
        points_per_unit: f64,
        redemption_rate: f64,
        tiers: Vec<LoyaltyTier>,
    ) -> Result<String, WalletError> {
        let program_id = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let loyalty_program = LoyaltyProgram {
            program_id: program_id.clone(),
            program_name: program_name.clone(),
            points_per_unit,
            redemption_rate,
            member_tiers: tiers,
            expiration_policy: None,
            is_active: true,
            created_at: timestamp,
            total_members: 0,
            total_points_issued: 0,
            total_points_redeemed: 0,
        };

        self.loyalty_program = Some(loyalty_program);
        self.merchant_settings.loyalty_program_enabled = true;

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "loyalty_program_created".to_string(),
            timestamp,
        ).with_detail("program_name".to_string(), program_name)
        .with_detail("program_id".to_string(), program_id.clone());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(program_id)
    }

    /// Create promotional campaign
    pub fn create_promotional_campaign(
        &mut self,
        campaign_name: String,
        description: String,
        campaign_type: CampaignType,
        start_date: u64,
        end_date: u64,
        budget: u64,
        conditions: Vec<CampaignCondition>,
        rewards: Vec<CampaignReward>,
    ) -> Result<String, WalletError> {
        if start_date >= end_date {
            return Err(WalletError::InvalidAmount);
        }

        if budget > self.balance.total_balance() {
            return Err(WalletError::InsufficientBalance);
        }

        let campaign_id = Uuid::new_v4().to_string();

        let campaign = PromotionalCampaign {
            campaign_id: campaign_id.clone(),
            campaign_name: campaign_name.clone(),
            description,
            campaign_type,
            start_date,
            end_date,
            budget,
            spent: 0,
            target_audience: TargetAudience {
                customer_tiers: Vec::new(),
                age_range: None,
                location_restrictions: Vec::new(),
                spending_history: None,
            },
            conditions,
            rewards,
            is_active: true,
            metrics: CampaignMetrics {
                participants: 0,
                total_savings_provided: 0,
                conversion_rate: 0.0,
                customer_acquisition: 0,
                repeat_customers: 0,
            },
        };

        self.promotional_campaigns.push(campaign);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add audit log entry
        let audit_entry = AuditLogEntry::new(
            Uuid::new_v4().to_string(),
            self.config.wallet_id.clone(),
            "promotional_campaign_created".to_string(),
            timestamp,
        ).with_detail("campaign_name".to_string(), campaign_name)
        .with_detail("campaign_id".to_string(), campaign_id.clone())
        .with_detail("budget".to_string(), budget.to_string());

        self.audit_log.push(audit_entry);
        self.config.updated_at = timestamp;

        Ok(campaign_id)
    }

    /// Get merchant statistics
    pub fn get_merchant_stats(&self) -> MerchantStats {
        let active_campaigns = self.promotional_campaigns.iter()
            .filter(|c| c.is_active)
            .count();

        let total_campaign_budget = self.promotional_campaigns.iter()
            .map(|c| c.budget)
            .sum();

        let total_campaign_spent = self.promotional_campaigns.iter()
            .map(|c| c.spent)
            .sum();

        MerchantStats {
            business_name: self.merchant_info.business_name.clone(),
            verification_status: self.merchant_info.verification_status.clone(),
            total_balance: self.balance.total_balance(),
            gu_balance: self.balance.gu_balance,
            su_balance: self.balance.su_balance,
            active_hooks: self.smart_contract_hooks.iter().filter(|h| h.is_active).count(),
            loyalty_program_active: self.loyalty_program.is_some(),
            loyalty_members: self.loyalty_program.as_ref().map(|p| p.total_members).unwrap_or(0),
            active_campaigns,
            total_campaign_budget,
            total_campaign_spent,
            transaction_count: self.transaction_history.transactions.len(),
            registration_date: self.merchant_info.registration_date,
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

// Supporting structures for hook execution
#[derive(Debug, Clone)]
pub struct HookExecutionContext {
    pub customer_address: Option<String>,
    pub transaction_amount: Option<u64>,
    pub product_ids: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct HookExecutionResult {
    pub hook_id: String,
    pub success: bool,
    pub message: String,
    pub data: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ActionExecutionResult {
    pub success: bool,
    pub message: String,
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantStats {
    pub business_name: String,
    pub verification_status: VerificationStatus,
    pub total_balance: u64,
    pub gu_balance: u64,
    pub su_balance: u64,
    pub active_hooks: usize,
    pub loyalty_program_active: bool,
    pub loyalty_members: u64,
    pub active_campaigns: usize,
    pub total_campaign_budget: u64,
    pub total_campaign_spent: u64,
    pub transaction_count: usize,
    pub registration_date: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_merchant_info() -> MerchantInfo {
        MerchantInfo {
            business_name: "Test Store".to_string(),
            business_type: BusinessType::Retail,
            registration_number: Some("REG123".to_string()),
            tax_id: Some("TAX456".to_string()),
            address: MerchantAddress {
                street: "123 Main St".to_string(),
                city: "Test City".to_string(),
                state: "Test State".to_string(),
                postal_code: "12345".to_string(),
                country: "Test Country".to_string(),
            },
            contact_info: ContactInfo {
                email: "test@teststore.com".to_string(),
                phone: Some("+1234567890".to_string()),
                website: Some("https://teststore.com".to_string()),
                social_media: HashMap::new(),
            },
            verification_status: VerificationStatus::Pending,
            registration_date: 1640995200,
            last_active: 1640995200,
        }
    }

    #[test]
    fn test_merchant_wallet_creation() {
        let merchant_info = create_test_merchant_info();
        let wallet = MerchantWallet::new(merchant_info).unwrap();

        assert_eq!(wallet.merchant_info.business_name, "Test Store");
        assert_eq!(wallet.config.wallet_type, WalletType::Merchant);
        assert!(wallet.smart_contract_hooks.is_empty());
    }

    #[test]
    fn test_add_smart_contract_hook() {
        let merchant_info = create_test_merchant_info();
        let mut wallet = MerchantWallet::new(merchant_info).unwrap();

        let hook_id = wallet.add_smart_contract_hook(
            HookType::LoyaltyPointCalculator,
            TriggerCondition::OnTransaction,
            HookAction::AwardLoyaltyPoints(10),
        ).unwrap();

        assert_eq!(wallet.smart_contract_hooks.len(), 1);
        assert_eq!(wallet.smart_contract_hooks[0].hook_id, hook_id);
        assert!(wallet.smart_contract_hooks[0].is_active);
    }

    #[test]
    fn test_loyalty_program_setup() {
        let merchant_info = create_test_merchant_info();
        let mut wallet = MerchantWallet::new(merchant_info).unwrap();

        let tiers = vec![
            LoyaltyTier {
                tier_name: "Bronze".to_string(),
                minimum_points: 0,
                benefits: vec!["Basic rewards".to_string()],
                multiplier: 1.0,
                special_rewards: Vec::new(),
            }
        ];

        let program_id = wallet.setup_loyalty_program(
            "Test Loyalty Program".to_string(),
            1.0, // 1 point per unit
            100.0, // 100 points = 1 unit
            tiers,
        ).unwrap();

        assert!(wallet.loyalty_program.is_some());
        assert!(wallet.merchant_settings.loyalty_program_enabled);
        
        let program = wallet.loyalty_program.unwrap();
        assert_eq!(program.program_id, program_id);
        assert_eq!(program.program_name, "Test Loyalty Program");
    }
}
