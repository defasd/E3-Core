/// E3 Wallet System Integration Examples
/// 
/// This file demonstrates how to use the comprehensive E3 Wallet System
/// that we've just created. It shows practical examples of all wallet types
/// and their key features.

use e3_core_blockchain::wallet::*;
use e3_core_blockchain::wallet::merchant_wallet::*;
use std::collections::HashMap;

/// Example: Setting up a complete E3 Wallet ecosystem
pub fn example_complete_wallet_setup() -> Result<(), WalletError> {
    println!("🚀 Setting up E3 Wallet System...");

    // 1. Initialize the Wallet Manager
    let wallet_manager = WalletManager::new();

    // 2. Create Treasury Wallet (Multi-sig with admin nodes)
    println!("📦 Creating Treasury Wallet...");
    let admin_addresses = vec![
        "E3admin1_address".to_string(),
        "E3admin2_address".to_string(),
        "E3admin3_address".to_string(),
    ];
    
    let treasury_id = wallet_manager.create_treasury_wallet(
        "E3treasury_main_address".to_string(),
        admin_addresses,
        2, // 2-of-3 multi-sig
    )?;
    println!("✅ Treasury Wallet created: {}", treasury_id);

    // 3. Create User Wallets
    println!("👤 Creating User Wallets...");
    let user1_id = wallet_manager.create_user_wallet(Some("did:e3:user:alice".to_string()))?;
    let user2_id = wallet_manager.create_user_wallet(Some("did:e3:user:bob".to_string()))?;
    println!("✅ User wallets created: {} and {}", user1_id, user2_id);

    // 4. Create Validator Wallet
    println!("🔐 Creating Validator Wallet...");
    let validator_id = wallet_manager.create_validator_wallet(
        "operator_node_1".to_string(),
        "E3 Validator Alpha".to_string(),
        vec![1, 2, 3, 4, 5], // Mock public key
        10000, // Minimum stake: 10,000 SU
        5.0,   // 5% commission rate
    )?;
    println!("✅ Validator Wallet created: {}", validator_id);

    // 5. Create Merchant Wallet
    println!("🏪 Creating Merchant Wallet...");
    let merchant_info = MerchantInfo {
        business_name: "Golden Coffee Shop".to_string(),
        business_type: BusinessType::Restaurant,
        registration_number: Some("REG123456".to_string()),
        tax_id: Some("TAX789012".to_string()),
        address: MerchantAddress {
            street: "123 Blockchain Avenue".to_string(),
            city: "Crypto City".to_string(),
            state: "Digital State".to_string(),
            postal_code: "12345".to_string(),
            country: "E3 Republic".to_string(),
        },
        contact_info: ContactInfo {
            email: "hello@goldencoffee.e3".to_string(),
            phone: Some("+1-555-E3-GOLD".to_string()),
            website: Some("https://goldencoffee.e3".to_string()),
            social_media: HashMap::new(),
        },
        verification_status: VerificationStatus::Verified,
        registration_date: 1640995200,
        last_active: 1640995200,
    };

    let merchant_id = wallet_manager.create_merchant_wallet(merchant_info)?;
    println!("✅ Merchant Wallet created: {}", merchant_id);

    // 6. Display System Statistics
    let stats = wallet_manager.get_system_stats();
    println!("\n📊 E3 Wallet System Statistics:");
    println!("   Total Wallets: {}", stats.total_wallets);
    println!("   User Wallets: {}", stats.total_user_wallets);
    println!("   Treasury Wallets: {}", stats.total_treasury_wallets);
    println!("   Validator Wallets: {}", stats.total_validator_wallets);
    println!("   Merchant Wallets: {}", stats.total_merchant_wallets);

    Ok(())
}

/// Example: User Wallet Operations
pub fn example_user_wallet_operations() -> Result<(), WalletError> {
    println!("\n👤 User Wallet Operations Example");

    // Create a user wallet
    let mut user_wallet = UserWallet::new(Some("did:e3:user:demo".to_string()))?;
    println!("✅ Created user wallet: {}", user_wallet.config.wallet_id);

    // Add additional addresses
    let secondary_address = user_wallet.add_address(Some("Shopping Address".to_string()))?;
    let savings_address = user_wallet.add_address(Some("Savings Address".to_string()))?;
    
    println!("📍 Primary address: {}", user_wallet.get_primary_address_string());
    println!("📍 Secondary address: {}", secondary_address);
    println!("📍 Savings address: {}", savings_address);

    // Update balances (simulating received funds)
    user_wallet.update_address_balance(
        user_wallet.get_primary_address_string(),
        5000, // 5000 GU
        2000, // 2000 SU
    )?;

    // Check total balance
    let total_balance = user_wallet.get_total_balance();
    println!("💰 Total Balance: {} GU, {} SU", total_balance.gu_balance, total_balance.su_balance);

    // Create a transfer transaction
    let transfer_tx = user_wallet.create_transfer(
        user_wallet.get_primary_address_string(),
        "E3recipient_address",
        100, // Transfer 100 GU
        TokenType::GU,
        5,   // 5 GU fee
    )?;

    println!("💸 Created transfer: {} GU to recipient (Fee: {} GU)", 
             transfer_tx.amount, transfer_tx.fee);

    Ok(())
}

/// Example: Treasury Wallet Multi-Sig Operations
pub fn example_treasury_operations() -> Result<(), WalletError> {
    println!("\n📦 Treasury Wallet Multi-Sig Example");

    let admin_addresses = vec![
        "E3admin1".to_string(),
        "E3admin2".to_string(),
        "E3admin3".to_string(),
    ];

    let mut treasury = TreasuryWallet::new(
        "E3treasury_address".to_string(),
        admin_addresses,
        2, // Require 2 signatures
    )?;

    println!("✅ Treasury created with 2-of-3 multi-sig");

    // Create a mint proposal
    let mut mint_proposal = treasury.create_mint_proposal(
        "E3user_beneficiary".to_string(),
        1000, // Mint 1000 GU
        "E3admin1".to_string(),
        "Initial token distribution for new user program".to_string(),
    )?;

    println!("📝 Mint proposal created: {} GU", mint_proposal.transaction.amount);

    // Admin 1 signs the proposal
    let signature1 = WalletSignature::new(
        vec![1, 2, 3], // Mock signature
        vec![4, 5, 6], // Mock public key
    );

    let ready_after_first_sig = treasury.sign_proposal(
        &mut mint_proposal,
        "E3admin1".to_string(),
        signature1,
    )?;

    println!("✍️  Admin1 signed. Ready to execute: {}", ready_after_first_sig);

    // Admin 2 signs the proposal
    let signature2 = WalletSignature::new(
        vec![7, 8, 9],   // Mock signature
        vec![10, 11, 12], // Mock public key
    );

    let ready_after_second_sig = treasury.sign_proposal(
        &mut mint_proposal,
        "E3admin2".to_string(),
        signature2,
    )?;

    println!("✍️  Admin2 signed. Ready to execute: {}", ready_after_second_sig);

    // Execute the proposal (threshold met)
    if ready_after_second_sig {
        treasury.execute_proposal(&mut mint_proposal)?;
        println!("🚀 Mint proposal executed successfully!");
    }

    // Display treasury stats
    let stats = treasury.get_treasury_stats();
    println!("📊 Treasury Stats: {} GU minted, {} total signers",
             stats.total_minted, stats.admin_count);

    Ok(())
}

/// Example: Validator Wallet Staking Operations
pub fn example_validator_operations() -> Result<(), WalletError> {
    println!("\n🔐 Validator Wallet Staking Example");

    let mut validator = ValidatorWallet::new(
        "validator_operator_1".to_string(),
        "E3 Gold Validator".to_string(),
        vec![1, 2, 3, 4, 5, 6, 7, 8], // Mock public key
        10000, // Minimum stake
        3.5,   // 3.5% commission
    )?;

    println!("✅ Validator created: {}", validator.validator_metadata.validator_name);

    // Set initial balance (validator receives tokens to stake)
    validator.balance.su_balance = 15000;

    // Stake tokens to become active
    let stake_tx = validator.stake(12000, TokenType::SU)?;
    println!("🔒 Staked {} SU. Validator active: {}", 
             stake_tx.amount, validator.validator_metadata.is_active);

    // Simulate delegation from another user
    validator.add_delegation("E3delegator1".to_string(), 5000)?;
    validator.add_delegation("E3delegator2".to_string(), 3000)?;

    println!("👥 Received delegations. Total delegated: {} SU", 
             validator.staking_info.total_delegated);

    // Distribute rewards
    let reward_distributions = validator.distribute_rewards(1000)?;
    println!("💰 Distributed {} reward payments", reward_distributions.len());

    for distribution in reward_distributions {
        println!("   → {} SU to {} ({:?})", 
                 distribution.amount, distribution.recipient, distribution.reward_type);
    }

    // Update performance metrics
    validator.update_performance(
        50,   // blocks proposed
        95,   // blocks signed
        100,  // total blocks
        150,  // avg response time (ms)
    );

    // Get validator stats
    let stats = validator.get_validator_stats();
    println!("📊 Validator Stats:");
    println!("   Uptime: {:.2}%", stats.uptime_percentage);
    println!("   Staked: {} SU", stats.staked_amount);
    println!("   Delegated: {} SU", stats.total_delegated);
    println!("   Total Rewards: {} SU", stats.total_rewards);

    Ok(())
}

/// Example: Merchant Wallet with Smart Contracts and Loyalty
pub fn example_merchant_operations() -> Result<(), WalletError> {
    println!("\n🏪 Merchant Wallet Smart Contract Example");

    // Create merchant info
    let merchant_info = MerchantInfo {
        business_name: "E3 Digital Marketplace".to_string(),
        business_type: BusinessType::OnlineStore,
        registration_number: Some("E3-MARKET-001".to_string()),
        tax_id: Some("TAX-E3-789".to_string()),
        address: MerchantAddress {
            street: "456 E3 Commerce Blvd".to_string(),
            city: "Token Town".to_string(),
            state: "Blockchain State".to_string(),
            postal_code: "54321".to_string(),
            country: "E3 Republic".to_string(),
        },
        contact_info: ContactInfo {
            email: "support@e3marketplace.gold".to_string(),
            phone: Some("+1-555-E3-SHOP".to_string()),
            website: Some("https://marketplace.e3.gold".to_string()),
            social_media: HashMap::new(),
        },
        verification_status: VerificationStatus::Verified,
        registration_date: 1640995200,
        last_active: 1704067200,
    };

    let mut merchant = MerchantWallet::new(merchant_info)?;
    println!("✅ Merchant created: {}", merchant.merchant_info.business_name);

    // Set up smart contract hooks
    let loyalty_hook_id = merchant.add_smart_contract_hook(
        HookType::LoyaltyPointCalculator,
        TriggerCondition::OnTransaction,
        HookAction::AwardLoyaltyPoints(10), // 10 points per transaction
    )?;

    let discount_hook_id = merchant.add_smart_contract_hook(
        HookType::DiscountApplicator,
        TriggerCondition::OnAmountThreshold(1000), // Discount for orders > 1000
        HookAction::ApplyDiscount(5.0), // 5% discount
    )?;

    println!("🔗 Added smart contract hooks:");
    println!("   Loyalty Hook: {}", loyalty_hook_id);
    println!("   Discount Hook: {}", discount_hook_id);

    // Set up loyalty program
    let loyalty_tiers = vec![
        LoyaltyTier {
            tier_name: "Bronze".to_string(),
            minimum_points: 0,
            benefits: vec!["Basic rewards".to_string()],
            multiplier: 1.0,
            special_rewards: vec![],
        },
        LoyaltyTier {
            tier_name: "Gold".to_string(),
            minimum_points: 1000,
            benefits: vec!["Enhanced rewards".to_string(), "Priority support".to_string()],
            multiplier: 1.5,
            special_rewards: vec![
                SpecialReward {
                    reward_name: "Free E3 Coffee Mug".to_string(),
                    cost_in_points: 500,
                    description: "Exclusive E3-branded coffee mug".to_string(),
                    expiry_date: None,
                    quantity_available: Some(100),
                }
            ],
        },
    ];

    let loyalty_program_id = merchant.setup_loyalty_program(
        "E3 Marketplace Rewards".to_string(),
        1.0,   // 1 point per SU spent
        100.0, // 100 points = 1 SU
        loyalty_tiers,
    )?;

    println!("🎁 Loyalty program created: {}", loyalty_program_id);

    // Create promotional campaign
    let campaign_conditions = vec![
        CampaignCondition::MinimumPurchase(500),
        CampaignCondition::TimeWindow { 
            start: 1704067200, 
            end: 1706745600 
        },
    ];

    let campaign_rewards = vec![
        CampaignReward {
            reward_type: RewardType::DiscountPercentage,
            value: 15, // 15% off
            max_per_customer: Some(1),
            total_available: Some(1000),
            used_count: 0,
        }
    ];

    let campaign_id = merchant.create_promotional_campaign(
        "E3 New Year Sale".to_string(),
        "Celebrate the new year with exclusive E3 discounts!".to_string(),
        CampaignType::SeasonalPromotion,
        1704067200, // Start date
        1706745600, // End date  
        50000,      // 50,000 SU budget
        campaign_conditions,
        campaign_rewards,
    )?;

    println!("🎉 Promotional campaign created: {}", campaign_id);

    // Execute smart contract hooks (simulate customer transaction)
    let hook_context = HookExecutionContext {
        customer_address: Some("E3customer_alice".to_string()),
        transaction_amount: Some(1200), // Above threshold for discount
        product_ids: vec!["PROD001".to_string(), "PROD002".to_string()],
        metadata: HashMap::new(),
    };

    let hook_results = merchant.execute_hooks(
        &TriggerCondition::OnTransaction,
        &hook_context,
    )?;

    println!("⚡ Smart contract hooks executed:");
    for result in hook_results {
        println!("   Hook {}: {} - {}", result.hook_id, 
                 if result.success { "✅" } else { "❌" }, result.message);
    }

    // Get merchant stats
    let stats = merchant.get_merchant_stats();
    println!("📊 Merchant Stats:");
    println!("   Business: {}", stats.business_name);
    println!("   Total Balance: {} tokens", stats.total_balance);
    println!("   Active Hooks: {}", stats.active_hooks);
    println!("   Loyalty Program: {}", if stats.loyalty_program_active { "Active" } else { "Inactive" });
    println!("   Active Campaigns: {}", stats.active_campaigns);

    Ok(())
}

/// Example: Proof of Reserve for Treasury
pub fn example_proof_of_reserve() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 Proof of Reserve Example");

    // Create backing assets
    let backing_assets = vec![
        BackingAsset {
            asset_id: "GOLD_BAR_001".to_string(),
            asset_type: AssetType::PhysicalGold,
            amount: 1000000, // 1,000 kg of gold (in grams)
            location: "E3 Secure Vault - New York".to_string(),
            custodian: "E3 Trusted Custody Inc.".to_string(),
            verification_method: "Physical inspection + XRF analysis".to_string(),
            last_verified: 1704067200,
            certificates: vec!["LBMA_CERT_001".to_string(), "ISO_AUDIT_2024".to_string()],
        },
        BackingAsset {
            asset_id: "GOLD_BAR_002".to_string(),
            asset_type: AssetType::PhysicalGold,
            amount: 500000, // 500 kg of gold
            location: "E3 Secure Vault - London".to_string(),
            custodian: "E3 International Custody Ltd.".to_string(),
            verification_method: "Physical inspection + Chemical assay".to_string(),
            last_verified: 1704067200,
            certificates: vec!["LBMA_CERT_002".to_string()],
        },
    ];

    // Create auditor attestation
    let attestation = ReserveAttestation {
        auditor_id: "E3_AUDIT_001".to_string(),
        auditor_name: "E3 Certified Auditors LLC".to_string(),
        audit_date: 1704067200,
        audit_report_hash: "sha256:abcd1234567890...".to_string(),
        signature: "ed25519:signature_data_here...".to_string(),
        validity_period: 31536000, // 1 year
        next_audit_due: 1735689600, // Next year
    };

    // Create proof of reserve
    let mut proof = ProofOfReserve::new(
        "E3treasury_main_address".to_string(),
        backing_assets,
        attestation,
    );

    println!("✅ Proof of Reserve created");
    println!("   Reserve ID: {}", proof.reserve_id);
    println!("   Total Reserves: {} grams of gold", proof.total_reserves);

    // Update with current GU issuance (simulate 1.2M GU tokens issued)
    proof.update_issuance(1200000);
    println!("   Current GU Issued: {}", proof.metadata.total_gu_issued);
    println!("   Reserve Ratio: {:.2}%", proof.metadata.reserve_ratio);

    // Verify the proof
    match proof.verify() {
        Ok(true) => println!("✅ Proof of Reserve verification: PASSED"),
        Ok(false) => println!("❌ Proof of Reserve verification: FAILED"),
        Err(error) => println!("⚠️  Proof of Reserve verification error: {}", error),
    }

    // Get reserve statistics
    let reserve_stats = proof.get_reserve_stats();
    println!("📊 Reserve Statistics:");
    println!("   Total Physical Gold: {} grams", reserve_stats.total_reserves);
    println!("   Reserve Ratio: {:.2}%", reserve_stats.reserve_ratio);
    println!("   Asset Count: {}", reserve_stats.asset_count);
    println!("   Compliance: {:?}", reserve_stats.compliance_standards);

    // Export proof for external verification
    let proof_export = proof.export_proof();
    println!("📤 Proof Export (for external verification):");
    println!("   Merkle Root: {}", proof_export.merkle_root);
    println!("   Proof Hash: {}", proof_export.proof_hash);
    println!("   Auditor: {}", proof_export.auditor_name);

    Ok(())
}

/// Main demonstration function
pub fn demonstrate_e3_wallet_system() {
    println!("🌟 E3 Wallet System - Comprehensive Demonstration");
    println!("==================================================\n");

    // Run all examples
    if let Err(e) = example_complete_wallet_setup() {
        println!("❌ Setup error: {}", e);
        return;
    }

    if let Err(e) = example_user_wallet_operations() {
        println!("❌ User wallet error: {}", e);
        return;
    }

    if let Err(e) = example_treasury_operations() {
        println!("❌ Treasury error: {}", e);
        return;
    }

    if let Err(e) = example_validator_operations() {
        println!("❌ Validator error: {}", e);
        return;
    }

    if let Err(e) = example_merchant_operations() {
        println!("❌ Merchant error: {}", e);
        return;
    }

    if let Err(e) = example_proof_of_reserve() {
        println!("❌ Proof of Reserve error: {}", e);
        return;
    }

    println!("\n🎉 E3 Wallet System demonstration completed successfully!");
    println!("\n📋 Summary of Features Demonstrated:");
    println!("   ✅ Multi-type wallet creation (User, Treasury, Validator, Merchant)");
    println!("   ✅ Multi-signature treasury operations");
    println!("   ✅ Validator staking and delegation");
    println!("   ✅ Merchant smart contract hooks");
    println!("   ✅ Loyalty programs and promotional campaigns");
    println!("   ✅ Proof of Reserve with physical gold backing");
    println!("   ✅ Comprehensive transaction processing");
    println!("   ✅ Audit logging and compliance tracking");
    println!("\n🔗 The E3 Wallet System is ready for integration!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_wallet_demo() {
        // This test ensures all our examples compile and run without panicking
        assert!(example_complete_wallet_setup().is_ok());
        assert!(example_user_wallet_operations().is_ok());
        assert!(example_treasury_operations().is_ok());
        assert!(example_validator_operations().is_ok());
        assert!(example_merchant_operations().is_ok());
        assert!(example_proof_of_reserve().is_ok());
    }
}
