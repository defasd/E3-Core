use clap::{Arg, Command};
use e3_core_lib::wallet::*;
use e3_core_lib::wallet::merchant_wallet::*;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("E3 Wallet CLI")
        .version("1.0")
        .about("Command-line interface for E3 Wallet System")
        .subcommand(
            Command::new("demo")
                .about("Run the complete wallet system demonstration")
        )
        .subcommand(
            Command::new("create-user")
                .about("Create a new user wallet")
                .arg(Arg::new("did")
                    .long("did")
                    .value_name("DID")
                    .help("Decentralized Identifier for the user"))
        )
        .subcommand(
            Command::new("create-treasury")
                .about("Create a new treasury wallet")
                .arg(Arg::new("address")
                    .long("address")
                    .value_name("ADDRESS")
                    .help("Treasury wallet address")
                    .required(true))
                .arg(Arg::new("admins")
                    .long("admins")
                    .value_name("ADDRESSES")
                    .help("Comma-separated list of admin addresses")
                    .required(true))
                .arg(Arg::new("threshold")
                    .long("threshold")
                    .value_name("NUMBER")
                    .help("Required number of signatures")
                    .required(true))
        )
        .subcommand(
            Command::new("create-validator")
                .about("Create a new validator wallet")
                .arg(Arg::new("operator")
                    .long("operator")
                    .value_name("OPERATOR_ID")
                    .help("Validator operator ID")
                    .required(true))
                .arg(Arg::new("name")
                    .long("name")
                    .value_name("NAME")
                    .help("Validator name")
                    .required(true))
                .arg(Arg::new("stake")
                    .long("minimum-stake")
                    .value_name("AMOUNT")
                    .help("Minimum stake amount")
                    .required(true))
                .arg(Arg::new("commission")
                    .long("commission")
                    .value_name("PERCENTAGE")
                    .help("Commission rate (0.0-100.0)")
                    .required(true))
        )
        .subcommand(
            Command::new("create-merchant")
                .about("Create a new merchant wallet")
                .arg(Arg::new("name")
                    .long("business-name")
                    .value_name("NAME")
                    .help("Business name")
                    .required(true))
                .arg(Arg::new("email")
                    .long("email")
                    .value_name("EMAIL")
                    .help("Business email")
                    .required(true))
                .arg(Arg::new("type")
                    .long("type")
                    .value_name("TYPE")
                    .help("Business type (retail, restaurant, online, service, etc.)"))
        )
        .subcommand(
            Command::new("stats")
                .about("Show wallet system statistics")
        )
        .subcommand(
            Command::new("balance")
                .about("Check the balance of a wallet")
                .arg(Arg::new("wallet-id")
                    .long("wallet-id")
                    .value_name("WALLET_ID")
                    .help("The wallet ID to check")
                    .required(true))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("demo", _)) => {
            println!("🚀 Running E3 Wallet System demonstration...\n");
            run_demonstration()?;
        }
        Some(("create-user", sub_matches)) => {
            let did = sub_matches.get_one::<String>("did").map(|s| s.clone());
            create_user_wallet_interactive(did)?;
        }
        Some(("create-treasury", sub_matches)) => {
            let address = sub_matches.get_one::<String>("address").unwrap().clone();
            let admins: Vec<String> = sub_matches.get_one::<String>("admins").unwrap()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            let threshold: u32 = sub_matches.get_one::<String>("threshold").unwrap().parse()?;
            create_treasury_wallet_interactive(address, admins, threshold)?;
        }
        Some(("create-validator", sub_matches)) => {
            let operator = sub_matches.get_one::<String>("operator").unwrap().clone();
            let name = sub_matches.get_one::<String>("name").unwrap().clone();
            let minimum_stake: u64 = sub_matches.get_one::<String>("stake").unwrap().parse()?;
            let commission: f64 = sub_matches.get_one::<String>("commission").unwrap().parse()?;
            create_validator_wallet_interactive(operator, name, minimum_stake, commission)?;
        }
        Some(("create-merchant", sub_matches)) => {
            let business_name = sub_matches.get_one::<String>("name").unwrap().clone();
            let email = sub_matches.get_one::<String>("email").unwrap().clone();
            let business_type = match sub_matches.get_one::<String>("type").map(|s| s.as_str()).unwrap_or("retail") {
                "retail" => BusinessType::Retail,
                "restaurant" => BusinessType::Restaurant,
                "online" => BusinessType::OnlineStore,
                "service" => BusinessType::Service,
                "entertainment" => BusinessType::Entertainment,
                "healthcare" => BusinessType::Healthcare,
                "education" => BusinessType::Education,
                other => BusinessType::Other(other.to_string()),
            };
            create_merchant_wallet_interactive(business_name, email, business_type)?;
        }
        Some(("balance", sub_matches)) => {
            let wallet_id = sub_matches.get_one::<String>("wallet-id").unwrap();
            let wallet_manager = WalletManager::new();
            match wallet_manager.get_wallet_balance(wallet_id) {
                Ok(balance) => {
                    println!("\n💰 Balance for wallet {}:", wallet_id);
                    println!("   GU: {}", balance.gu_balance);
                    println!("   SU: {}", balance.su_balance);
                }
                Err(e) => {
                    println!("❌ Error: {}", e);
                }
            }
        }
        Some(("stats", _)) => {
            show_wallet_statistics()?;
        }
        _ => {
            println!("No subcommand provided. Use --help for usage information.");
        }
    }

    Ok(())
}

fn run_demonstration() -> Result<(), Box<dyn std::error::Error>> {
    // Run the demonstration directly here
    println!("🌟 E3 Wallet System - CLI Demonstration");
    println!("======================================\n");

    // Initialize the Wallet Manager
    let wallet_manager = WalletManager::new();

    // Create sample wallets
    println!("📦 Creating Treasury Wallet...");
    let treasury_id = wallet_manager.create_treasury_wallet(
        "E3treasury_cli_demo".to_string(),
        vec!["admin1".to_string(), "admin2".to_string()],
        2,
    )?;
    println!("✅ Treasury created: {}\n", treasury_id);

    println!("👤 Creating User Wallet...");
    let user_id = wallet_manager.create_user_wallet(Some("did:e3:cli:demo".to_string()))?;
    println!("✅ User wallet created: {}\n", user_id);

    println!("🔐 Creating Validator Wallet...");
    let validator_id = wallet_manager.create_validator_wallet(
        "cli_validator".to_string(),
        "CLI Demo Validator".to_string(),
        vec![1, 2, 3, 4],
        10000,
        5.0,
    )?;
    println!("✅ Validator created: {}\n", validator_id);

    // Show final stats
    let stats = wallet_manager.get_system_stats();
    println!("📊 Final Statistics:");
    println!("   Total Wallets: {}", stats.total_wallets);
    println!("   User: {}, Treasury: {}, Validator: {}", 
             stats.total_user_wallets, stats.total_treasury_wallets, stats.total_validator_wallets);

    println!("\n🎉 E3 Wallet CLI demonstration completed!");
    Ok(())
}

fn create_user_wallet_interactive(did_id: Option<String>) -> Result<(), WalletError> {
    println!("👤 Creating User Wallet...");
    
    let wallet_manager = WalletManager::new();
    let (wallet_id, private_key) = wallet_manager.create_user_wallet_with_key(did_id.clone())?;
    
    println!("✅ User Wallet Created Successfully!");
    println!("   Wallet ID: {}", wallet_id);
    if let Some(did) = did_id {
        println!("   DID: {}", did);
    }
    println!("   Type: User Wallet");
    println!("   Features: Multi-token support (GU/SU), Multi-address, DID integration");
    println!("   ⚠️  Save your private key securely!\n   Private Key: {}", private_key);
    
    Ok(())
}

fn create_treasury_wallet_interactive(
    address: String,
    admin_addresses: Vec<String>,
    required_signatures: u32,
) -> Result<(), WalletError> {
    println!("📦 Creating Treasury Wallet...");
    
    let wallet_manager = WalletManager::new();
    let (wallet_id, private_key) = wallet_manager.create_treasury_wallet_with_key(
        address.clone(),
        admin_addresses.clone(),
        required_signatures,
    )?;
    
    println!("✅ Treasury Wallet Created Successfully!");
    println!("   Wallet ID: {}", wallet_id);
    println!("   Address: {}", address);
    println!("   Multi-sig: {}-of-{}", required_signatures, admin_addresses.len());
    println!("   Admin Addresses:");
    for (i, addr) in admin_addresses.iter().enumerate() {
        println!("     {}. {}", i + 1, addr);
    }
    println!("   Features: Multi-sig operations, Proof of Reserve, GU minting");
    println!("   ⚠️  Save your private key securely!\n   Private Key: {}", private_key);
    
    Ok(())
}

fn create_validator_wallet_interactive(
    operator_id: String,
    validator_name: String,
    minimum_stake: u64,
    commission_rate: f64,
) -> Result<(), WalletError> {
    println!("🔐 Creating Validator Wallet...");
    
    let wallet_manager = WalletManager::new();
    let (wallet_id, private_key) = wallet_manager.create_validator_wallet_with_key(
        operator_id.clone(),
        validator_name.clone(),
        vec![1, 2, 3, 4, 5, 6, 7, 8], // Mock public key
        minimum_stake,
        commission_rate,
    )?;
    
    println!("✅ Validator Wallet Created Successfully!");
    println!("   Wallet ID: {}", wallet_id);
    println!("   Operator ID: {}", operator_id);
    println!("   Validator Name: {}", validator_name);
    println!("   Minimum Stake: {} SU", minimum_stake);
    println!("   Commission Rate: {}%", commission_rate);
    println!("   Features: Staking, Delegation, Reward distribution, Performance tracking");
    println!("   ⚠️  Save your private key securely!\n   Private Key: {}", private_key);
    
    Ok(())
}

fn create_merchant_wallet_interactive(
    business_name: String,
    email: String,
    business_type: BusinessType,
) -> Result<(), WalletError> {
    println!("🏪 Creating Merchant Wallet...");
    
    let merchant_info = MerchantInfo {
        business_name: business_name.clone(),
        business_type: business_type.clone(),
        registration_number: None,
        tax_id: None,
        address: MerchantAddress {
            street: "TBD".to_string(),
            city: "TBD".to_string(),
            state: "TBD".to_string(),
            postal_code: "TBD".to_string(),
            country: "TBD".to_string(),
        },
        contact_info: ContactInfo {
            email: email.clone(),
            phone: None,
            website: None,
            social_media: HashMap::new(),
        },
        verification_status: VerificationStatus::Pending,
        registration_date: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        last_active: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    let wallet_manager = WalletManager::new();
    let (wallet_id, private_key) = wallet_manager.create_merchant_wallet_with_key(merchant_info)?;
    
    println!("✅ Merchant Wallet Created Successfully!");
    println!("   Wallet ID: {}", wallet_id);
    println!("   Business Name: {}", business_name);
    println!("   Business Type: {:?}", business_type);
    println!("   Email: {}", email);
    println!("   Verification Status: Pending");
    println!("   Features: Smart contract hooks, Loyalty programs, Promotional campaigns");
    println!("   ⚠️  Save your private key securely!\n   Private Key: {}", private_key);
    
    Ok(())
}

fn show_wallet_statistics() -> Result<(), Box<dyn std::error::Error>> {
    println!("📊 E3 Wallet System Statistics");
    println!("==============================");
    
    // Create a wallet manager and show basic stats
    let wallet_manager = WalletManager::new();
    let stats = wallet_manager.get_system_stats();
    
    println!("Total Wallets: {}", stats.total_wallets);
    println!("├── User Wallets: {}", stats.total_user_wallets);
    println!("├── Treasury Wallets: {}", stats.total_treasury_wallets);
    println!("├── Validator Wallets: {}", stats.total_validator_wallets);
    println!("└── Merchant Wallets: {}", stats.total_merchant_wallets);
    println!();
    println!("Total Token Balances:");
    println!("├── GU (Gold Units): {}", stats.total_gu_balance);
    println!("├── SU (Standard Units): {}", stats.total_su_balance);
    println!("└── Combined: {}", stats.total_balance);
    
    if stats.total_wallets == 0 {
        println!("\n💡 No wallets found. Use the create commands to add wallets:");
        println!("   • e3-wallet create-user --did did:e3:user:example");
        println!("   • e3-wallet create-treasury --address addr --admins addr1,addr2 --threshold 2");
        println!("   • e3-wallet create-validator --operator op1 --name 'My Validator' --minimum-stake 10000 --commission 5.0");
        println!("   • e3-wallet create-merchant --business-name 'My Store' --email store@example.com --type retail");
    }
    
    Ok(())
}
