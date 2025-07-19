mod wallet;
use std::env;
use wallet::{create_wallet, import_wallet_from_file, import_wallet_from_mnemonic, send_tokens, WalletManager, show_tx_history, cli_register_did, cli_show_did, cli_sign_vote, cli_sign_proposal};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }
    match args[1].as_str() {
        "new" => {
            let name = if args.len() > 2 { &args[2] } else { "default" };
            let password = rpassword::prompt_password("Set wallet password: ").unwrap();
            let wallet = create_wallet(name, &password);
            let manager = WalletManager::new("wallets");
            manager.save_wallet(&wallet, &password).expect("Failed to save wallet");
            println!("Wallet created! Public Key: {}", wallet.public_key);
            println!("Mnemonic: {}", wallet.mnemonic);
        }
        "import" => {
            if args.len() < 3 {
                println!("Usage: import <wallet.json> [name]");
                return;
            }
            let name = if args.len() > 3 { &args[3] } else { "default" };
            let password = rpassword::prompt_password("Set wallet password: ").unwrap();
            let wallet = import_wallet_from_file(&args[2], name, &password).expect("Failed to import wallet");
            println!("Wallet imported! Public Key: {}", wallet.public_key);
            println!("Mnemonic: {}", wallet.mnemonic);
        }
        "import-mnemonic" => {
            if args.len() < 3 {
                println!("Usage: import-mnemonic <mnemonic> [name]");
                return;
            }
            let name = if args.len() > 3 { &args[3] } else { "default" };
            let password = rpassword::prompt_password("Set wallet password: ").unwrap();
            let wallet = import_wallet_from_mnemonic(name, &args[2], &password);
            let manager = WalletManager::new("wallets");
            manager.save_wallet(&wallet, &password).expect("Failed to save wallet");
            println!("Wallet imported! Public Key: {}", wallet.public_key);
            println!("Mnemonic: {}", wallet.mnemonic);
        }
        "balance" => {
            let name = if args.len() > 2 { &args[2] } else { "default" };
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            let manager = WalletManager::new("wallets");
            let wallet = manager.load_wallet(name, &password).expect("Failed to load wallet");
            println!("GU Balance: {}", wallet.gu_balance);
            println!("SU Balance: {}", wallet.su_balance);
        }
        "send" => {
            if args.len() < 5 {
                println!("Usage: send <to_pubkey> <amount> <GU|SU> [wallet_name]");
                return;
            }
            let name = if args.len() > 5 { &args[5] } else { "default" };
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            let manager = WalletManager::new("wallets");
            let mut wallet = manager.load_wallet(name, &password).expect("Failed to load wallet");
            let to = &args[2];
            let amount: u64 = args[3].parse().expect("Invalid amount");
            let unit = &args[4];
            send_tokens(&mut wallet, to, amount, unit);
            manager.save_wallet(&wallet, &password).expect("Failed to update wallet");
        }
        "list" => {
            let manager = WalletManager::new("wallets");
            let wallets = manager.list_wallets();
            println!("Available wallets:");
            for w in wallets {
                println!("- {}", w);
            }
        }
        "view" => {
            if args.len() < 3 {
                println!("Usage: view <wallet_name>");
                return;
            }
            let name = &args[2];
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            let manager = WalletManager::new("wallets");
            match manager.load_wallet(name, &password) {
                Ok(wallet) => {
                    println!("Wallet loaded!");
                    println!("Name: {}", wallet.name);
                    println!("Address: {}", wallet.address);
                    println!("Mnemonic: {}", wallet.mnemonic);
                    // Fetch and display live balances
                    if let Some((gu, su)) = wallet::fetch_balances(&wallet.address) {
                        println!("GU Balance (live): {}", gu);
                        println!("SU Balance (live): {}", su);
                    } else {
                        println!("Could not fetch live balances.");
                    }
                    println!("DID: {}", wallet.did.as_deref().unwrap_or("None"));
                }
                Err(_) => println!("Failed to load wallet. Wrong name or password?"),
            }
        }
        "history" => {
            if args.len() < 3 {
                println!("Usage: history <wallet_name>");
                return;
            }
            let name = &args[2];
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            let manager = WalletManager::new("wallets");
            match manager.load_wallet(name, &password) {
                Ok(wallet) => {
                    println!("Transaction history for {}:", wallet.name);
                    show_tx_history(&wallet);
                }
                Err(_) => println!("Failed to load wallet. Wrong name or password?"),
            }
        }
        "did-register" => {
            if args.len() < 3 {
                println!("Usage: did-register <wallet_name>");
                return;
            }
            let name = &args[2];
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            cli_register_did(name, &password);
        }
        "did" => {
            if args.len() < 3 {
                println!("Usage: did <wallet_name>");
                return;
            }
            let name = &args[2];
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            cli_show_did(name, &password);
        }
        "vote" => {
            if args.len() < 5 {
                println!("Usage: vote <wallet_name> <proposal_id> <choice>");
                println!("Choices: yes/no/abstain");
                return;
            }
            let name = &args[2];
            let proposal_id = &args[3];
            let choice = &args[4];
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            cli_sign_vote(name, &password, proposal_id, choice);
        }
        "proposal-sign" => {
            if args.len() < 7 {
                println!("Usage: proposal-sign <wallet_name> <title> <description> <category> <voting_duration_hours>");
                return;
            }
            let name = &args[2];
            let title = &args[3];
            let description = &args[4];
            let category = &args[5];
            let duration: u64 = args[6].parse().unwrap_or_else(|_| {
                println!("Error: Invalid voting duration hours");
                std::process::exit(1);
            });
            let password = rpassword::prompt_password("Wallet password: ").unwrap();
            cli_sign_proposal(name, &password, title, description, category, duration);
        }
        _ => print_help(),
    }
}

fn print_help() {
    println!("E3 Wallet CLI");
    println!("Usage:");
    println!("  new <wallet_name>                - Create a new wallet");
    println!("  import <wallet.json> [name]      - Import wallet from file");
    println!("  import-mnemonic <mnemonic> [name] - Import wallet from mnemonic");
    println!("  balance [wallet_name]            - Show wallet balances");
    println!("  send <to> <amount> <GU|SU> [wallet_name] - Send tokens");
    println!("  list                             - List all wallets");
    println!("  view <wallet_name>               - View wallet info");
    println!("  history <wallet_name>            - Show transaction history");
    println!("  did-register <wallet_name>       - Register a DID for the wallet and update the wallet file");
    println!("  did <wallet_name>                - Show DID");
    println!("  vote <wallet_name> <proposal_id> <choice> - Vote on a proposal (choices: yes/no/abstain)");
}
