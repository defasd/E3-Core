//
// CLI Usage:
//   did-register <wallet_name>   - Register a DID for the wallet and update the wallet file
//   did <wallet_name>            - Show the DID for the wallet
//
// NOTE: These commands must be integrated in main.rs to be available from the CLI.
//
/// CLI helper: Show the DID for a wallet
pub fn cli_show_did(wallet_name: &str, password: &str) {
    let manager = WalletManager::new("wallets");
    let wallet = match manager.load_wallet(wallet_name, password) {
        Ok(w) => w,
        Err(e) => {
            println!("Failed to load wallet '{}': {}", wallet_name, e);
            return;
        }
    };
    show_did(&wallet);
}
/// CLI helper: Register a DID for a wallet and update the wallet file
pub fn cli_register_did(wallet_name: &str, password: &str) {
    let manager = WalletManager::new("wallets");
    let mut wallet = match manager.load_wallet(wallet_name, password) {
        Ok(w) => w,
        Err(e) => {
            println!("Failed to load wallet '{}': {}", wallet_name, e);
            return;
        }
    };
    request_did_from_node(&mut wallet, &manager, password);
}
// Request a DID from the governance node and update the wallet
pub fn request_did_from_node(wallet: &mut Wallet, manager: &WalletManager, password: &str) {
    let method = "example";
    let network = "testnet";
    let signature = sign_did_registration(wallet, method, network);

    let payload = serde_json::json!({
        "method": method,
        "network": network,
        "public_key": wallet.public_key,
        "wallet_address": wallet.address,
        "signature": signature
    });
    let resp = ureq::post("http://localhost:5003/api/v1/dids")
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string());

    match resp {
        Ok(response) => {
            let reader = response.into_reader();
            let json: serde_json::Value = serde_json::from_reader(reader).unwrap_or_default();
            if let Some(did) = json.get("did_id").and_then(|v| v.as_str()) {
                update_wallet_did(wallet, did, manager, password);
                println!("DID registered and linked: {}", did);
            } else {
                println!("Failed to obtain DID: {:?}", json);
            }
        }
        Err(e) => {
            println!("Error requesting DID: {}", e);
        }
    }
}
// Require a DID before voting
#[allow(dead_code)]
pub fn require_did_for_voting(wallet: &Wallet) -> bool {
    if wallet.did.is_none() {
        println!("You must register a DID before voting.");
        false
    } else {
        true
    }
}
// After successful DID registration, update and persist the wallet's DID
pub fn update_wallet_did(wallet: &mut Wallet, did: &str, manager: &WalletManager, password: &str) {
    set_did(wallet, did);
    if let Err(e) = manager.save_wallet(wallet, password) {
        println!("[WARN] Failed to save wallet with new DID: {}", e);
    }
}
// Helper to sign a DID registration with the wallet's private key
pub fn sign_did_registration(wallet: &Wallet, method: &str, network: &str) -> String {
    let message = format!("{}{}{}{}", method, network, wallet.public_key, wallet.address);
    let mut hasher = Sha256::default();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();

    let priv_bytes_vec = hex::decode(&wallet.private_key).expect("Invalid private key hex");
    let priv_bytes: [u8; 32] = priv_bytes_vec.as_slice().try_into().expect("Invalid private key length");
    let signing_key = SigningKey::from_bytes(&priv_bytes);

    let signature: Signature = signing_key.sign(&hash);
    hex::encode(signature.to_bytes())
}

// 

use ed25519_dalek::{SigningKey, Signature, Signer};
use sha2::{Sha256, Digest};
// Helper to sign a transaction with the wallet's private key
fn sign_transaction(private_key_hex: &str, from: &str, to: &str, amount: u64, token: &str) -> String {
    // Concatenate fields as a message (order matters!)
    let message = format!("{}{}{}{}", from, to, amount, token);

    // Hash the message

    let mut hasher = Sha256::default();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();

    // Decode private key from hex and convert to [u8; 32]
    let priv_bytes_vec = hex::decode(private_key_hex).expect("Invalid private key hex");
    let priv_bytes: [u8; 32] = priv_bytes_vec.as_slice().try_into().expect("Invalid private key length");
    let signing_key = SigningKey::from_bytes(&priv_bytes);

    // Sign the hash
    let signature: Signature = signing_key.sign(&hash);

    // Return as hex string
    hex::encode(signature.to_bytes())
}
// Fetch live GU/SU balances from blockchain node
// Requires: ureq and serde_json in Cargo.toml
// Example API response: { "gu_balance": 123, "su_balance": 456 }
pub fn fetch_balances(address: &str) -> Option<(u64, u64)> {
    // Change this URL to your node's actual API endpoint
    let url = format!("http://localhost:9000/api/balance/{}", address);
    let resp = match ureq::get(&url).call() {
        Ok(r) => r,
        Err(_) => return None,
    };
    let reader = resp.into_reader();
    let json: serde_json::Value = match serde_json::from_reader(reader) {
        Ok(j) => j,
        Err(_) => return None,
    };
    let data = json.get("data")?;
    let gu = data.get("GU").and_then(|v| v.as_u64()).unwrap_or(0);
    let su = data.get("SU").and_then(|v| v.as_u64()).unwrap_or(0);
    Some((gu, su))
}

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use bip39::{Language, Mnemonic};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use chrono::Utc;
use base64;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Wallet {
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub mnemonic: String,
    pub did: Option<String>,
    pub gu_balance: u64,
    pub su_balance: u64,
    pub tx_history: Vec<TxRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxRecord {
    pub tx_id: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub token: String,
    pub timestamp: u64,
    pub status: String, // "pending", "confirmed", etc.
}

pub struct WalletManager {
    pub dir: String,
    pub active: Option<String>,
}

impl WalletManager {
    pub fn new(dir: &str) -> Self {
        fs::create_dir_all(dir).ok();
        Self { dir: dir.to_string(), active: None }
    }

    pub fn list_wallets(&self) -> Vec<String> {
        fs::read_dir(&self.dir)
            .unwrap()
            .filter_map(|e| {
                let path = e.ok()?.path();
                if path.extension()? == "wallet" {
                    Some(path.file_stem()?.to_string_lossy().to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn load_wallet(&self, name: &str, password: &str) -> io::Result<Wallet> {
        let path = format!("{}/{}.wallet", self.dir, name);
        let data = fs::read(&path)?;
        let decrypted = decrypt_wallet(&data, password)?;
        let wallet: Wallet = serde_json::from_slice(&decrypted)?;
        Ok(wallet)
    }

    pub fn save_wallet(&self, wallet: &Wallet, password: &str) -> io::Result<()> {
        let path = format!("{}/{}.wallet", self.dir, wallet.name);
        let data = serde_json::to_vec(wallet)?;
        let encrypted = encrypt_wallet(&data, password)?;
        fs::write(path, encrypted)?;
        Ok(())
    }

    pub fn set_active(&mut self, name: &str) {
        self.active = Some(name.to_string());
    }
}

// Encryption helpers
fn encrypt_wallet(data: &[u8], password: &str) -> io::Result<Vec<u8>> {
    let key_bytes = Sha256::digest(password.as_bytes());
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data).map_err(|_| io::ErrorKind::Other)?;
    let mut out = nonce_bytes.to_vec();
    out.extend(ciphertext);
    Ok(out)
}

fn decrypt_wallet(data: &[u8], password: &str) -> io::Result<Vec<u8>> {
    let key_bytes = Sha256::digest(password.as_bytes());
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| io::ErrorKind::Other)?;
    Ok(plaintext)
}

// Wallet creation/import/export
pub fn create_wallet(name: &str, _password: &str) -> Wallet {
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
    let mut hasher = Sha256::default();
    hasher.update(mnemonic.to_entropy());
    let seed_hash = hasher.finalize();
    let seed: [u8; 32] = seed_hash.into();
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key();
    let address = hex::encode(public_key.to_bytes());

    Wallet {
        name: name.to_string(),
        address: address.clone(),
        public_key: address.clone(),
        private_key: hex::encode(signing_key.to_bytes()),
        mnemonic: mnemonic.to_string(),
        did: None,
        gu_balance: 0,
        su_balance: 0,
        tx_history: vec![],
    }
}

pub fn import_wallet_from_mnemonic(name: &str, mnemonic_phrase: &str, _password: &str) -> Wallet {
    let mnemonic = Mnemonic::parse(mnemonic_phrase).unwrap();
    let mut hasher = Sha256::default();
    hasher.update(mnemonic.to_entropy());
    let seed_hash = hasher.finalize();
    let seed: [u8; 32] = seed_hash.into();
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key();
    let address = hex::encode(public_key.to_bytes());

    Wallet {
        name: name.to_string(),
        address: address.clone(),
        public_key: address.clone(),
        private_key: hex::encode(signing_key.to_bytes()),
        mnemonic: mnemonic.to_string(),
        did: None,
        gu_balance: 0,
        su_balance: 0,
        tx_history: vec![],
    }
}

// DID management
pub fn set_did(wallet: &mut Wallet, did: &str) {
    wallet.did = Some(did.to_string());
    show_did(wallet);
}

pub fn show_did(wallet: &Wallet) {
    println!("DID: {}", wallet.did.as_deref().unwrap_or("None"));
}

// Token transfer (stub, expand with real HTTP call)
pub fn send_tokens(wallet: &mut Wallet, to: &str, amount: u64, token: &str) {
    // Sign the transaction
    let signature = sign_transaction(
        &wallet.private_key,
        &wallet.address,
        to,
        amount,
        token,
    );

    // Prepare the transaction payload
    let payload = serde_json::json!({
        "from": wallet.address,
        "to": to,
        "amount": amount,
        "signature": signature,
        "token": token
    });

    // Send the transaction to the public node
    let resp_result = ureq::post("http://localhost:9000/api/submit-transaction")
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string());

    match resp_result {
        Ok(_response) => {
            println!("Transaction broadcast to node!");
            let tx = TxRecord {
                tx_id: format!("tx-{}", wallet.tx_history.len() + 1),
                from: wallet.address.clone(),
                to: to.to_string(),
                amount,
                token: token.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                status: "broadcast".to_string(),
            };
            wallet.tx_history.push(tx);
        }
        Err(e) => {
            println!("Failed to broadcast transaction: {}", e);
            let tx = TxRecord {
                tx_id: format!("tx-{}", wallet.tx_history.len() + 1),
                from: wallet.address.clone(),
                to: to.to_string(),
                amount,
                token: token.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                status: "failed".to_string(),
            };
            wallet.tx_history.push(tx);
        }
    }
}

// Export/backup
pub fn export_wallet(wallet: &Wallet, path: &str) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(wallet)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn import_wallet_from_file(path: &str, _name: &str, password: &str) -> io::Result<Wallet> {
    let data = fs::read(path)?;
    let wallet: Wallet = serde_json::from_slice(&data)?;
    // Save as encrypted wallet in manager dir
    let manager = WalletManager::new("wallets");
    manager.save_wallet(&wallet, password)?;
    Ok(wallet)
}

// Show transaction history
pub fn show_tx_history(wallet: &Wallet) {
    for tx in &wallet.tx_history {
        println!("{:?}", tx);
    }
}

// ===== VOTING SYSTEM =====

/// Vote payload structure for signing
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VotePayload {
    pub did: String,
    pub proposal_id: String,
    pub vote_choice: String,
    pub timestamp: u64,
    pub nonce: String,
}

/// Proposal payload structure for signing
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProposalPayload {
    pub did: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub voting_duration_hours: u64,
    pub timestamp: u64,
    pub nonce: String,
}

/// CLI function to sign and output proposal payload
pub fn cli_sign_proposal(
    wallet_name: &str, 
    password: &str, 
    title: &str, 
    description: &str, 
    category: &str, 
    voting_duration_hours: u64
) {
    let manager = WalletManager::new("wallets");
    let wallet = match manager.load_wallet(wallet_name, password) {
        Ok(w) => w,
        Err(e) => {
            println!("Failed to load wallet '{}': {}", wallet_name, e);
            return;
        }
    };

    // Check if wallet has a DID
    let _did = match &wallet.did {
        Some(d) => d,
        None => {
            println!("Error: Wallet '{}' does not have a registered DID", wallet_name);
            println!("Please register a DID first using: did-register {}", wallet_name);
            return;
        }
    };

    // Sign the proposal
    match sign_proposal_payload(&wallet, title, description, category, voting_duration_hours) {
        Ok((payload, signature)) => {
            // Create final JSON output with signature, using submitter_did as required by backend
            let signed_proposal = serde_json::json!({
                "submitter_did": payload.did,
                "title": payload.title,
                "description": payload.description,
                "category": payload.category,
                "voting_duration_hours": payload.voting_duration_hours,
                "timestamp": payload.timestamp,
                "nonce": payload.nonce,
                "signature": signature
            });
            // Output to stdout as requested
            println!("{}", serde_json::to_string_pretty(&signed_proposal).unwrap());
        }
        Err(e) => {
            eprintln!("Failed to sign proposal: {}", e);
            std::process::exit(1);
        }
    }
}

/// Core proposal signing function
pub fn sign_proposal_payload(
    wallet: &Wallet, 
    title: &str, 
    description: &str, 
    category: &str, 
    voting_duration_hours: u64
) -> Result<(ProposalPayload, String), String> {
    // Validate DID exists
    let did = wallet.did.as_ref().ok_or("Wallet does not have a registered DID")?;
    
    // Create proposal payload
    let payload = ProposalPayload {
        did: did.clone(),
        title: title.to_string(),
        description: description.to_string(),
        category: category.to_string(),
        voting_duration_hours,
        timestamp: Utc::now().timestamp() as u64,
        nonce: generate_nonce(),
    };

    // Create message to sign (canonical format)
    let message = format!("{}:{}:{}:{}:{}:{}:{}", 
        payload.did, 
        payload.title, 
        payload.description, 
        payload.category, 
        payload.voting_duration_hours,
        payload.timestamp, 
        payload.nonce
    );

    // Hash the message
    let mut hasher = Sha256::default();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();

    // Sign with wallet's private key
    let priv_bytes_vec = hex::decode(&wallet.private_key)
        .map_err(|_| "Invalid private key hex".to_string())?;
    let priv_bytes: [u8; 32] = priv_bytes_vec.as_slice()
        .try_into()
        .map_err(|_| "Invalid private key length".to_string())?;
    let signing_key = SigningKey::from_bytes(&priv_bytes);
    
    let signature: Signature = signing_key.sign(&hash);
    let signature_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.to_bytes());

    Ok((payload, signature_b64))
}

/// CLI function to sign and submit vote
pub fn cli_sign_vote(wallet_name: &str, password: &str, proposal_id: &str, choice: &str) {
    let manager = WalletManager::new("wallets");
    let wallet = match manager.load_wallet(wallet_name, password) {
        Ok(w) => w,
        Err(e) => {
            println!("Failed to load wallet '{}': {}", wallet_name, e);
            return;
        }
    };

    // Check if wallet has a DID
    let _did = match &wallet.did {
        Some(d) => d,
        None => {
            println!("Error: Wallet '{}' does not have a registered DID", wallet_name);
            println!("Please register a DID first using: did-register {}", wallet_name);
            return;
        }
    };

    // Sign the vote
    match sign_vote_payload(&wallet, proposal_id, choice) {
        Ok((payload, signature)) => {
            println!("Vote signed successfully!");
            println!("DID: {}", payload.did);
            println!("Proposal ID: {}", payload.proposal_id);
            println!("Vote Choice: {}", payload.vote_choice);
            println!("Timestamp: {}", payload.timestamp);
            println!("Nonce: {}", payload.nonce);
            println!("Signature: {}", signature);
            
            // Submit vote to governance API
            match submit_vote_to_api(&payload, &signature) {
                Ok(response) => {
                    println!("Vote submitted successfully!");
                    println!("Response: {}", response);
                }
                Err(e) => {
                    println!("Failed to submit vote: {}", e);
                    println!("You can manually submit using the signature above.");
                }
            }
        }
        Err(e) => {
            println!("Failed to sign vote: {}", e);
        }
    }
}

/// Core vote signing function
pub fn sign_vote_payload(wallet: &Wallet, proposal_id: &str, choice: &str) -> Result<(VotePayload, String), String> {
    // Validate DID exists
    let did = wallet.did.as_ref().ok_or("Wallet does not have a registered DID")?;
    
    // Validate vote choice
    let normalized_choice = match choice.to_lowercase().as_str() {
        "yes" | "y" | "approve" | "for" => "yes",
        "no" | "n" | "reject" | "against" => "no", 
        "abstain" | "a" | "neutral" => "abstain",
        _ => return Err(format!("Invalid vote choice: {}. Use: yes/no/abstain", choice)),
    };

    // Create vote payload
    let payload = VotePayload {
        did: did.clone(),
        proposal_id: proposal_id.to_string(),
        vote_choice: normalized_choice.to_string(),
        timestamp: Utc::now().timestamp() as u64,
        nonce: generate_nonce(),
    };

    // Create message to sign (canonical format)
    let message = format!("{}:{}:{}:{}:{}", 
        payload.did, 
        payload.proposal_id, 
        payload.vote_choice, 
        payload.timestamp, 
        payload.nonce
    );

    // Hash the message
    let mut hasher = Sha256::default();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();

    // Sign with wallet's private key
    let priv_bytes_vec = hex::decode(&wallet.private_key)
        .map_err(|_| "Invalid private key hex".to_string())?;
    let priv_bytes: [u8; 32] = priv_bytes_vec.as_slice()
        .try_into()
        .map_err(|_| "Invalid private key length".to_string())?;
    let signing_key = SigningKey::from_bytes(&priv_bytes);
    
    let signature: Signature = signing_key.sign(&hash);
    let signature_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.to_bytes());

    Ok((payload, signature_b64))
}

/// Generate cryptographically secure nonce
fn generate_nonce() -> String {
    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 16];
    rng.fill_bytes(&mut nonce_bytes);
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    format!("{}_{}", timestamp, hex::encode(nonce_bytes))
}

/// Submit vote to governance API
fn submit_vote_to_api(payload: &VotePayload, signature: &str) -> Result<String, String> {
    let vote_data = serde_json::json!({
        "did": payload.did,
        "proposal_id": payload.proposal_id,
        "vote_choice": payload.vote_choice,
        "timestamp": payload.timestamp,
        "nonce": payload.nonce,
        "signature": signature
    });

    let resp = ureq::post("http://localhost:5003/api/v1/votes")
        .set("Content-Type", "application/json")
        .send_string(&vote_data.to_string())
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let response_text = resp.into_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;
    
    Ok(response_text)
}
