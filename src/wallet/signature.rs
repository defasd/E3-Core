use crate::wallet::types::WalletError;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wallet signature wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSignature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: String,
}

impl WalletSignature {
    pub fn new(signature: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            signature,
            public_key,
            algorithm: "ed25519".to_string(),
        }
    }
}

/// Signature verification service
#[derive(Debug)]
pub struct SignatureVerification;

impl SignatureVerification {
    /// Generate a new Ed25519 keypair
    pub fn generate_keypair() -> Result<Keypair, WalletError> {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        Ok(Keypair::generate(&mut csprng))
    }

    /// Sign a message with a private key
    pub fn sign_message(
        keypair: &Keypair,
        message: &[u8],
    ) -> Result<WalletSignature, WalletError> {
        let signature = keypair.sign(message);
        
        Ok(WalletSignature::new(
            signature.to_bytes().to_vec(),
            keypair.public.to_bytes().to_vec(),
        ))
    }

    /// Verify a signature against a message and public key
    pub fn verify_signature(
        signature: &WalletSignature,
        message: &[u8],
        expected_public_key: &[u8],
    ) -> Result<bool, WalletError> {
        // Verify the public key matches
        if signature.public_key != expected_public_key {
            return Ok(false);
        }

        // Parse the public key
        let public_key = PublicKey::from_bytes(&signature.public_key)
            .map_err(|_| WalletError::InvalidSignature)?;

        // Parse the signature
        let sig = Signature::from_bytes(&signature.signature)
            .map_err(|_| WalletError::InvalidSignature)?;

        // Verify the signature
        match public_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create a message hash for signing (deterministic)
    pub fn create_message_hash(
        sender: &str,
        recipient: &str,
        amount: u64,
        token_type: &str,
        nonce: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(sender.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(token_type.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify transaction signature with nonce check
    pub fn verify_transaction_signature(
        signature: &WalletSignature,
        sender: &str,
        recipient: &str,
        amount: u64,
        token_type: &str,
        nonce: u64,
        timestamp: u64,
        sender_public_key: &[u8],
    ) -> Result<bool, WalletError> {
        let message_hash = Self::create_message_hash(
            sender,
            recipient,
            amount,
            token_type,
            nonce,
            timestamp,
        );

        Self::verify_signature(signature, &message_hash, sender_public_key)
    }
}

/// Wallet key management
#[derive(Debug)]
pub struct WalletKeyManager {
    keypair: Keypair,
    address: String,
}

impl Clone for WalletKeyManager {
    fn clone(&self) -> Self {
        // Recreate the keypair from the secret key bytes
        let secret_key_bytes = self.keypair.secret.to_bytes();
        Self::from_secret_key(&secret_key_bytes).expect("Failed to clone WalletKeyManager")
    }
}

impl WalletKeyManager {
    /// Create a new wallet key manager with generated keypair
    pub fn new() -> Result<Self, WalletError> {
        let keypair = SignatureVerification::generate_keypair()?;
        let address = Self::derive_address_from_public_key(&keypair.public);
        
        Ok(Self {
            keypair,
            address,
        })
    }

    /// Create from existing secret key
    pub fn from_secret_key(secret_key_bytes: &[u8]) -> Result<Self, WalletError> {
        let secret_key = SecretKey::from_bytes(secret_key_bytes)
            .map_err(|_| WalletError::KeyGenerationFailed)?;
        
        let public_key = PublicKey::from(&secret_key);
        let keypair = Keypair { secret: secret_key, public: public_key };
        let address = Self::derive_address_from_public_key(&keypair.public);
        
        Ok(Self {
            keypair,
            address,
        })
    }

    /// Get the wallet address
    pub fn get_address(&self) -> &str {
        &self.address
    }

    /// Get the public key bytes
    pub fn get_public_key(&self) -> Vec<u8> {
        self.keypair.public.to_bytes().to_vec()
    }

    /// Get the secret key bytes (be careful with this!)
    pub fn get_secret_key(&self) -> Vec<u8> {
        self.keypair.secret.to_bytes().to_vec()
    }

    /// Get the private key as a hex string (be careful with this!)
    pub fn get_private_key_hex(&self) -> String {
        hex::encode(self.keypair.secret.to_bytes())
    }

    /// Sign a transaction
    pub fn sign_transaction(
        &self,
        recipient: &str,
        amount: u64,
        token_type: &str,
        nonce: u64,
        timestamp: u64,
    ) -> Result<WalletSignature, WalletError> {
        let message_hash = SignatureVerification::create_message_hash(
            &self.address,
            recipient,
            amount,
            token_type,
            nonce,
            timestamp,
        );

        SignatureVerification::sign_message(&self.keypair, &message_hash)
    }

    /// Derive address from public key (simplified - in production use proper address derivation)
    fn derive_address_from_public_key(public_key: &PublicKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key.to_bytes());
        let hash = hasher.finalize();
        format!("E3{}", hex::encode(&hash[..20])) // E3 prefix + first 20 bytes of hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let key_manager = WalletKeyManager::new().unwrap();
        assert!(key_manager.get_address().starts_with("E3"));
        assert_eq!(key_manager.get_public_key().len(), 32);
    }

    #[test]
    fn test_signature_verification() {
        let key_manager = WalletKeyManager::new().unwrap();
        let signature = key_manager.sign_transaction(
            "recipient_address",
            1000,
            "GU",
            1,
            1234567890,
        ).unwrap();

        let is_valid = SignatureVerification::verify_transaction_signature(
            &signature,
            key_manager.get_address(),
            "recipient_address",
            1000,
            "GU",
            1,
            1234567890,
            &key_manager.get_public_key(),
        ).unwrap();

        assert!(is_valid);
    }
}
