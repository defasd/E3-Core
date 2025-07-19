use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Proof of Reserve for treasury wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfReserve {
    pub reserve_id: String,
    pub treasury_address: String,
    pub total_reserves: u64, // Physical gold reserves in grams
    pub backing_assets: Vec<BackingAsset>,
    pub attestation: ReserveAttestation,
    pub verification: ReserveVerification,
    pub metadata: ReserveMetadata,
}

/// Physical or digital assets backing the treasury
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackingAsset {
    pub asset_id: String,
    pub asset_type: AssetType,
    pub amount: u64, // In grams for gold, units for other assets
    pub location: String,
    pub custodian: String,
    pub verification_method: String,
    pub last_verified: u64,
    pub certificates: Vec<String>, // Certificate hashes or references
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetType {
    PhysicalGold,
    GoldCertificate,
    DigitalGold,
    Other(String),
}

/// Attestation from authorized auditors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveAttestation {
    pub auditor_id: String,
    pub auditor_name: String,
    pub audit_date: u64,
    pub audit_report_hash: String,
    pub signature: String, // Auditor's digital signature
    pub validity_period: u64, // How long this attestation is valid
    pub next_audit_due: u64,
}

/// Cryptographic verification of the reserves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveVerification {
    pub merkle_root: String, // Merkle root of all backing assets
    pub proof_hash: String, // Hash of the entire proof
    pub timestamp: u64,
    pub block_height: Option<u64>, // If anchored to blockchain
    pub verification_nodes: Vec<String>, // Nodes that verified this proof
}

/// Additional metadata for the proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveMetadata {
    pub total_gu_issued: u64, // Total GU tokens issued
    pub reserve_ratio: f64, // Actual reserve ratio (should be >= 100%)
    pub last_updated: u64,
    pub update_frequency: u64, // How often reserves are verified (in seconds)
    pub public_audit_url: Option<String>, // URL to public audit reports
    pub compliance_standards: Vec<String>, // Standards complied with
    pub insurance_coverage: Option<u64>, // Insurance coverage amount
}

impl ProofOfReserve {
    /// Create a new proof of reserve
    pub fn new(
        treasury_address: String,
        backing_assets: Vec<BackingAsset>,
        attestation: ReserveAttestation,
    ) -> Self {
        let total_reserves = backing_assets.iter()
            .filter(|asset| matches!(asset.asset_type, AssetType::PhysicalGold))
            .map(|asset| asset.amount)
            .sum();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let merkle_root = Self::calculate_merkle_root(&backing_assets);
        let proof_hash = Self::calculate_proof_hash(&treasury_address, &backing_assets, &attestation);

        let verification = ReserveVerification {
            merkle_root,
            proof_hash,
            timestamp,
            block_height: None,
            verification_nodes: Vec::new(),
        };

        let metadata = ReserveMetadata {
            total_gu_issued: 0, // Will be updated when linked to treasury
            reserve_ratio: 0.0, // Will be calculated when linked to treasury
            last_updated: timestamp,
            update_frequency: 86400, // Daily updates by default
            public_audit_url: None,
            compliance_standards: vec!["LBMA".to_string(), "ISO9001".to_string()],
            insurance_coverage: None,
        };

        Self {
            reserve_id: uuid::Uuid::new_v4().to_string(),
            treasury_address,
            total_reserves,
            backing_assets,
            attestation,
            verification,
            metadata,
        }
    }

    /// Calculate merkle root of backing assets
    fn calculate_merkle_root(assets: &[BackingAsset]) -> String {
        if assets.is_empty() {
            return "0".repeat(64);
        }

        let mut hashes: Vec<String> = assets.iter()
            .map(|asset| {
                let mut hasher = Sha256::new();
                hasher.update(asset.asset_id.as_bytes());
                hasher.update(&asset.amount.to_le_bytes());
                hasher.update(asset.location.as_bytes());
                hasher.update(asset.custodian.as_bytes());
                hex::encode(hasher.finalize())
            })
            .collect();

        // Simple merkle tree calculation
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0].as_bytes());
                if chunk.len() > 1 {
                    hasher.update(chunk[1].as_bytes());
                } else {
                    hasher.update(chunk[0].as_bytes()); // Duplicate if odd number
                }
                next_level.push(hex::encode(hasher.finalize()));
            }
            
            hashes = next_level;
        }

        hashes[0].clone()
    }

    /// Calculate overall proof hash
    fn calculate_proof_hash(
        treasury_address: &str,
        assets: &[BackingAsset],
        attestation: &ReserveAttestation,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(treasury_address.as_bytes());
        hasher.update(&assets.len().to_le_bytes());
        hasher.update(attestation.auditor_id.as_bytes());
        hasher.update(&attestation.audit_date.to_le_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify the proof of reserve
    pub fn verify(&self) -> Result<bool, String> {
        // Check if attestation is still valid
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time > self.attestation.audit_date + self.attestation.validity_period {
            return Err("Attestation has expired".to_string());
        }

        // Verify merkle root
        let calculated_merkle = Self::calculate_merkle_root(&self.backing_assets);
        if calculated_merkle != self.verification.merkle_root {
            return Err("Merkle root verification failed".to_string());
        }

        // Verify proof hash
        let calculated_hash = Self::calculate_proof_hash(
            &self.treasury_address,
            &self.backing_assets,
            &self.attestation,
        );
        if calculated_hash != self.verification.proof_hash {
            return Err("Proof hash verification failed".to_string());
        }

        // Check reserve ratio if metadata is available
        if self.metadata.total_gu_issued > 0 {
            let calculated_ratio = (self.total_reserves as f64 / self.metadata.total_gu_issued as f64) * 100.0;
            if calculated_ratio < 100.0 {
                return Err(format!("Reserve ratio too low: {:.2}%", calculated_ratio));
            }
        }

        Ok(true)
    }

    /// Update with current GU issuance to calculate reserve ratio
    pub fn update_issuance(&mut self, total_gu_issued: u64) {
        self.metadata.total_gu_issued = total_gu_issued;
        
        if total_gu_issued > 0 {
            self.metadata.reserve_ratio = (self.total_reserves as f64 / total_gu_issued as f64) * 100.0;
        } else {
            self.metadata.reserve_ratio = f64::INFINITY;
        }

        self.metadata.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Add a new backing asset
    pub fn add_backing_asset(&mut self, asset: BackingAsset) {
        // Add to the reserves if it's physical gold
        if matches!(asset.asset_type, AssetType::PhysicalGold) {
            self.total_reserves += asset.amount;
        }

        self.backing_assets.push(asset);
        
        // Recalculate verification
        self.verification.merkle_root = Self::calculate_merkle_root(&self.backing_assets);
        self.verification.proof_hash = Self::calculate_proof_hash(
            &self.treasury_address,
            &self.backing_assets,
            &self.attestation,
        );
        self.verification.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Update reserve ratio if we have issuance data
        if self.metadata.total_gu_issued > 0 {
            self.metadata.reserve_ratio = (self.total_reserves as f64 / self.metadata.total_gu_issued as f64) * 100.0;
        }

        self.metadata.last_updated = self.verification.timestamp;
    }

    /// Remove a backing asset
    pub fn remove_backing_asset(&mut self, asset_id: &str) -> Result<(), String> {
        let index = self.backing_assets.iter()
            .position(|asset| asset.asset_id == asset_id)
            .ok_or("Asset not found")?;

        let removed_asset = self.backing_assets.remove(index);
        
        // Subtract from reserves if it was physical gold
        if matches!(removed_asset.asset_type, AssetType::PhysicalGold) {
            self.total_reserves = self.total_reserves.saturating_sub(removed_asset.amount);
        }

        // Recalculate verification
        self.verification.merkle_root = Self::calculate_merkle_root(&self.backing_assets);
        self.verification.proof_hash = Self::calculate_proof_hash(
            &self.treasury_address,
            &self.backing_assets,
            &self.attestation,
        );
        self.verification.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Update reserve ratio
        if self.metadata.total_gu_issued > 0 {
            self.metadata.reserve_ratio = (self.total_reserves as f64 / self.metadata.total_gu_issued as f64) * 100.0;
        }

        self.metadata.last_updated = self.verification.timestamp;

        Ok(())
    }

    /// Get reserve statistics
    pub fn get_reserve_stats(&self) -> ReserveStats {
        ReserveStats {
            total_reserves: self.total_reserves,
            total_gu_issued: self.metadata.total_gu_issued,
            reserve_ratio: self.metadata.reserve_ratio,
            asset_count: self.backing_assets.len(),
            last_audit: self.attestation.audit_date,
            next_audit_due: self.attestation.next_audit_due,
            is_valid: self.verify().is_ok(),
            compliance_standards: self.metadata.compliance_standards.clone(),
        }
    }

    /// Export proof for external verification
    pub fn export_proof(&self) -> ProofExport {
        ProofExport {
            reserve_id: self.reserve_id.clone(),
            treasury_address: self.treasury_address.clone(),
            merkle_root: self.verification.merkle_root.clone(),
            proof_hash: self.verification.proof_hash.clone(),
            total_reserves: self.total_reserves,
            reserve_ratio: self.metadata.reserve_ratio,
            audit_date: self.attestation.audit_date,
            auditor_name: self.attestation.auditor_name.clone(),
            timestamp: self.verification.timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveStats {
    pub total_reserves: u64,
    pub total_gu_issued: u64,
    pub reserve_ratio: f64,
    pub asset_count: usize,
    pub last_audit: u64,
    pub next_audit_due: u64,
    pub is_valid: bool,
    pub compliance_standards: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofExport {
    pub reserve_id: String,
    pub treasury_address: String,
    pub merkle_root: String,
    pub proof_hash: String,
    pub total_reserves: u64,
    pub reserve_ratio: f64,
    pub audit_date: u64,
    pub auditor_name: String,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_reserve_creation() {
        let assets = vec![
            BackingAsset {
                asset_id: "GOLD001".to_string(),
                asset_type: AssetType::PhysicalGold,
                amount: 1000, // 1kg of gold
                location: "Vault A".to_string(),
                custodian: "SecureVault Inc".to_string(),
                verification_method: "Physical inspection".to_string(),
                last_verified: 1640995200, // Jan 1, 2022
                certificates: vec!["CERT001".to_string()],
            }
        ];

        let attestation = ReserveAttestation {
            auditor_id: "AUDIT001".to_string(),
            auditor_name: "TrustedAudit Corp".to_string(),
            audit_date: 1640995200,
            audit_report_hash: "abcd1234".to_string(),
            signature: "signature123".to_string(),
            validity_period: 31536000, // 1 year
            next_audit_due: 1672531200, // Jan 1, 2023
        };

        let proof = ProofOfReserve::new(
            "treasury123".to_string(),
            assets,
            attestation,
        );

        assert_eq!(proof.total_reserves, 1000);
        assert_eq!(proof.backing_assets.len(), 1);
        assert!(!proof.verification.merkle_root.is_empty());
    }

    #[test]
    fn test_proof_verification() {
        let assets = vec![
            BackingAsset {
                asset_id: "GOLD001".to_string(),
                asset_type: AssetType::PhysicalGold,
                amount: 1000,
                location: "Vault A".to_string(),
                custodian: "SecureVault Inc".to_string(),
                verification_method: "Physical inspection".to_string(),
                last_verified: 1640995200,
                certificates: vec!["CERT001".to_string()],
            }
        ];

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let attestation = ReserveAttestation {
            auditor_id: "AUDIT001".to_string(),
            auditor_name: "TrustedAudit Corp".to_string(),
            audit_date: current_time - 1000, // Recent audit
            audit_report_hash: "abcd1234".to_string(),
            signature: "signature123".to_string(),
            validity_period: 31536000, // 1 year
            next_audit_due: current_time + 30000000, // Future date
        };

        let proof = ProofOfReserve::new(
            "treasury123".to_string(),
            assets,
            attestation,
        );

        assert!(proof.verify().is_ok());
    }
}
