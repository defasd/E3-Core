//! Smart Contract Management Module
//!
//! Handles smart contract submission, approval, deployment, and lifecycle management

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use base64::Engine;

/// Smart contract status in the governance system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractStatus {
    Submitted,      // Contract submitted for review
    UnderReview,    // Being reviewed by governance
    Approved,       // Approved for deployment
    Deployed,       // Successfully deployed
    Rejected,       // Rejected by governance
    Deprecated,     // Marked for deprecation
    Disabled,       // Temporarily disabled
}

/// Contract execution permission levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionLevel {
    Public,         // Anyone can execute
    Restricted,     // Only approved DIDs can execute
    Admin,          // Only admin can execute
    Governance,     // Only governance can execute
}

/// Smart contract metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartContract {
    pub contract_id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub bytecode: Vec<u8>,                    // WASM bytecode
    pub bytecode_hash: String,                // SHA-256 hash of bytecode
    pub allowed_methods: Vec<String>,         // Callable methods
    pub permission_level: PermissionLevel,
    pub developer_did: String,                // DID of the developer
    pub status: ContractStatus,
    pub governance_proposal_id: Option<String>, // Associated proposal ID
    pub submission_timestamp: DateTime<Utc>,
    pub approval_timestamp: Option<DateTime<Utc>>,
    pub deployment_timestamp: Option<DateTime<Utc>>,
    pub gas_limit: u64,                       // Maximum gas for execution
    pub metadata: HashMap<String, String>,    // Additional metadata
}

/// Contract submission request
#[derive(Debug, Deserialize)]
pub struct ContractSubmissionRequest {
    pub name: String,
    pub description: String,
    pub version: String,
    pub bytecode: String,                     // Base64 encoded bytecode
    pub allowed_methods: Vec<String>,
    pub permission_level: PermissionLevel,
    pub developer_did: String,
    pub gas_limit: u64,
    pub metadata: HashMap<String, String>,
    pub signature: String,                    // Developer's signature
}

/// Contract approval request (for governance voting)
#[derive(Debug, Deserialize)]
pub struct ContractApprovalRequest {
    pub contract_id: String,
    pub approver_did: String,
    pub signature: String,
}

/// Contract registry for managing all smart contracts
pub struct ContractRegistry {
    contracts: HashMap<String, SmartContract>,
    deployed_contracts: HashMap<String, SmartContract>, // Quick lookup for deployed contracts
}

impl ContractRegistry {
    pub fn new() -> Self {
        ContractRegistry {
            contracts: HashMap::new(),
            deployed_contracts: HashMap::new(),
        }
    }

    /// Submit a new smart contract for governance approval
    pub fn submit_contract(&mut self, request: ContractSubmissionRequest) -> Result<String, String> {
        // Generate unique contract ID
        let contract_id = format!("contract_{}", uuid::Uuid::new_v4());
        
        // Decode bytecode from base64
        let bytecode = match base64::engine::general_purpose::STANDARD.decode(&request.bytecode) {
            Ok(bytes) => bytes,
            Err(_) => return Err("Invalid bytecode encoding (expected base64)".to_string()),
        };

        // Calculate bytecode hash
        let bytecode_hash = sha256::digest(&bytecode);

        // Create smart contract entry
        let contract = SmartContract {
            contract_id: contract_id.clone(),
            name: request.name,
            description: request.description,
            version: request.version,
            bytecode,
            bytecode_hash,
            allowed_methods: request.allowed_methods,
            permission_level: request.permission_level,
            developer_did: request.developer_did,
            status: ContractStatus::Submitted,
            governance_proposal_id: None,
            submission_timestamp: Utc::now(),
            approval_timestamp: None,
            deployment_timestamp: None,
            gas_limit: request.gas_limit,
            metadata: request.metadata,
        };

        // Store contract
        self.contracts.insert(contract_id.clone(), contract);
        
        println!("📄 Smart contract submitted: {}", contract_id);
        Ok(contract_id)
    }

    /// Get contract by ID
    pub fn get_contract(&self, contract_id: &str) -> Option<&SmartContract> {
        self.contracts.get(contract_id)
    }

    /// Get all contracts by status
    pub fn get_contracts_by_status(&self, status: ContractStatus) -> Vec<&SmartContract> {
        self.contracts
            .values()
            .filter(|contract| contract.status == status)
            .collect()
    }

    /// Update contract status
    pub fn update_contract_status(&mut self, contract_id: &str, status: ContractStatus) -> Result<(), String> {
        if let Some(contract) = self.contracts.get_mut(contract_id) {
            contract.status = status.clone();
            
            match status {
                ContractStatus::Approved => {
                    contract.approval_timestamp = Some(Utc::now());
                }
                ContractStatus::Deployed => {
                    contract.deployment_timestamp = Some(Utc::now());
                    // Add to deployed contracts for quick lookup
                    self.deployed_contracts.insert(contract_id.to_string(), contract.clone());
                }
                _ => {}
            }
            
            Ok(())
        } else {
            Err("Contract not found".to_string())
        }
    }

    /// Associate contract with governance proposal
    pub fn set_governance_proposal(&mut self, contract_id: &str, proposal_id: String) -> Result<(), String> {
        if let Some(contract) = self.contracts.get_mut(contract_id) {
            contract.governance_proposal_id = Some(proposal_id);
            Ok(())
        } else {
            Err("Contract not found".to_string())
        }
    }

    /// Get all deployed contracts (for public node consumption)
    pub fn get_deployed_contracts(&self) -> &HashMap<String, SmartContract> {
        &self.deployed_contracts
    }

    /// Check if a contract is deployed and executable
    pub fn is_contract_executable(&self, contract_id: &str) -> bool {
        self.deployed_contracts.contains_key(contract_id)
    }

    /// Get contract execution metadata
    pub fn get_execution_metadata(&self, contract_id: &str) -> Option<(Vec<String>, PermissionLevel, u64)> {
        self.deployed_contracts.get(contract_id).map(|contract| {
            (contract.allowed_methods.clone(), contract.permission_level.clone(), contract.gas_limit)
        })
    }

    /// Get contracts submitted by a specific DID
    pub fn get_contracts_by_developer(&self, developer_did: &str) -> Vec<&SmartContract> {
        self.contracts
            .values()
            .filter(|contract| contract.developer_did == developer_did)
            .collect()
    }

    /// Remove/disable a contract
    pub fn disable_contract(&mut self, contract_id: &str) -> Result<(), String> {
        if let Some(contract) = self.contracts.get_mut(contract_id) {
            contract.status = ContractStatus::Disabled;
            // Remove from deployed contracts
            self.deployed_contracts.remove(contract_id);
            Ok(())
        } else {
            Err("Contract not found".to_string())
        }
    }
}

/// Contract governance events for publishing to other nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractGovernanceEvent {
    ContractSubmitted {
        contract_id: String,
        developer_did: String,
        contract_hash: String,
    },
    ContractApproved {
        contract_id: String,
        proposal_id: String,
    },
    ContractDeployed {
        contract_id: String,
        bytecode: Vec<u8>,
        allowed_methods: Vec<String>,
        permission_level: PermissionLevel,
        gas_limit: u64,
    },
    ContractDisabled {
        contract_id: String,
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn sample_submission_request() -> ContractSubmissionRequest {
        ContractSubmissionRequest {
            name: "TestContract".to_string(),
            description: "A test contract".to_string(),
            version: "1.0.0".to_string(),
            bytecode: base64::engine::general_purpose::STANDARD.encode(b"wasm"),
            allowed_methods: vec!["execute".to_string()],
            permission_level: PermissionLevel::Public,
            developer_did: "did:example:dev1".to_string(),
            gas_limit: 100_000,
            metadata: HashMap::new(),
            signature: "sig".to_string(),
        }
    }

    #[test]
    fn test_submit_contract_success() {
        let mut registry = ContractRegistry::new();
        let req = sample_submission_request();
        let result = registry.submit_contract(req);
        assert!(result.is_ok());
        let contract_id = result.unwrap();
        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.name, "TestContract");
        assert_eq!(contract.status, ContractStatus::Submitted);
    }

    #[test]
    fn test_submit_contract_invalid_base64() {
        let mut registry = ContractRegistry::new();
        let mut req = sample_submission_request();
        req.bytecode = "!!!notbase64!!!".to_string();
        let result = registry.submit_contract(req);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_contract_status() {
        let mut registry = ContractRegistry::new();
        let req = sample_submission_request();
        let contract_id = registry.submit_contract(req).unwrap();
        assert!(registry.update_contract_status(&contract_id, ContractStatus::Approved).is_ok());
        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.status, ContractStatus::Approved);
        assert!(contract.approval_timestamp.is_some());
    }

    #[test]
    fn test_deploy_contract_and_executable() {
        let mut registry = ContractRegistry::new();
        let req = sample_submission_request();
        let contract_id = registry.submit_contract(req).unwrap();
        registry.update_contract_status(&contract_id, ContractStatus::Deployed).unwrap();
        assert!(registry.is_contract_executable(&contract_id));
        let deployed = registry.get_deployed_contracts();
        assert!(deployed.contains_key(&contract_id));
    }

    #[test]
    fn test_set_governance_proposal() {
        let mut registry = ContractRegistry::new();
        let req = sample_submission_request();
        let contract_id = registry.submit_contract(req).unwrap();
        let proposal_id = "proposal-123".to_string();
        assert!(registry.set_governance_proposal(&contract_id, proposal_id.clone()).is_ok());
        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.governance_proposal_id, Some(proposal_id));
    }

    #[test]
    fn test_get_contracts_by_status() {
        let mut registry = ContractRegistry::new();
        let req1 = sample_submission_request();
        let req2 = ContractSubmissionRequest { name: "C2".to_string(), ..sample_submission_request() };
        let id1 = registry.submit_contract(req1).unwrap();
        let id2 = registry.submit_contract(req2).unwrap();
        registry.update_contract_status(&id2, ContractStatus::Approved).unwrap();
        let submitted = registry.get_contracts_by_status(ContractStatus::Submitted);
        let approved = registry.get_contracts_by_status(ContractStatus::Approved);
        assert_eq!(submitted.len(), 1);
        assert_eq!(approved.len(), 1);
    }

    #[test]
    fn test_get_contracts_by_developer() {
        let mut registry = ContractRegistry::new();
        let mut req1 = sample_submission_request();
        req1.developer_did = "did:dev:1".to_string();
        let mut req2 = sample_submission_request();
        req2.developer_did = "did:dev:2".to_string();
        registry.submit_contract(req1).unwrap();
        registry.submit_contract(req2).unwrap();
        let dev1_contracts = registry.get_contracts_by_developer("did:dev:1");
        let dev2_contracts = registry.get_contracts_by_developer("did:dev:2");
        assert_eq!(dev1_contracts.len(), 1);
        assert_eq!(dev2_contracts.len(), 1);
    }

    #[test]
    fn test_disable_contract() {
        let mut registry = ContractRegistry::new();
        let req = sample_submission_request();
        let contract_id = registry.submit_contract(req).unwrap();
        registry.update_contract_status(&contract_id, ContractStatus::Deployed).unwrap();
        assert!(registry.is_contract_executable(&contract_id));
        assert!(registry.disable_contract(&contract_id).is_ok());
        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.status, ContractStatus::Disabled);
        assert!(!registry.is_contract_executable(&contract_id));
    }

    #[test]
    fn test_get_execution_metadata() {
        let mut registry = ContractRegistry::new();
        let req = sample_submission_request();
        let contract_id = registry.submit_contract(req).unwrap();
        registry.update_contract_status(&contract_id, ContractStatus::Deployed).unwrap();
        let meta = registry.get_execution_metadata(&contract_id);
        assert!(meta.is_some());
        let (methods, perm, gas) = meta.unwrap();
        assert_eq!(methods, vec!["execute".to_string()]);
        assert_eq!(perm, PermissionLevel::Public);
        assert_eq!(gas, 100_000);
    }
}
