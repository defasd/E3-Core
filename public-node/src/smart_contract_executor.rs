#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[tokio::test]
    async fn test_public_contract_execution() {
        let mut executor = ContractExecutor::new();

        // Create a test contract
        let contract = ExecutableContract {
            contract_id: "test1".to_string(),
            name: "TestContract".to_string(),
            bytecode: vec![],
            allowed_methods: vec!["get_balance".to_string(), "transfer".to_string()],
            permission_level: PermissionLevel::Public,
            gas_limit: 100_000,
            deployment_timestamp: Utc::now(),
        };

        executor.add_contract(contract);

        // Prepare execution request
        let request = ContractExecutionRequest {
            contract_id: "test1".to_string(),
            method: "get_balance".to_string(),
            parameters: json!({}),
            caller_did: "did:example:publicuser".to_string(),
            gas_limit: None,
            signature: "dummy_signature".to_string(),
        };

        // Execute contract
        let result = executor.execute_contract(request).await.unwrap();

        assert!(result.success);
        assert_eq!(result.method, "get_balance");
        assert!(result.result.is_some());
    }
}
// Smart Contract Execution Module for Public Node
//
// Handles execution of governance-approved smart contracts

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Smart contract execution permission levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PermissionLevel {
    Public,         // Anyone can execute
    Restricted,     // Only approved DIDs can execute
    Admin,          // Only admin can execute
    Governance,     // Only governance can execute
}

/// Smart contract metadata for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableContract {
    pub contract_id: String,
    pub name: String,
    pub bytecode: Vec<u8>,                    // WASM bytecode
    pub allowed_methods: Vec<String>,         // Callable methods
    pub permission_level: PermissionLevel,
    pub gas_limit: u64,                       // Maximum gas for execution
    pub deployment_timestamp: DateTime<Utc>,
}

/// Contract execution request
#[derive(Debug, Deserialize)]
pub struct ContractExecutionRequest {
    pub contract_id: String,
    pub method: String,
    pub parameters: serde_json::Value,        // Method parameters
    pub caller_did: String,                   // DID of the caller
    pub gas_limit: Option<u64>,               // Override gas limit (if lower)
    pub signature: String,                    // Caller's signature
}

/// Contract execution result
#[derive(Debug, Serialize)]
pub struct ContractExecutionResult {
    pub contract_id: String,
    pub method: String,
    pub success: bool,
    pub result: Option<serde_json::Value>,    // Execution result
    pub error: Option<String>,                // Error message if failed
    pub gas_used: u64,                        // Gas consumed
    pub execution_time_ms: u64,               // Execution time in milliseconds
    pub timestamp: DateTime<Utc>,
}

/// Smart contract registry for public node
pub struct ContractExecutor {
    contracts: HashMap<String, ExecutableContract>,
    approved_dids: HashMap<String, bool>,     // DID approval cache
}

impl ContractExecutor {
    pub fn new() -> Self {
        ContractExecutor {
            contracts: HashMap::new(),
            approved_dids: HashMap::new(),
        }
    }

    /// Add a new contract for execution (called when governance deploys)
    pub fn add_contract(&mut self, contract: ExecutableContract) {
        println!("📄 Adding executable contract: {} ({})", contract.name, contract.contract_id);
        self.contracts.insert(contract.contract_id.clone(), contract);
    }

    /// Remove a contract (called when governance disables)
    pub fn remove_contract(&mut self, contract_id: &str) {
        if self.contracts.remove(contract_id).is_some() {
            println!("📄 Removed contract: {}", contract_id);
        }
    }

    /// Check if a contract is available for execution
    pub fn is_contract_available(&self, contract_id: &str) -> bool {
        self.contracts.contains_key(contract_id)
    }

    /// Get contract metadata
    pub fn get_contract_metadata(&self, contract_id: &str) -> Option<&ExecutableContract> {
        self.contracts.get(contract_id)
    }

    /// Check if a DID has permission to execute a contract method
    pub fn check_execution_permission(
        &self,
        contract_id: &str,
        method: &str,
        caller_did: &str,
    ) -> Result<(), String> {
        let contract = self.contracts.get(contract_id)
            .ok_or_else(|| "Contract not found".to_string())?;

        // Check if method is allowed
        if !contract.allowed_methods.contains(&method.to_string()) {
            return Err("Method not allowed for this contract".to_string());
        }

        // Check permission level
        match contract.permission_level {
            PermissionLevel::Public => {
                // Anyone can execute
                Ok(())
            }
            PermissionLevel::Restricted => {
                // Check if DID is approved (would check against DID registry)
                if *self.approved_dids.get(caller_did).unwrap_or(&false) {
                    Ok(())
                } else {
                    Err("DID not approved for restricted contract execution".to_string())
                }
            }
            PermissionLevel::Admin => {
                // Check if DID has admin role (would check against governance)
                // For now, simple check
                if caller_did.contains("admin") {
                    Ok(())
                } else {
                    Err("Admin permission required".to_string())
                }
            }
            PermissionLevel::Governance => {
                // Only governance can execute
                if caller_did.contains("governance") {
                    Ok(())
                } else {
                    Err("Governance permission required".to_string())
                }
            }
        }
    }

    /// Execute a smart contract method
    pub async fn execute_contract(
        &self,
        request: ContractExecutionRequest,
    ) -> Result<ContractExecutionResult, String> {
        let start_time = std::time::Instant::now();
        
        // Check if contract exists and method is allowed
        self.check_execution_permission(&request.contract_id, &request.method, &request.caller_did)?;
        
        let contract = self.contracts.get(&request.contract_id)
            .ok_or_else(|| "Contract not found".to_string())?;

        // Validate gas limit
        let gas_limit = request.gas_limit.unwrap_or(contract.gas_limit);
        if gas_limit > contract.gas_limit {
            return Err("Gas limit exceeds contract maximum".to_string());
        }

        // TODO: Validate signature
        if request.signature.is_empty() {
            return Err("Signature required".to_string());
        }

        // Simulate smart contract execution
        // In a real implementation, this would use a WASM runtime like Wasmtime
        let (success, result, error, gas_used) = self.simulate_execution(
            &contract.bytecode,
            &request.method,
            &request.parameters,
            gas_limit,
        ).await?;

        let execution_time = start_time.elapsed().as_millis() as u64;
        
        let execution_result = ContractExecutionResult {
            contract_id: request.contract_id,
            method: request.method,
            success,
            result,
            error,
            gas_used,
            execution_time_ms: execution_time,
            timestamp: Utc::now(),
        };

        println!("📄 Contract execution completed: {} (success: {}, gas: {})", 
                 execution_result.contract_id, execution_result.success, execution_result.gas_used);

        Ok(execution_result)
    }

    /// Simulate smart contract execution
    /// In production, this would use a proper WASM runtime
    async fn simulate_execution(
        &self,
        _bytecode: &[u8],
        method: &str,
        parameters: &serde_json::Value,
        gas_limit: u64,
    ) -> Result<(bool, Option<serde_json::Value>, Option<String>, u64), String> {
        // Simulate different contract behaviors based on method name
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await; // Simulate execution time
        
        let gas_used = (gas_limit as f64 * 0.1) as u64; // Use 10% of gas limit
        
        match method {
            "get_balance" => {
                let result = serde_json::json!({
                    "balance": 1000,
                    "currency": "ST"
                });
                Ok((true, Some(result), None, gas_used))
            }
            "transfer" => {
                if let Some(amount) = parameters.get("amount").and_then(|a| a.as_u64()) {
                    if amount > 10000 {
                        Ok((false, None, Some("Transfer amount exceeds limit".to_string()), gas_used))
                    } else {
                        let result = serde_json::json!({
                            "transaction_id": uuid::Uuid::new_v4().to_string(),
                            "amount": amount,
                            "status": "success"
                        });
                        Ok((true, Some(result), None, gas_used))
                    }
                } else {
                    Ok((false, None, Some("Invalid amount parameter".to_string()), gas_used))
                }
            }
            "stake" => {
                let result = serde_json::json!({
                    "stake_id": uuid::Uuid::new_v4().to_string(),
                    "status": "staked"
                });
                Ok((true, Some(result), None, gas_used))
            }
            "unstake" => {
                let result = serde_json::json!({
                    "status": "unstaked",
                    "unlock_time": (Utc::now().timestamp() + 86400) // 24 hours from now
                });
                Ok((true, Some(result), None, gas_used))
            }
            _ => {
                Ok((false, None, Some(format!("Unknown method: {}", method)), gas_used))
            }
        }
    }

    /// Update approved DIDs cache
    pub fn update_approved_dids(&mut self, approved_dids: HashMap<String, bool>) {
        self.approved_dids = approved_dids;
    }

    /// Get all available contracts
    pub fn get_available_contracts(&self) -> Vec<String> {
        self.contracts.keys().cloned().collect()
    }

    /// Get contract execution statistics
    pub fn get_contract_stats(&self, contract_id: &str) -> Option<serde_json::Value> {
        if let Some(contract) = self.contracts.get(contract_id) {
            Some(serde_json::json!({
                "contract_id": contract_id,
                "name": contract.name,
                "allowed_methods": contract.allowed_methods,
                "permission_level": contract.permission_level,
                "gas_limit": contract.gas_limit,
                "deployment_timestamp": contract.deployment_timestamp
            }))
        } else {
            None
        }
    }
}
