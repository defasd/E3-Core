//! Smart Contract Policy Management for Admin Node
//!
//! Handles governance-driven policy changes that affect smart contract execution

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Smart contract execution policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPolicy {
    pub contract_id: String,
    pub max_gas_limit: u64,              // Maximum gas allowed for execution
    pub execution_fee_rate: f64,         // Fee rate per gas unit
    pub permission_overrides: HashMap<String, bool>, // DID-specific permissions
    pub enabled: bool,                   // Whether contract execution is enabled
    pub rate_limit: Option<RateLimit>,   // Execution rate limiting
    pub last_updated: DateTime<Utc>,
}

/// Rate limiting configuration for smart contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_executions_per_minute: u32,
    pub max_executions_per_hour: u32,
    pub max_executions_per_day: u32,
}

/// Global smart contract execution policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalContractPolicy {
    pub global_gas_limit: u64,              // Global maximum gas limit
    pub min_execution_fee: f64,              // Minimum execution fee
    pub contract_deployment_fee: f64,        // Fee for deploying contracts
    pub governance_only_deployment: bool,    // Whether only governance can deploy
    pub emergency_shutdown: bool,            // Emergency shutdown of all contracts
    pub last_updated: DateTime<Utc>,
}

/// Contract policy manager for admin node
pub struct ContractPolicyManager {
    contract_policies: HashMap<String, ContractPolicy>,
    global_policy: GlobalContractPolicy,
    execution_stats: HashMap<String, ExecutionStats>,
}

/// Contract execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub total_executions: u64,
    pub total_gas_used: u64,
    pub total_fees_collected: f64,
    pub last_execution: Option<DateTime<Utc>>,
    pub error_count: u64,
    pub success_count: u64,
}

impl ContractPolicyManager {
    pub fn new() -> Self {
        ContractPolicyManager {
            contract_policies: HashMap::new(),
            global_policy: GlobalContractPolicy {
                global_gas_limit: 10_000_000,      // 10M gas global limit
                min_execution_fee: 0.001,           // 0.001 ST minimum fee
                contract_deployment_fee: 10.0,      // 10 ST deployment fee
                governance_only_deployment: true,   // Only governance can deploy
                emergency_shutdown: false,          // Not in emergency mode
                last_updated: Utc::now(),
            },
            execution_stats: HashMap::new(),
        }
    }

    /// Update contract policy based on governance decision
    pub fn update_contract_policy(
        &mut self,
        contract_id: String,
        policy_updates: serde_json::Value,
    ) -> Result<(), String> {
        let mut policy = self.contract_policies
            .get(&contract_id)
            .cloned()
            .unwrap_or_else(|| ContractPolicy {
                contract_id: contract_id.clone(),
                max_gas_limit: 1_000_000,
                execution_fee_rate: 0.0001,
                permission_overrides: HashMap::new(),
                enabled: true,
                rate_limit: None,
                last_updated: Utc::now(),
            });

        // Apply policy updates
        if let Some(max_gas) = policy_updates.get("max_gas_limit").and_then(|v| v.as_u64()) {
            policy.max_gas_limit = max_gas;
        }

        if let Some(fee_rate) = policy_updates.get("execution_fee_rate").and_then(|v| v.as_f64()) {
            policy.execution_fee_rate = fee_rate;
        }

        if let Some(enabled) = policy_updates.get("enabled").and_then(|v| v.as_bool()) {
            policy.enabled = enabled;
        }

        if let Some(rate_limit_config) = policy_updates.get("rate_limit") {
            if let (Some(per_min), Some(per_hour), Some(per_day)) = (
                rate_limit_config.get("max_executions_per_minute").and_then(|v| v.as_u64()),
                rate_limit_config.get("max_executions_per_hour").and_then(|v| v.as_u64()),
                rate_limit_config.get("max_executions_per_day").and_then(|v| v.as_u64()),
            ) {
                policy.rate_limit = Some(RateLimit {
                    max_executions_per_minute: per_min as u32,
                    max_executions_per_hour: per_hour as u32,
                    max_executions_per_day: per_day as u32,
                });
            }
        }

        policy.last_updated = Utc::now();
        self.contract_policies.insert(contract_id.clone(), policy);

        println!("📋 Updated contract policy for: {}", contract_id);
        Ok(())
    }

    /// Update global contract policies
    pub fn update_global_policy(&mut self, policy_updates: serde_json::Value) -> Result<(), String> {
        if let Some(global_gas) = policy_updates.get("global_gas_limit").and_then(|v| v.as_u64()) {
            self.global_policy.global_gas_limit = global_gas;
        }

        if let Some(min_fee) = policy_updates.get("min_execution_fee").and_then(|v| v.as_f64()) {
            self.global_policy.min_execution_fee = min_fee;
        }

        if let Some(deployment_fee) = policy_updates.get("contract_deployment_fee").and_then(|v| v.as_f64()) {
            self.global_policy.contract_deployment_fee = deployment_fee;
        }

        if let Some(gov_only) = policy_updates.get("governance_only_deployment").and_then(|v| v.as_bool()) {
            self.global_policy.governance_only_deployment = gov_only;
        }

        if let Some(emergency) = policy_updates.get("emergency_shutdown").and_then(|v| v.as_bool()) {
            self.global_policy.emergency_shutdown = emergency;
        }

        self.global_policy.last_updated = Utc::now();

        println!("📋 Updated global contract policy");
        Ok(())
    }

    /// Check if contract execution is allowed
    pub fn is_execution_allowed(&self, contract_id: &str) -> bool {
        if self.global_policy.emergency_shutdown {
            return false;
        }

        if let Some(policy) = self.contract_policies.get(contract_id) {
            policy.enabled
        } else {
            true // Default to allowed if no policy exists
        }
    }

    /// Get contract execution policy
    pub fn get_contract_policy(&self, contract_id: &str) -> Option<&ContractPolicy> {
        self.contract_policies.get(contract_id)
    }

    /// Get global policy
    pub fn get_global_policy(&self) -> &GlobalContractPolicy {
        &self.global_policy
    }

    /// Record contract execution for statistics
    pub fn record_execution(
        &mut self,
        contract_id: &str,
        gas_used: u64,
        fee_paid: f64,
        success: bool,
    ) {
        let stats = self.execution_stats
            .entry(contract_id.to_string())
            .or_insert(ExecutionStats {
                total_executions: 0,
                total_gas_used: 0,
                total_fees_collected: 0.0,
                last_execution: None,
                error_count: 0,
                success_count: 0,
            });

        stats.total_executions += 1;
        stats.total_gas_used += gas_used;
        stats.total_fees_collected += fee_paid;
        stats.last_execution = Some(Utc::now());

        if success {
            stats.success_count += 1;
        } else {
            stats.error_count += 1;
        }
    }

    /// Get execution statistics for a contract
    pub fn get_execution_stats(&self, contract_id: &str) -> Option<&ExecutionStats> {
        self.execution_stats.get(contract_id)
    }

    /// Get all contract policies
    pub fn get_all_policies(&self) -> &HashMap<String, ContractPolicy> {
        &self.contract_policies
    }

    /// Emergency disable all contracts
    pub fn emergency_shutdown(&mut self, reason: String) {
        self.global_policy.emergency_shutdown = true;
        self.global_policy.last_updated = Utc::now();
        
        println!("🚨 EMERGENCY: All smart contracts disabled. Reason: {}", reason);
    }

    /// Emergency enable all contracts
    pub fn emergency_restore(&mut self) {
        self.global_policy.emergency_shutdown = false;
        self.global_policy.last_updated = Utc::now();
        
        println!("✅ RESTORED: Smart contract execution re-enabled");
    }

    /// Generate policy report
    pub fn generate_policy_report(&self) -> serde_json::Value {
        serde_json::json!({
            "global_policy": self.global_policy,
            "contract_count": self.contract_policies.len(),
            "enabled_contracts": self.contract_policies.values().filter(|p| p.enabled).count(),
            "disabled_contracts": self.contract_policies.values().filter(|p| !p.enabled).count(),
            "total_executions": self.execution_stats.values().map(|s| s.total_executions).sum::<u64>(),
            "total_gas_used": self.execution_stats.values().map(|s| s.total_gas_used).sum::<u64>(),
            "total_fees_collected": self.execution_stats.values().map(|s| s.total_fees_collected).sum::<f64>(),
            "emergency_shutdown": self.global_policy.emergency_shutdown,
            "report_timestamp": Utc::now()
        })
    }
}
