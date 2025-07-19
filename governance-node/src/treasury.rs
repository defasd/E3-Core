//! Treasury Management Module
//!
//! Manages community treasury funds, disbursements, and financial governance

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::Utc;

// Treasury account structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryAccount {
    pub account_id: String,
    pub balance: f64,                   // ST token balance
    pub reserved: f64,                  // Reserved for pending disbursements
    pub available: f64,                 // Available for new disbursements
    pub last_updated: u64,
    pub account_type: AccountType,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountType {
    Main,           // Main treasury account
    Reserve,        // Emergency reserve fund
    Operations,     // Day-to-day operations fund
    Development,    // Development and grants fund
    Community,      // Community rewards and incentives
}

impl TreasuryAccount {
    pub fn new(account_id: String, account_type: AccountType) -> Self {
        TreasuryAccount {
            account_id,
            balance: 0.0,
            reserved: 0.0,
            available: 0.0,
            last_updated: Utc::now().timestamp() as u64,
            account_type,
            metadata: serde_json::json!({}),
        }
    }
    
    pub fn update_available(&mut self) {
        self.available = self.balance - self.reserved;
        self.last_updated = Utc::now().timestamp() as u64;
    }
    
    pub fn add_funds(&mut self, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }
        
        self.balance += amount;
        self.update_available();
        Ok(())
    }
    
    pub fn reserve_funds(&mut self, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }
        
        if self.available < amount {
            return Err("Insufficient available funds".to_string());
        }
        
        self.reserved += amount;
        self.update_available();
        Ok(())
    }
    
    pub fn release_reserved_funds(&mut self, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }
        
        if self.reserved < amount {
            return Err("Insufficient reserved funds".to_string());
        }
        
        self.reserved -= amount;
        self.balance -= amount;
        self.update_available();
        Ok(())
    }
}

// Disbursement request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisbursementRequest {
    pub request_id: String,
    pub proposal_id: String,            // Associated governance proposal
    pub recipient: String,              // Wallet address or DID
    pub amount: f64,                    // ST tokens to disburse
    pub category: DisbursementCategory,
    pub description: String,
    pub status: DisbursementStatus,
    pub created_at: u64,
    pub approved_at: Option<u64>,
    pub executed_at: Option<u64>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisbursementCategory {
    Development,        // Development work, bounties
    Community,          // Community rewards, events
    Operations,         // Operational expenses
    Marketing,          // Marketing and promotion
    Infrastructure,     // Infrastructure costs
    Emergency,          // Emergency funds
    Grant,             // Research grants, partnerships
    Other(String),     // Custom category
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DisbursementStatus {
    Pending,           // Awaiting governance approval
    Approved,          // Approved by governance, funds reserved
    Executed,          // Funds disbursed successfully
    Rejected,          // Rejected by governance
    Cancelled,         // Cancelled by requester
    Failed,            // Execution failed
}

// Treasury statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStats {
    pub total_balance: f64,
    pub total_reserved: f64,
    pub total_available: f64,
    pub total_disbursed: f64,
    pub disbursements_count: usize,
    pub accounts_count: usize,
    pub calculated_at: u64,
}

// Main treasury manager
pub struct TreasuryManager {
    accounts: HashMap<String, TreasuryAccount>,
    disbursements: HashMap<String, DisbursementRequest>,
    disbursement_counter: u64,
    disbursement_history: Vec<DisbursementRequest>,
}

impl TreasuryManager {
    pub fn new() -> Self {
        let mut manager = TreasuryManager {
            accounts: HashMap::new(),
            disbursements: HashMap::new(),
            disbursement_counter: 0,
            disbursement_history: Vec::new(),
        };
        
        // Create default treasury accounts
        manager.create_account("treasury_main".to_string(), AccountType::Main);
        manager.create_account("treasury_reserve".to_string(), AccountType::Reserve);
        manager.create_account("treasury_operations".to_string(), AccountType::Operations);
        manager.create_account("treasury_development".to_string(), AccountType::Development);
        manager.create_account("treasury_community".to_string(), AccountType::Community);
        
        manager
    }
    
    pub fn create_account(&mut self, account_id: String, account_type: AccountType) -> Result<(), String> {
        if self.accounts.contains_key(&account_id) {
            return Err("Account already exists".to_string());
        }
        
        let account = TreasuryAccount::new(account_id.clone(), account_type);
        self.accounts.insert(account_id.clone(), account);
        
        println!("💰 Created treasury account: {}", account_id);
        Ok(())
    }
    
    pub fn add_funds(&mut self, account_id: &str, amount: f64) -> Result<(), String> {
        let account = self.accounts.get_mut(account_id)
            .ok_or("Account not found")?;
        
        account.add_funds(amount)?;
        
        println!("💰 Added {} ST tokens to account {}", amount, account_id);
        Ok(())
    }
    
    pub fn create_disbursement_request(
        &mut self,
        proposal_id: String,
        recipient: String,
        amount: f64,
        category: DisbursementCategory,
        description: String,
    ) -> Result<String, String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }
        
        self.disbursement_counter += 1;
        let request_id = format!("DISB_{:08}", self.disbursement_counter);
        
        let request = DisbursementRequest {
            request_id: request_id.clone(),
            proposal_id,
            recipient,
            amount,
            category,
            description,
            status: DisbursementStatus::Pending,
            created_at: Utc::now().timestamp() as u64,
            approved_at: None,
            executed_at: None,
            metadata: serde_json::json!({}),
        };
        
        self.disbursements.insert(request_id.clone(), request);
        
        println!("📝 Created disbursement request: {} for {} ST", request_id, amount);
        Ok(request_id)
    }
    
    pub fn approve_disbursement(&mut self, request_id: &str, account_id: Option<&str>) -> Result<(), String> {
        let request = self.disbursements.get_mut(request_id)
            .ok_or("Disbursement request not found")?;
        
        if request.status != DisbursementStatus::Pending {
            return Err("Request is not in pending status".to_string());
        }
        
        // Determine which account to use
        let source_account_id = account_id.unwrap_or("treasury_main");
        
        let account = self.accounts.get_mut(source_account_id)
            .ok_or("Source account not found")?;
        
        // Reserve funds
        account.reserve_funds(request.amount)?;
        
        // Update request status
        request.status = DisbursementStatus::Approved;
        request.approved_at = Some(Utc::now().timestamp() as u64);
        
        println!("✅ Approved disbursement request: {} (reserved {} ST from {})", 
                request_id, request.amount, source_account_id);
        Ok(())
    }
    
    pub fn execute_disbursement(&mut self, request_id: &str, account_id: Option<&str>) -> Result<(), String> {
        let request = self.disbursements.get_mut(request_id)
            .ok_or("Disbursement request not found")?;
        
        if request.status != DisbursementStatus::Approved {
            return Err("Request is not approved".to_string());
        }
        
        // Determine which account to use
        let source_account_id = account_id.unwrap_or("treasury_main");
        
        let account = self.accounts.get_mut(source_account_id)
            .ok_or("Source account not found")?;
        
        // Release reserved funds (this removes from balance)
        account.release_reserved_funds(request.amount)?;
        
        // Update request status
        request.status = DisbursementStatus::Executed;
        request.executed_at = Some(Utc::now().timestamp() as u64);
        
        // Move to history
        self.disbursement_history.push(request.clone());
        
        println!("💸 Executed disbursement: {} ST to {} (request: {})", 
                request.amount, request.recipient, request_id);
        
        // In a real implementation, this would trigger the actual blockchain transaction
        // to transfer tokens to the recipient
        
        Ok(())
    }
    
    pub fn reject_disbursement(&mut self, request_id: &str, reason: String) -> Result<(), String> {
        let request = self.disbursements.get_mut(request_id)
            .ok_or("Disbursement request not found")?;
        
        if request.status != DisbursementStatus::Pending {
            return Err("Request is not in pending status".to_string());
        }
        
        request.status = DisbursementStatus::Rejected;
        request.metadata = serde_json::json!({ "rejection_reason": reason });
        
        println!("❌ Rejected disbursement request: {} (reason: {})", request_id, reason);
        Ok(())
    }
    
    pub fn cancel_disbursement(&mut self, request_id: &str, account_id: Option<&str>) -> Result<(), String> {
        let request = self.disbursements.get_mut(request_id)
            .ok_or("Disbursement request not found")?;
        
        // If approved, need to unreserve funds
        if request.status == DisbursementStatus::Approved {
            let source_account_id = account_id.unwrap_or("treasury_main");
            let account = self.accounts.get_mut(source_account_id)
                .ok_or("Source account not found")?;
            
            // Unreserve funds
            account.reserved -= request.amount;
            account.update_available();
        }
        
        request.status = DisbursementStatus::Cancelled;
        
        println!("🚫 Cancelled disbursement request: {}", request_id);
        Ok(())
    }
    
    pub fn get_account(&self, account_id: &str) -> Option<&TreasuryAccount> {
        self.accounts.get(account_id)
    }
    
    pub fn get_disbursement(&self, request_id: &str) -> Option<&DisbursementRequest> {
        self.disbursements.get(request_id)
    }
    
    pub fn list_pending_disbursements(&self) -> Vec<&DisbursementRequest> {
        self.disbursements.values()
            .filter(|r| r.status == DisbursementStatus::Pending)
            .collect()
    }
    
    pub fn get_treasury_stats(&self) -> TreasuryStats {
        let total_balance: f64 = self.accounts.values().map(|a| a.balance).sum();
        let total_reserved: f64 = self.accounts.values().map(|a| a.reserved).sum();
        let total_available: f64 = self.accounts.values().map(|a| a.available).sum();
        
        let total_disbursed: f64 = self.disbursement_history.iter()
            .filter(|r| r.status == DisbursementStatus::Executed)
            .map(|r| r.amount)
            .sum();
        
        TreasuryStats {
            total_balance,
            total_reserved,
            total_available,
            total_disbursed,
            disbursements_count: self.disbursement_history.len(),
            accounts_count: self.accounts.len(),
            calculated_at: Utc::now().timestamp() as u64,
        }
    }
    
    pub fn get_disbursements_by_category(&self, category: &DisbursementCategory) -> Vec<&DisbursementRequest> {
        self.disbursement_history.iter()
            .filter(|r| std::mem::discriminant(&r.category) == std::mem::discriminant(category))
            .collect()
    }
    
    pub fn get_disbursements_by_status(&self, status: &DisbursementStatus) -> Vec<&DisbursementRequest> {
        self.disbursements.values()
            .filter(|r| r.status == *status)
            .collect()
    }
    
    pub fn transfer_between_accounts(&mut self, from_account: &str, to_account: &str, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }
        
        // Check source account
        {
            let from_acc = self.accounts.get(from_account)
                .ok_or("Source account not found")?;
            
            if from_acc.available < amount {
                return Err("Insufficient available funds in source account".to_string());
            }
        }
        
        // Perform transfer
        {
            let from_acc = self.accounts.get_mut(from_account).unwrap();
            from_acc.balance -= amount;
            from_acc.update_available();
        }
        
        {
            let to_acc = self.accounts.get_mut(to_account)
                .ok_or("Destination account not found")?;
            to_acc.add_funds(amount)?;
        }
        
        println!("🔄 Transferred {} ST from {} to {}", amount, from_account, to_account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_treasury_account() {
        let mut account = TreasuryAccount::new("test_account".to_string(), AccountType::Main);
        
        assert_eq!(account.balance, 0.0);
        assert_eq!(account.available, 0.0);
        
        account.add_funds(1000.0).unwrap();
        assert_eq!(account.balance, 1000.0);
        assert_eq!(account.available, 1000.0);
        
        account.reserve_funds(300.0).unwrap();
        assert_eq!(account.reserved, 300.0);
        assert_eq!(account.available, 700.0);
        
        account.release_reserved_funds(300.0).unwrap();
        assert_eq!(account.balance, 700.0);
        assert_eq!(account.reserved, 0.0);
        assert_eq!(account.available, 700.0);
    }
    
    #[test]
    fn test_treasury_manager() {
        let mut manager = TreasuryManager::new();
        
        // Add funds to main account
        manager.add_funds("treasury_main", 10000.0).unwrap();
        
        // Create disbursement request
        let request_id = manager.create_disbursement_request(
            "PROP_001".to_string(),
            "wallet_123".to_string(),
            500.0,
            DisbursementCategory::Development,
            "Development bounty payment".to_string(),
        ).unwrap();
        
        // Approve and execute
        manager.approve_disbursement(&request_id, None).unwrap();
        manager.execute_disbursement(&request_id, None).unwrap();
        
        let stats = manager.get_treasury_stats();
        assert_eq!(stats.total_disbursed, 500.0);
        
        let main_account = manager.get_account("treasury_main").unwrap();
        assert_eq!(main_account.balance, 9500.0);
    }
    
    #[test]
    fn test_account_transfer() {
        let mut manager = TreasuryManager::new();
        
        manager.add_funds("treasury_main", 5000.0).unwrap();
        manager.transfer_between_accounts("treasury_main", "treasury_development", 1000.0).unwrap();
        
        let main_account = manager.get_account("treasury_main").unwrap();
        let dev_account = manager.get_account("treasury_development").unwrap();
        
        assert_eq!(main_account.balance, 4000.0);
        assert_eq!(dev_account.balance, 1000.0);
    }
}
