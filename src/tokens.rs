use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Errors that can occur during token operations
#[derive(Debug, Clone)]
pub enum TokenError {
    InsufficientBalance,
    InvalidAmount,
    InvalidAddress,
    Unauthorized,
    SupplyCapExceeded,
    TransferFailed,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TokenError::InsufficientBalance => write!(f, "Insufficient balance"),
            TokenError::InvalidAmount => write!(f, "Invalid amount"),
            TokenError::InvalidAddress => write!(f, "Invalid address"),
            TokenError::Unauthorized => write!(f, "Unauthorized operation"),
            TokenError::SupplyCapExceeded => write!(f, "Supply cap exceeded"),
            TokenError::TransferFailed => write!(f, "Transfer failed"),
        }
    }
}

impl Error for TokenError {}

/// Gold Units (GU) - Admin chain token backed by physical gold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldUnit {
    pub total_supply: u64,
    pub balances: HashMap<String, u64>,
    pub metadata: GoldUnitMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldUnitMetadata {
    pub last_mint_timestamp: u64,
    pub last_burn_timestamp: u64,
    pub total_minted: u64,
    pub total_burned: u64,
}

/// Standard Units (SU) - Public chain utility token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardUnit {
    pub total_supply: u64,
    pub balances: HashMap<String, u64>,
    pub metadata: StandardUnitMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardUnitMetadata {
    pub mirrored_gu_supply: u64,
    pub max_supply_cap: u64,
    pub health_factor: f64,
    pub last_mint_timestamp: u64,
    pub total_minted: u64,
    pub total_burned: u64,
}

impl GoldUnit {
    pub fn new() -> Self {
        Self {
            total_supply: 0,
            balances: HashMap::new(),
            metadata: GoldUnitMetadata {
                last_mint_timestamp: 0,
                last_burn_timestamp: 0,
                total_minted: 0,
                total_burned: 0,
            },
        }
    }

    /// Mint GU tokens to a specific address (admin only)
    pub fn mint(&mut self, to: &str, amount: u64, timestamp: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if to.is_empty() {
            return Err(TokenError::InvalidAddress);
        }

        // Check for overflow
        if self.total_supply.checked_add(amount).is_none() {
            return Err(TokenError::SupplyCapExceeded);
        }

        *self.balances.entry(to.to_string()).or_insert(0) += amount;
        self.total_supply += amount;
        self.metadata.total_minted += amount;
        self.metadata.last_mint_timestamp = timestamp;

        Ok(())
    }

    /// Burn GU tokens from a specific address (admin only)
    pub fn burn(&mut self, from: &str, amount: u64, timestamp: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if from.is_empty() {
            return Err(TokenError::InvalidAddress);
        }

        let balance = self.balances.get(from).unwrap_or(&0);
        if *balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        *self.balances.entry(from.to_string()).or_insert(0) -= amount;
        self.total_supply -= amount;
        self.metadata.total_burned += amount;
        self.metadata.last_burn_timestamp = timestamp;

        Ok(())
    }

    /// Transfer GU tokens between addresses (admin only)
    pub fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if from.is_empty() || to.is_empty() {
            return Err(TokenError::InvalidAddress);
        }
        if from == to {
            return Ok(()); // No-op for same address
        }

        let from_balance = self.balances.get(from).unwrap_or(&0);
        if *from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        *self.balances.entry(from.to_string()).or_insert(0) -= amount;
        *self.balances.entry(to.to_string()).or_insert(0) += amount;

        Ok(())
    }

    /// Get balance for a specific address
    pub fn get_balance(&self, address: &str) -> u64 {
        *self.balances.get(address).unwrap_or(&0)
    }

    /// Get total supply
    pub fn get_total_supply(&self) -> u64 {
        self.total_supply
    }
}

impl StandardUnit {
    pub fn new() -> Self {
        Self {
            total_supply: 0,
            balances: HashMap::new(),
            metadata: StandardUnitMetadata {
                mirrored_gu_supply: 0,
                max_supply_cap: 0,
                health_factor: 1.0,
                last_mint_timestamp: 0,
                total_minted: 0,
                total_burned: 0,
            },
        }
    }

    /// Update the mirrored GU supply and recalculate max supply cap
    pub fn update_gu_supply(&mut self, gu_supply: u64, health_factor: f64) {
        self.metadata.mirrored_gu_supply = gu_supply;
        self.metadata.health_factor = health_factor;
        // Rule: SU ≤ GU × 20 × health_factor
        self.metadata.max_supply_cap = ((gu_supply as f64) * 20.0 * health_factor) as u64;
    }

    /// Mint SU tokens (called when GU is minted or algorithmically)
    pub fn mint(&mut self, to: &str, amount: u64, timestamp: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if to.is_empty() {
            return Err(TokenError::InvalidAddress);
        }

        // Check supply cap
        if self.total_supply + amount > self.metadata.max_supply_cap {
            return Err(TokenError::SupplyCapExceeded);
        }

        // Check for overflow
        if self.total_supply.checked_add(amount).is_none() {
            return Err(TokenError::SupplyCapExceeded);
        }

        *self.balances.entry(to.to_string()).or_insert(0) += amount;
        self.total_supply += amount;
        self.metadata.total_minted += amount;
        self.metadata.last_mint_timestamp = timestamp;

        Ok(())
    }

    /// Burn SU tokens from a specific address
    pub fn burn(&mut self, from: &str, amount: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if from.is_empty() {
            return Err(TokenError::InvalidAddress);
        }

        let balance = self.balances.get(from).unwrap_or(&0);
        if *balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        *self.balances.entry(from.to_string()).or_insert(0) -= amount;
        self.total_supply -= amount;
        self.metadata.total_burned += amount;

        Ok(())
    }

    /// Transfer SU tokens between addresses
    pub fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if from.is_empty() || to.is_empty() {
            return Err(TokenError::InvalidAddress);
        }
        if from == to {
            return Ok(()); // No-op for same address
        }

        let from_balance = self.balances.get(from).unwrap_or(&0);
        if *from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        *self.balances.entry(from.to_string()).or_insert(0) -= amount;
        *self.balances.entry(to.to_string()).or_insert(0) += amount;

        Ok(())
    }

    /// Get balance for a specific address
    pub fn get_balance(&self, address: &str) -> u64 {
        *self.balances.get(address).unwrap_or(&0)
    }

    /// Get total supply
    pub fn get_total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Get current supply cap
    pub fn get_max_supply_cap(&self) -> u64 {
        self.metadata.max_supply_cap
    }

    /// Get mirrored GU supply
    pub fn get_mirrored_gu_supply(&self) -> u64 {
        self.metadata.mirrored_gu_supply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gu_mint() {
        let mut gu = GoldUnit::new();
        assert!(gu.mint("alice", 100, 1000).is_ok());
        assert_eq!(gu.get_balance("alice"), 100);
        assert_eq!(gu.get_total_supply(), 100);
    }

    #[test]
    fn test_gu_burn() {
        let mut gu = GoldUnit::new();
        gu.mint("alice", 100, 1000).unwrap();
        assert!(gu.burn("alice", 50, 2000).is_ok());
        assert_eq!(gu.get_balance("alice"), 50);
        assert_eq!(gu.get_total_supply(), 50);
    }

    #[test]
    fn test_gu_transfer() {
        let mut gu = GoldUnit::new();
        gu.mint("alice", 100, 1000).unwrap();
        assert!(gu.transfer("alice", "bob", 30).is_ok());
        assert_eq!(gu.get_balance("alice"), 70);
        assert_eq!(gu.get_balance("bob"), 30);
    }

    #[test]
    fn test_su_supply_cap() {
        let mut su = StandardUnit::new();
        su.update_gu_supply(10, 1.0); // 10 GU * 20 * 1.0 = 200 SU max
        assert_eq!(su.get_max_supply_cap(), 200);
        
        assert!(su.mint("alice", 200, 1000).is_ok());
        assert!(su.mint("bob", 1, 2000).is_err()); // Should exceed cap
    }

    #[test]
    fn test_su_mint_and_transfer() {
        let mut su = StandardUnit::new();
        su.update_gu_supply(10, 1.0);
        
        su.mint("alice", 100, 1000).unwrap();
        assert!(su.transfer("alice", "bob", 30).is_ok());
        assert_eq!(su.get_balance("alice"), 70);
        assert_eq!(su.get_balance("bob"), 30);
    }
}
