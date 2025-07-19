use crate::tokens::{StandardUnit, TokenError};
use serde::{Deserialize, Serialize};

/// Chain health factors and metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHealth {
    pub uptime_factor: f64,        // 0.0 to 1.0
    pub activity_factor: f64,      // 0.0 to 1.0
    pub network_factor: f64,       // 0.0 to 1.0
    pub overall_health: f64,       // Combined health score
    pub last_updated: u64,
}

impl ChainHealth {
    pub fn new() -> Self {
        Self {
            uptime_factor: 1.0,
            activity_factor: 1.0,
            network_factor: 1.0,
            overall_health: 1.0,
            last_updated: 0,
        }
    }

    /// Calculate overall health from individual factors
    pub fn calculate_overall_health(&mut self) {
        // Weighted average of health factors
        self.overall_health = (self.uptime_factor * 0.4) + 
                             (self.activity_factor * 0.3) + 
                             (self.network_factor * 0.3);
        
        // Ensure health is between 0.0 and 1.0
        self.overall_health = self.overall_health.max(0.0).min(1.0);
    }

    /// Update uptime factor based on node uptime percentage
    pub fn update_uptime(&mut self, uptime_percentage: f64, timestamp: u64) {
        self.uptime_factor = (uptime_percentage / 100.0).max(0.0).min(1.0);
        self.last_updated = timestamp;
        self.calculate_overall_health();
    }

    /// Update activity factor based on transaction volume
    pub fn update_activity(&mut self, tx_per_minute: f64, timestamp: u64) {
        // Normalize activity (assume 100 tx/min = perfect activity)
        self.activity_factor = (tx_per_minute / 100.0).max(0.0).min(1.0);
        self.last_updated = timestamp;
        self.calculate_overall_health();
    }

    /// Update network factor based on peer count and connectivity
    pub fn update_network(&mut self, peer_count: u32, target_peers: u32, timestamp: u64) {
        self.network_factor = if target_peers > 0 {
            (peer_count as f64 / target_peers as f64).max(0.0).min(1.0)
        } else {
            0.0
        };
        self.last_updated = timestamp;
        self.calculate_overall_health();
    }
}

/// Tokenomics engine that manages SU supply based on GU supply and chain health
#[derive(Debug, Clone)]
pub struct TokenomicsEngine {
    pub chain_health: ChainHealth,
    pub su_to_gu_ratio: f64,       // Base ratio (default: 20.0)
    pub min_health_threshold: f64,  // Minimum health for minting (default: 0.1)
    pub max_health_bonus: f64,      // Maximum health bonus multiplier (default: 1.5)
}

impl TokenomicsEngine {
    pub fn new() -> Self {
        Self {
            chain_health: ChainHealth::new(),
            su_to_gu_ratio: 20.0,
            min_health_threshold: 0.1,
            max_health_bonus: 1.5,
        }
    }

    /// Calculate maximum SU supply based on GU supply and chain health
    /// Formula: SU_max = GU_supply × su_to_gu_ratio × health_factor
    pub fn calculate_max_su_supply(&self, gu_supply: u64) -> u64 {
        let health_factor = self.get_effective_health_factor();
        let max_supply = (gu_supply as f64) * self.su_to_gu_ratio * health_factor;
        max_supply as u64
    }

    /// Calculate how much SU should be minted when GU is minted
    /// Standard rule: 1 GU = 20 SU (modified by health)
    pub fn calculate_su_mint_for_gu(&self, gu_amount: u64) -> u64 {
        let health_factor = self.get_effective_health_factor();
        let su_amount = (gu_amount as f64) * self.su_to_gu_ratio * health_factor;
        su_amount as u64
    }

    /// Get effective health factor for calculations
    fn get_effective_health_factor(&self) -> f64 {
        let health = self.chain_health.overall_health;
        
        // If health is below threshold, reduce minting capability
        if health < self.min_health_threshold {
            return self.min_health_threshold;
        }
        
        // Apply health bonus (up to max_health_bonus)
        let health_factor = health.min(self.max_health_bonus);
        health_factor
    }

    /// Check if SU minting is allowed given current conditions
    pub fn can_mint_su(&self, amount: u64, current_su_supply: u64, gu_supply: u64) -> bool {
        let max_supply = self.calculate_max_su_supply(gu_supply);
        current_su_supply + amount <= max_supply
    }

    /// Update chain health and recalculate supply cap
    pub fn update_chain_health(&mut self, standard_unit: &mut StandardUnit, gu_supply: u64) {
        let health_factor = self.get_effective_health_factor();
        standard_unit.update_gu_supply(gu_supply, health_factor);
    }

    /// Update uptime and recalculate health
    pub fn update_uptime(&mut self, uptime_percentage: f64, timestamp: u64) {
        self.chain_health.update_uptime(uptime_percentage, timestamp);
    }

    /// Update activity and recalculate health
    pub fn update_activity(&mut self, tx_per_minute: f64, timestamp: u64) {
        self.chain_health.update_activity(tx_per_minute, timestamp);
    }

    /// Update network health and recalculate health
    pub fn update_network(&mut self, peer_count: u32, target_peers: u32, timestamp: u64) {
        self.chain_health.update_network(peer_count, target_peers, timestamp);
    }

    /// Suggest SU burn amount to maintain healthy supply ratio
    pub fn suggest_su_burn_for_supply_control(&self, current_su_supply: u64, gu_supply: u64) -> u64 {
        let max_supply = self.calculate_max_su_supply(gu_supply);
        if current_su_supply > max_supply {
            current_su_supply - max_supply
        } else {
            0
        }
    }

    /// Get current tokenomics info for reporting
    pub fn get_tokenomics_info(&self, su_supply: u64, gu_supply: u64) -> TokenomicsInfo {
        TokenomicsInfo {
            gu_supply,
            su_supply,
            max_su_supply: self.calculate_max_su_supply(gu_supply),
            health_factor: self.get_effective_health_factor(),
            su_to_gu_ratio: self.su_to_gu_ratio,
            chain_health: self.chain_health.clone(),
            utilization_ratio: if gu_supply > 0 {
                su_supply as f64 / self.calculate_max_su_supply(gu_supply) as f64
            } else {
                0.0
            },
        }
    }
}

/// Tokenomics information for reporting and API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenomicsInfo {
    pub gu_supply: u64,
    pub su_supply: u64,
    pub max_su_supply: u64,
    pub health_factor: f64,
    pub su_to_gu_ratio: f64,
    pub chain_health: ChainHealth,
    pub utilization_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_health_calculation() {
        let mut health = ChainHealth::new();
        health.uptime_factor = 0.9;
        health.activity_factor = 0.8;
        health.network_factor = 0.7;
        health.calculate_overall_health();
        
        // 0.9 * 0.4 + 0.8 * 0.3 + 0.7 * 0.3 = 0.36 + 0.24 + 0.21 = 0.81
        assert!((health.overall_health - 0.81).abs() < 0.01);
    }

    #[test]
    fn test_tokenomics_max_supply() {
        let engine = TokenomicsEngine::new();
        let gu_supply = 10;
        let max_su = engine.calculate_max_su_supply(gu_supply);
        
        // 10 GU * 20 ratio * 1.0 health = 200 SU
        assert_eq!(max_su, 200);
    }

    #[test]
    fn test_su_mint_calculation() {
        let engine = TokenomicsEngine::new();
        let gu_amount = 5;
        let su_to_mint = engine.calculate_su_mint_for_gu(gu_amount);
        
        // 5 GU * 20 ratio * 1.0 health = 100 SU
        assert_eq!(su_to_mint, 100);
    }

    #[test]
    fn test_reduced_health_impact() {
        let mut engine = TokenomicsEngine::new();
        engine.chain_health.overall_health = 0.5;
        
        let gu_amount = 10;
        let su_to_mint = engine.calculate_su_mint_for_gu(gu_amount);
        
        // 10 GU * 20 ratio * 0.5 health = 100 SU
        assert_eq!(su_to_mint, 100);
    }

    #[test]
    fn test_can_mint_su() {
        let engine = TokenomicsEngine::new();
        let gu_supply = 10; // Max SU = 200
        let current_su_supply = 150;
        
        assert!(engine.can_mint_su(50, current_su_supply, gu_supply));
        assert!(!engine.can_mint_su(51, current_su_supply, gu_supply));
    }
}
