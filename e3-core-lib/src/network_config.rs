// src/network_config.rs
// Network configuration for peer discovery

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub bootstrap_peers: Vec<String>,
    pub enable_mdns: bool,
    pub enable_dht: bool,
    pub max_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            bootstrap_peers: vec![
                // Default bootstrap peers - can be overridden by environment variables
                "/ip4/203.0.113.1/tcp/4002".to_string(),
                "/ip4/198.51.100.2/tcp/4003".to_string(),
            ],
            enable_mdns: true,
            enable_dht: true,
            max_peers: 50,
        }
    }
}

impl NetworkConfig {
    /// Load configuration from environment variables and defaults
    pub fn from_env() -> Self {
        let mut config = Self::default();
        
        // Read bootstrap peers from environment variable
        if let Ok(peers_str) = env::var("E3_BOOTSTRAP_PEERS") {
            config.bootstrap_peers = peers_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        
        // Read mDNS setting from environment
        if let Ok(mdns_str) = env::var("E3_ENABLE_MDNS") {
            config.enable_mdns = mdns_str.to_lowercase() == "true";
        }
        
        // Read DHT setting from environment
        if let Ok(dht_str) = env::var("E3_ENABLE_DHT") {
            config.enable_dht = dht_str.to_lowercase() == "true";
        }
        
        // Read max peers from environment
        if let Ok(max_peers_str) = env::var("E3_MAX_PEERS") {
            if let Ok(max_peers) = max_peers_str.parse::<usize>() {
                config.max_peers = max_peers;
            }
        }
        
        config
    }
    
    /// Create a config with custom bootstrap peers
    pub fn with_bootstrap_peers(peers: Vec<String>) -> Self {
        Self {
            bootstrap_peers: peers,
            ..Self::default()
        }
    }
    
    /// Create a config for local testing (mDNS only)
    pub fn local_only() -> Self {
        Self {
            bootstrap_peers: vec![],
            enable_mdns: true,
            enable_dht: false,
            max_peers: 10,
        }
    }
    
    /// Get all discovery methods as a descriptive string
    pub fn discovery_methods(&self) -> String {
        let mut methods = Vec::new();
        
        if self.enable_mdns {
            methods.push("mDNS (LAN)".to_string());
        }
        
        if self.enable_dht {
            methods.push("DHT (Global)".to_string());
        }
        
        if !self.bootstrap_peers.is_empty() {
            methods.push(format!("Bootstrap ({} peers)", self.bootstrap_peers.len()));
        }
        
        if methods.is_empty() {
            "None".to_string()
        } else {
            methods.join(", ")
        }
    }
}

/// Helper function to parse multiaddr strings and validate them
pub fn validate_multiaddr(addr: &str) -> Result<(), String> {
    use libp2p::Multiaddr;
    
    match addr.parse::<Multiaddr>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Invalid multiaddr '{}': {}", addr, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert!(config.enable_mdns);
        assert!(config.enable_dht);
        assert!(!config.bootstrap_peers.is_empty());
    }
    
    #[test]
    fn test_local_only_config() {
        let config = NetworkConfig::local_only();
        assert!(config.enable_mdns);
        assert!(!config.enable_dht);
        assert!(config.bootstrap_peers.is_empty());
    }
    
    #[test]
    fn test_multiaddr_validation() {
        assert!(validate_multiaddr("/ip4/127.0.0.1/tcp/4001").is_ok());
        assert!(validate_multiaddr("/ip4/203.0.113.1/tcp/4002").is_ok());
        assert!(validate_multiaddr("invalid-address").is_err());
    }
}
