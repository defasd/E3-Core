pub mod blockchain;
pub mod storage;
pub mod p2p;
pub mod rpc;
pub mod block;
pub mod node;
pub mod network_config;
pub mod peer_discovery;
pub mod tokens;
pub mod events;
pub mod tokenomics;
pub mod wallet;

// Re-export commonly used types for easy access
pub use p2p::BlockHeader;
pub use blockchain::Blockchain;
pub use block::Block;
pub use network_config::NetworkConfig;
pub use peer_discovery::{PeerDiscoveryService, DiscoveryEvent};
pub use tokens::{GoldUnit, StandardUnit, TokenError};
pub use events::{AdminEvent, PublicEvent, CrossChainMessage, ExecutionReceipt};
pub use tokenomics::{TokenomicsEngine, ChainHealth, TokenomicsInfo};
pub use wallet::{
    UserWallet, TreasuryWallet, ValidatorWallet, MerchantWallet,
    Transaction, TransactionStatus, WalletSignature, ProofOfReserve,
    WalletManager, TransactionReceipt, WalletSystemStats
};

// Core blockchain functionality shared across all nodes
pub use p2p::P2PNetwork;
pub use storage::{Storage, open_db};
