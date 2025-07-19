use serde::{Deserialize, Serialize};

/// Events that can be emitted by the admin chain and processed by the public chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminEvent {
    /// Gold Unit minted on admin chain
    GUMinted {
        to: String,
        amount: u64,
        proof_hash: String,
        timestamp: u64,
        admin_signature: String,
    },
    /// Gold Unit burned on admin chain
    GUBurned {
        from: String,
        amount: u64,
        timestamp: u64,
        admin_signature: String,
    },
    /// Proof of reserve submitted
    ProofOfReserve {
        proof_hash: String,
        reserve_amount: u64,
        timestamp: u64,
        admin_signature: String,
    },
}

/// Events that can be emitted by the public chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicEvent {
    /// Standard Unit minted on public chain
    SUMinted {
        to: String,
        amount: u64,
        trigger: MintTrigger,
        timestamp: u64,
    },
    /// Standard Unit burned on public chain
    SUBurned {
        from: String,
        amount: u64,
        reason: BurnReason,
        timestamp: u64,
    },
    /// Standard Unit transferred
    SUTransferred {
        from: String,
        to: String,
        amount: u64,
        timestamp: u64,
    },
    /// Admin event processed (receipt)
    AdminEventProcessed {
        event_id: String,
        event_type: String,
        success: bool,
        error_message: Option<String>,
        timestamp: u64,
    },
}

/// Reasons why SU tokens are minted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MintTrigger {
    /// Minted due to GU minting (1 GU = 20 SU)
    GUMint { gu_amount: u64 },
    /// Minted algorithmically based on chain health
    Algorithmic { health_factor: f64 },
    /// Manual mint by authorized user
    Manual,
}

/// Reasons why SU tokens are burned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BurnReason {
    /// Burned for physical asset redemption
    Redemption,
    /// Burned for loan repayment
    LoanRepayment,
    /// Burned for supply control
    SupplyControl,
    /// Manual burn
    Manual,
}

/// Receipt sent from public chain to admin chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub event_id: String,
    pub event_type: String,
    pub success: bool,
    pub error_message: Option<String>,
    pub su_minted: Option<u64>,
    pub new_su_supply: u64,
    pub new_gu_supply_mirrored: u64,
    pub timestamp: u64,
    pub public_node_signature: String,
}

/// Cross-chain message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    pub id: String,
    pub timestamp: u64,
    pub from_chain: ChainType,
    pub to_chain: ChainType,
    pub payload: MessagePayload,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainType {
    Admin,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    AdminEvent(AdminEvent),
    PublicEvent(PublicEvent),
    ExecutionReceipt(ExecutionReceipt),
}

impl AdminEvent {
    /// Generate a unique ID for this event
    pub fn generate_id(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("admin_event_{:x}", hasher.finish())
    }

    /// Get the timestamp of this event
    pub fn get_timestamp(&self) -> u64 {
        match self {
            AdminEvent::GUMinted { timestamp, .. } => *timestamp,
            AdminEvent::GUBurned { timestamp, .. } => *timestamp,
            AdminEvent::ProofOfReserve { timestamp, .. } => *timestamp,
        }
    }
}

impl PublicEvent {
    /// Generate a unique ID for this event
    pub fn generate_id(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("public_event_{:x}", hasher.finish())
    }

    /// Get the timestamp of this event
    pub fn get_timestamp(&self) -> u64 {
        match self {
            PublicEvent::SUMinted { timestamp, .. } => *timestamp,
            PublicEvent::SUBurned { timestamp, .. } => *timestamp,
            PublicEvent::SUTransferred { timestamp, .. } => *timestamp,
            PublicEvent::AdminEventProcessed { timestamp, .. } => *timestamp,
        }
    }
}

impl CrossChainMessage {
    pub fn new(
        from_chain: ChainType,
        to_chain: ChainType,
        payload: MessagePayload,
        signature: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        use uuid::Uuid;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id: Uuid::new_v4().to_string(),
            timestamp,
            from_chain,
            to_chain,
            payload,
            signature,
        }
    }
}

// Hash implementations for event ID generation
use std::hash::{Hash, Hasher};

impl Hash for AdminEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            AdminEvent::GUMinted { to, amount, proof_hash, timestamp, .. } => {
                "GUMinted".hash(state);
                to.hash(state);
                amount.hash(state);
                proof_hash.hash(state);
                timestamp.hash(state);
            }
            AdminEvent::GUBurned { from, amount, timestamp, .. } => {
                "GUBurned".hash(state);
                from.hash(state);
                amount.hash(state);
                timestamp.hash(state);
            }
            AdminEvent::ProofOfReserve { proof_hash, reserve_amount, timestamp, .. } => {
                "ProofOfReserve".hash(state);
                proof_hash.hash(state);
                reserve_amount.hash(state);
                timestamp.hash(state);
            }
        }
    }
}

impl Hash for PublicEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PublicEvent::SUMinted { to, amount, timestamp, .. } => {
                "SUMinted".hash(state);
                to.hash(state);
                amount.hash(state);
                timestamp.hash(state);
            }
            PublicEvent::SUBurned { from, amount, timestamp, .. } => {
                "SUBurned".hash(state);
                from.hash(state);
                amount.hash(state);
                timestamp.hash(state);
            }
            PublicEvent::SUTransferred { from, to, amount, timestamp } => {
                "SUTransferred".hash(state);
                from.hash(state);
                to.hash(state);
                amount.hash(state);
                timestamp.hash(state);
            }
            PublicEvent::AdminEventProcessed { event_id, timestamp, .. } => {
                "AdminEventProcessed".hash(state);
                event_id.hash(state);
                timestamp.hash(state);
            }
        }
    }
}
