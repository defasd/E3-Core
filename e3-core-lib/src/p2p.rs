use futures::stream::StreamExt;
use futures::Stream;
use libp2p::{
    gossipsub::{Behaviour as Gossipsub, Config as GossipsubConfig, Event as GossipsubEvent, IdentTopic as Topic, MessageAuthenticity},
    mdns::{tokio::Behaviour as Mdns, Event as MdnsEvent},
    request_response::{Behaviour as RequestResponse, Config as RequestResponseConfig, Event as RequestResponseEvent, ProtocolSupport, ResponseChannel, RequestId},
    kad::{Kademlia, KademliaConfig, KademliaEvent, record::store::MemoryStore, QueryId, record::Key, Quorum, Record, GetRecordOk, PeerRecord},
    swarm::{Swarm, SwarmBuilder, SwarmEvent, NetworkBehaviour},
    identity, PeerId, noise, tcp, yamux, Transport, core::upgrade, Multiaddr,
};
use serde::{Serialize, Deserialize};
use bincode;
use std::error::Error;
use std::collections::HashMap;
use std::time::Duration;
use std::io;
use futures::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::storage::Storage;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub index: u64,
    pub prev_hash: String,
    pub hash: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainSummary {
    pub latest_index: u64,
    pub latest_hash: String,
    pub chain_length: u64,
}

// Enhanced message types for P2P communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlockMessage {
    BlockHeader(BlockHeader),
    FullBlock(Block),
    BlockRequest(BlockRequest),
    BlockResponse(BlockResponse),
    BlockAnnouncement(BlockAnnouncement),
    ChainSummary(ChainSummary),
    ChainData(Vec<Block>),
    ChainRequest,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockRequest {
    pub start_index: u64,
    pub end_index: u64,
    pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockResponse {
    pub blocks: Vec<Block>,
    pub request_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockAnnouncement {
    pub block_header: BlockHeader,
    pub peer_height: u64,
}

// Simple message structure for P2P communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub message_type: String,
    pub content: String,
    pub sender: String,
    pub timestamp: u64,
}

impl Message {
    pub fn new(message_type: String, content: String, sender: String) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            message_type,
            content,
            sender,
            timestamp,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn from_json(json_str: &str) -> Option<Self> {
        serde_json::from_str(json_str).ok()
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.message_type, self.sender, self.content)
    }
}

// Block request/response protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequestProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSyncRequest {
    pub start_index: u64,
    pub end_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSyncResponse {
    pub blocks: Vec<Block>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[async_trait]
impl libp2p::request_response::Codec for BlockRequestProtocol {
    type Protocol = String;
    type Request = BlockSyncRequest;
    type Response = BlockSyncResponse;

    async fn read_request<T>(
        &mut self, 
        _: &Self::Protocol, 
        io: &mut T
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut length_bytes = [0u8; 4];
        io.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let mut buffer = vec![0u8; length];
        io.read_exact(&mut buffer).await?;
        bincode::deserialize(&buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self, 
        _: &Self::Protocol, 
        io: &mut T
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut length_bytes = [0u8; 4];
        io.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let mut buffer = vec![0u8; length];
        io.read_exact(&mut buffer).await?;
        bincode::deserialize(&buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self, 
        _: &Self::Protocol, 
        io: &mut T, 
        req: Self::Request
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let length = data.len() as u32;
        io.write_all(&length.to_be_bytes()).await?;
        io.write_all(&data).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self, 
        _: &Self::Protocol, 
        io: &mut T, 
        res: Self::Response
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&res)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let length = data.len() as u32;
        io.write_all(&length.to_be_bytes()).await?;
        io.write_all(&data).await?;
        io.close().await?;
        Ok(())
    }
}

// Enhanced sync state management
pub struct BlockSyncState {
    pub local_height: u64,
    pub peer_heights: HashMap<PeerId, u64>,
    pub pending_requests: HashMap<RequestId, BlockSyncRequest>,
    pub sync_in_progress: bool,
    pub target_height: u64,
}

impl BlockSyncState {
    pub fn new() -> Self {
        Self {
            local_height: 0,
            peer_heights: HashMap::new(),
            pending_requests: HashMap::new(),
            sync_in_progress: false,
            target_height: 0,
        }
    }

    pub fn update_peer_height(&mut self, peer_id: PeerId, height: u64) {
        self.peer_heights.insert(peer_id, height);
        self.target_height = self.peer_heights.values().max().copied().unwrap_or(0);
    }

    pub fn needs_sync(&self) -> bool {
        self.target_height > self.local_height
    }

    pub fn get_missing_blocks(&self) -> Vec<u64> {
        if self.needs_sync() {
            (self.local_height + 1..=self.target_height).collect()
        } else {
            vec![]
        }
    }
}

#[derive(NetworkBehaviour)]
pub struct MyBehaviour {
    pub gossipsub: Gossipsub,
    pub mdns: Mdns,
    pub request_response: RequestResponse<BlockRequestProtocol>,
    pub kademlia: Kademlia<MemoryStore>,
}

impl MyBehaviour {
    pub fn new(local_key: &identity::Keypair) -> anyhow::Result<Self> {
        let local_peer_id = PeerId::from(local_key.public());
        let gossipsub_config = GossipsubConfig::default();
        let mut gossipsub = Gossipsub::new(MessageAuthenticity::Signed(local_key.clone()), gossipsub_config)
            .map_err(|e| anyhow::anyhow!("Failed to create gossipsub: {:?}", e))?;
        
        // Subscribe to multiple topics
        gossipsub.subscribe(&Topic::new("block-headers"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to block-headers topic: {:?}", e))?;
        gossipsub.subscribe(&Topic::new("full-blocks"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to full-blocks topic: {:?}", e))?;
        gossipsub.subscribe(&Topic::new("block-announcements"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to block-announcements topic: {:?}", e))?;
        gossipsub.subscribe(&Topic::new("chain-sync"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to chain-sync topic: {:?}", e))?;
        gossipsub.subscribe(&Topic::new("admin_actions"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to admin_actions topic: {:?}", e))?;
        gossipsub.subscribe(&Topic::new("admin_receipts"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to admin_receipts topic: {:?}", e))?;
        gossipsub.subscribe(&Topic::new("general"))
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to general topic: {:?}", e))?;
        
        // Configure RequestResponse
        let mut request_response_config = RequestResponseConfig::default();
        request_response_config.set_request_timeout(Duration::from_secs(30));
        
        let request_response = RequestResponse::new(
            BlockRequestProtocol,
            std::iter::once(("/block-sync/1.0.0".to_string(), ProtocolSupport::Full)),
            request_response_config,
        );
        
        // Create mDNS with more explicit configuration for better peer discovery
        let mdns_config = libp2p::mdns::Config::default();
        let mdns = Mdns::new(mdns_config, local_peer_id)?;
        println!("mDNS initialized for peer discovery with peer_id: {}", local_peer_id);
        
        // Initialize Kademlia DHT
        let store = MemoryStore::new(local_peer_id.clone());
        let mut kad_config = KademliaConfig::default();
        // Set custom query timeout and replication factor
        kad_config.set_query_timeout(Duration::from_secs(60));
        kad_config.set_replication_factor(std::num::NonZeroUsize::new(3).unwrap());
        let kademlia = Kademlia::with_config(local_peer_id.clone(), store, kad_config);
        
        // Kademlia is automatically set to server mode when created
        println!("Kademlia DHT initialized for peer discovery with peer_id: {}", local_peer_id);
        
        Ok(Self { gossipsub, mdns, request_response, kademlia })
    }

    // Chain sync methods
    pub fn send_chain_summary(&mut self, blockchain: &Arc<Mutex<Blockchain>>) -> Result<(), Box<dyn Error>> {
        let blockchain = blockchain.lock().unwrap();
        let latest_block = blockchain.latest();
        
        let summary = ChainSummary {
            latest_index: latest_block.index,
            latest_hash: latest_block.hash.clone(),
            chain_length: blockchain.chain.len() as u64,
        };
        
        let topic = Topic::new("chain-sync");
        let message = BlockMessage::ChainSummary(summary);
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Sent chain summary: index={}, hash={}, length={}", 
            latest_block.index, latest_block.hash, blockchain.chain.len());
        Ok(())
    }

    pub fn request_full_chain(&mut self, peer_id: PeerId) -> Result<(), Box<dyn Error>> {
        let topic = Topic::new("chain-sync");
        let message = BlockMessage::ChainRequest;
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Requested full chain from peer: {}", peer_id);
        Ok(())
    }

    pub fn send_full_chain(&mut self, blockchain: &Arc<Mutex<Blockchain>>) -> Result<(), Box<dyn Error>> {
        let blockchain = blockchain.lock().unwrap();
        let chain_data = blockchain.chain.clone();
        
        let topic = Topic::new("chain-sync");
        let message = BlockMessage::ChainData(chain_data);
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Sent full chain with {} blocks", blockchain.chain.len());
        Ok(())
    }

    // Enhanced block broadcasting methods
    pub fn publish_block_header(&mut self, block_header: &BlockHeader) -> Result<(), Box<dyn Error>> {
        let topic = Topic::new("block-headers");
        let message = BlockMessage::BlockHeader(block_header.clone());
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Published block header for index: {}", block_header.index);
        Ok(())
    }

    pub fn publish_full_block(&mut self, block: &Block) -> Result<(), Box<dyn Error>> {
        let topic = Topic::new("full-blocks");
        let message = BlockMessage::FullBlock(block.clone());
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Published full block for index: {}", block.index);
        Ok(())
    }

    pub fn publish_block_announcement(&mut self, block_header: &BlockHeader, peer_height: u64) -> Result<(), Box<dyn Error>> {
        let topic = Topic::new("block-announcements");
        let announcement = BlockAnnouncement {
            block_header: block_header.clone(),
            peer_height,
        };
        let message = BlockMessage::BlockAnnouncement(announcement);
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Published block announcement for index: {} with peer height: {}", block_header.index, peer_height);
        Ok(())
    }

    pub fn broadcast_height(&mut self, local_height: u64) -> Result<(), Box<dyn Error>> {
        let topic = Topic::new("block-announcements");
        let announcement = BlockAnnouncement {
            block_header: BlockHeader {
                index: local_height,
                prev_hash: "".to_string(),
                hash: "".to_string(),
                timestamp: 0,
            },
            peer_height: local_height,
        };
        let message = BlockMessage::BlockAnnouncement(announcement);
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Broadcasted blockchain height: {}", local_height);
        Ok(())
    }

    // Enhanced missing block detection with real blockchain state
    pub fn check_missing_blocks(&self, block_header: &BlockHeader, local_height: u64) -> Option<Vec<u64>> {
        // If received block index is higher than our local height, we're missing blocks
        if block_header.index > local_height + 1 {
            let missing_range = (local_height + 1)..block_header.index;
            let missing_blocks: Vec<u64> = missing_range.collect();
            return Some(missing_blocks);
        }
        
        // If we don't have this specific block, request it
        if block_header.index > local_height {
            return Some(vec![block_header.index]);
        }
        
        None
    }

    // Enhanced block sync methods
    pub fn request_blocks(&mut self, peer_id: PeerId, start_index: u64, end_index: u64) -> RequestId {
        let request = BlockSyncRequest {
            start_index,
            end_index,
        };
        let request_id = self.request_response.send_request(&peer_id, request.clone());
        println!("Requested blocks {}-{} from peer: {}", start_index, end_index, peer_id);
        request_id
    }

    pub fn respond_to_block_request(&mut self, request: BlockSyncRequest, channel: ResponseChannel<BlockSyncResponse>, blockchain: &Arc<Mutex<Blockchain>>) {
        let blocks = get_blocks_range(blockchain, request.start_index, request.end_index);
        
        let response = if blocks.is_empty() {
            BlockSyncResponse {
                blocks: vec![],
                success: false,
                error_message: Some("Requested blocks not found".to_string()),
            }
        } else {
            BlockSyncResponse {
                blocks,
                success: true,
                error_message: None,
            }
        };
        
        if let Err(e) = self.request_response.send_response(channel, response) {
            println!("Failed to send block response: {:?}", e);
        }
    }

    pub fn request_missing_blocks(&mut self, _peer_id: PeerId, missing_blocks: Vec<u64>) -> Result<(), Box<dyn Error>> {
        let topic = Topic::new("block-requests");
        let request = BlockRequest {
            start_index: *missing_blocks.first().unwrap(),
            end_index: *missing_blocks.last().unwrap(),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let message = BlockMessage::BlockRequest(request);
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Requested missing blocks: {:?}", missing_blocks);
        Ok(())
    }

    pub fn handle_block_request(&mut self, request: BlockRequest, blockchain: &Arc<Mutex<Blockchain>>) -> Result<(), Box<dyn Error>> {
        let topic = Topic::new("block-responses");
        let blocks = get_blocks_range(blockchain, request.start_index, request.end_index);
        let response = BlockResponse {
            blocks,
            request_id: request.request_id.clone(),
        };
        let message = BlockMessage::BlockResponse(response);
        let data = bincode::serialize(&message)?;
        self.gossipsub.publish(topic, data)?;
        println!("Responded to block request: {:?}", request);
        Ok(())
    }

    // Kademlia DHT methods
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.kademlia.add_address(&peer_id, addr.clone());
        println!("Added bootstrap peer to Kademlia: {} at {}", peer_id, addr);
    }

    pub fn bootstrap_dht(&mut self) -> Result<QueryId, Box<dyn Error>> {
        match self.kademlia.bootstrap() {
            Ok(query_id) => {
                println!("Started Kademlia DHT bootstrap with query ID: {:?}", query_id);
                Ok(query_id)
            }
            Err(e) => {
                println!("Failed to bootstrap Kademlia DHT: {:?}", e);
                Err(Box::new(e))
            }
        }
    }

    pub fn discover_peers(&mut self, target_peer_id: PeerId) -> QueryId {
        let query_id = self.kademlia.get_closest_peers(target_peer_id);
        println!("Started peer discovery for target: {} with query ID: {:?}", target_peer_id, query_id);
        query_id
    }

    pub fn store_record(&mut self, key: String, value: Vec<u8>) -> Result<QueryId, Box<dyn Error>> {
        let record = Record {
            key: Key::new(&key),
            value,
            publisher: None,
            expires: None,
        };
        match self.kademlia.put_record(record, Quorum::One) {
            Ok(query_id) => {
                println!("Started storing record with key: {} and query ID: {:?}", key, query_id);
                Ok(query_id)
            }
            Err(e) => {
                println!("Failed to store record: {:?}", e);
                Err(Box::new(e))
            }
        }
    }

    pub fn get_record(&mut self, key: String) -> QueryId {
        let query_id = self.kademlia.get_record(Key::new(&key));
        println!("Started retrieving record with key: {} and query ID: {:?}", key, query_id);
        query_id
    }

    pub fn get_routing_table_info(&mut self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        // Get peers from the routing table
        let mut peers = Vec::new();
        for bucket in self.kademlia.kbuckets() {
            for entry in bucket.iter() {
                let peer_id = entry.node.key.preimage().clone();
                let addresses = entry.node.value.clone().into_vec();
                peers.push((peer_id, addresses));
            }
        }
        peers
    }

    pub fn get_dht_peer_count(&mut self) -> usize {
        let mut count = 0;
        for bucket in self.kademlia.kbuckets() {
            count += bucket.num_entries();
        }
        count
    }
}

// Standalone blockchain helpers
pub fn get_blocks_range(blockchain: &Arc<Mutex<Blockchain>>, start_index: u64, end_index: u64) -> Vec<Block> {
    let blockchain = blockchain.lock().unwrap();
    blockchain.get_blocks_range(start_index, end_index)
}

pub fn add_block(blockchain: &Arc<Mutex<Blockchain>>, block: &Block) {
    let mut blockchain = blockchain.lock().unwrap();
    if let Err(e) = blockchain.try_add_block(block.clone()) {
        println!("Failed to add block: {}", e);
    }
}

pub fn validate_block(block: &Block) -> Result<(), String> {
    // Basic validation checks
    if block.index == 0 {
        // Genesis block validation
        if block.prev_hash != "0" {
            return Err("Genesis block must have prev_hash of '0'".to_string());
        }
    }

    // Check if hash is valid (simplified check)
    if block.hash.is_empty() {
        return Err("Block hash cannot be empty".to_string());
    }

    // Check timestamp (should not be too far in the future)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if block.timestamp > current_time + 300 { // 5 minutes tolerance
        return Err("Block timestamp is too far in the future".to_string());
    }

    println!("Block validation passed for index: {}", block.index);
    Ok(())
}

pub fn process_received_blocks(blockchain: &Arc<Mutex<Blockchain>>, blocks: Vec<Block>) -> Result<(), String> {
    for block in blocks {
        validate_block(&block)?;
        add_block(blockchain, &block);
        println!("Successfully processed block {}", block.index);
    }
    Ok(())
}

pub struct P2P {
    // Define peer-to-peer networking structures and logic here
}

impl P2P {
    pub fn new() -> Self {
        P2P {
            // Initialize P2P networking
        }
    }

    pub fn connect(&self, _peer: &str) {
        // TODO: implement peer connection logic using libp2p
        println!("Connecting to peer: {}", _peer);
    }

    pub fn start_network(&self) {
        // TODO: implement network startup logic
        println!("Starting P2P network...");
    }
}

pub fn build_swarm() -> anyhow::Result<Swarm<MyBehaviour>> {
    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());

    let noise_config = noise::Config::new(&id_keys).unwrap();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .boxed();

    let behaviour = MyBehaviour::new(&id_keys)?;
    
    // Add some bootstrap peers for Kademlia (these would typically be well-known nodes)
    // For testing, you can add specific bootstrap addresses if available
    // behaviour.add_bootstrap_peer(bootstrap_peer_id, bootstrap_addr);
    
    let mut swarm = SwarmBuilder::without_executor(transport, behaviour, local_peer_id).build();
    
    // Bootstrap the DHT after creating the swarm
    if let Err(e) = swarm.behaviour_mut().bootstrap_dht() {
        println!("Warning: Failed to bootstrap DHT: {:?}", e);
    }
    
    Ok(swarm)
}

pub async fn start_p2p() -> Result<(), Box<dyn Error>> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    println!("Local peer id: {:?}", peer_id);

    let noise_config = noise::Config::new(&keypair).unwrap();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .boxed();

    let behaviour = MyBehaviour::new(&keypair)?;
    let mut swarm = SwarmBuilder::without_executor(transport, behaviour, peer_id).build();

    // Listen on all interfaces, use a configurable port (e.g., from CLI args or config)
    // For demonstration, use 4001. Replace with your actual port variable if needed.
    Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/4001".parse()?)?;

    println!("Listening for peers...");
    
    // Bootstrap the DHT
    if let Err(e) = swarm.behaviour_mut().bootstrap_dht() {
        println!("Warning: Failed to bootstrap DHT: {:?}", e);
    }

    // Create a single shared blockchain instance
    let storage = Storage::new("chain_db");
    let blockchain = Arc::new(Mutex::new(Blockchain::new(storage)));
    
    // Set up periodic DHT maintenance
    let mut dht_maintenance_interval = tokio::time::interval(Duration::from_secs(60)); // Every minute
    let mut peer_discovery_interval = tokio::time::interval(Duration::from_secs(30)); // Every 30 seconds
    
    // Generate a random peer ID for peer discovery
    let random_peer_id = PeerId::random();

    loop {
        tokio::select! {
            event = swarm.next() => {
                if let Some(event) = event {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            match event {
                                MyBehaviourEvent::Mdns(MdnsEvent::Discovered(peers)) => {
                        for (peer_id, _) in peers {
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            println!("mDNS discovered peer: {:?}", peer_id);
                            // Send chain summary when discovering a new peer
                            if let Err(e) = swarm.behaviour_mut().send_chain_summary(&blockchain) {
                                println!("Failed to send chain summary to new peer: {:?}", e);
                            }
                        }
                    }
                    MyBehaviourEvent::Mdns(MdnsEvent::Expired(peers)) => {
                        for (peer_id, _) in peers {
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            println!("mDNS expired peer: {:?}", peer_id);
                        }
                    }
                    MyBehaviourEvent::Kademlia(event) => {
                        match event {
                            KademliaEvent::RoutingUpdated { peer, .. } => {
                                println!("Kademlia routing updated: peer {:?} added to routing table", peer);
                                // Add peer to gossipsub for message propagation
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                            }
                            KademliaEvent::OutboundQueryProgressed { id, result, .. } => {
                                match result {
                                    libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                        println!("Kademlia peer discovery completed for query {:?}, found {} peers", id, ok.peers.len());
                                        for peer_id in ok.peers {
                                            println!("Discovered peer via Kademlia: {}", peer_id);
                                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                        }
                                    }
                                    libp2p::kad::QueryResult::GetRecord(Ok(ok)) => {
                                        match ok {
                                            GetRecordOk::FoundRecord(PeerRecord { record, .. }) => {
                                                println!("Retrieved record: key={:?}, value_len={}",
                                                    String::from_utf8_lossy(&record.key.to_vec()), record.value.len());
                                            }
                                            GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {}
                                        }
                                    }
                                    libp2p::kad::QueryResult::PutRecord(Ok(_)) => {
                                        println!("Kademlia put record completed for query {:?}", id);
                                    }
                                    libp2p::kad::QueryResult::Bootstrap(Ok(_)) => {
                                        println!("Kademlia bootstrap completed for query {:?}", id);
                                        // Print routing table status
                                        let peer_count = swarm.behaviour_mut().get_dht_peer_count();
                                        println!("DHT routing table now contains {} peers", peer_count);
                                    }
                                    _ => {
                                        println!("Kademlia query {:?} completed with result: {:?}", id, result);
                                    }
                                }
                            }
                            KademliaEvent::InboundRequest { request } => {
                                println!("Received Kademlia inbound request: {:?}", request);
                            }
                            _ => {
                                println!("Other Kademlia event: {:?}", event);
                            }
                        }
                    }
                    MyBehaviourEvent::Gossipsub(GossipsubEvent::Message { 
                        propagation_source, 
                        message_id, 
                        message 
                    }) => {
                        // Handle different message types
                        if let Ok(block_message) = bincode::deserialize::<BlockMessage>(&message.data) {
                            match block_message {
                                BlockMessage::BlockHeader(block_header) => {
                                    println!("Received block header from {:?} id={} block_header={:?}", 
                                        propagation_source, message_id, block_header);
                                },
                                BlockMessage::FullBlock(block) => {
                                    println!("Received full block from {:?} id={} block_index={}", 
                                        propagation_source, message_id, block.index);
                                    
                                    // Validate the block
                                    if let Err(e) = validate_block(&block) {
                                        println!("Block validation failed: {}", e);
                                    } else {
                                        println!("Block validation passed");
                                    }
                                },
                                BlockMessage::BlockAnnouncement(announcement) => {
                                    println!("Received block announcement from {:?} block_index={} peer_height={}", 
                                        propagation_source, announcement.block_header.index, announcement.peer_height);
                                },
                                BlockMessage::BlockRequest(request) => {
                                    println!("Received block request from {:?} for blocks {}-{}", 
                                        propagation_source, request.start_index, request.end_index);
                                },
                                BlockMessage::BlockResponse(response) => {
                                    println!("Received block response from {:?} with {} blocks", 
                                        propagation_source, response.blocks.len());
                                },
                                BlockMessage::ChainSummary(summary) => {
                                    println!("Received chain summary from {:?}: index={}, hash={}, length={}", 
                                        propagation_source, summary.latest_index, summary.latest_hash, summary.chain_length);
                                    
                                    // Handle chain summary
                                    if let Err(e) = handle_chain_summary(&summary, &blockchain, &mut swarm, propagation_source) {
                                        println!("Failed to handle chain summary: {:?}", e);
                                    }
                                },
                                BlockMessage::ChainData(chain_data) => {
                                    println!("Received chain data from {:?} with {} blocks", 
                                        propagation_source, chain_data.len());
                                    
                                    // Handle chain data
                                    if let Err(e) = handle_chain_data(chain_data, &blockchain) {
                                        println!("Failed to handle chain data: {:?}", e);
                                    }
                                },
                                _ => {}
                            }
                        } else {
                            println!("Failed to deserialize message from {:?}", propagation_source);
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on: {:?}", address),
            _ => {}
                    }
                }
            },
            _ = dht_maintenance_interval.tick() => {
                // Periodic DHT maintenance
                let peer_count = swarm.behaviour_mut().get_dht_peer_count();
                println!("DHT Status: {} peers in routing table", peer_count);
                
                // Re-bootstrap if we have few peers
                if peer_count < 3 {
                    if let Err(e) = swarm.behaviour_mut().bootstrap_dht() {
                        println!("Failed to re-bootstrap DHT: {:?}", e);
                    } else {
                        println!("Re-bootstrapping DHT due to low peer count");
                    }
                }
            },
            _ = peer_discovery_interval.tick() => {
                // Periodic peer discovery
                swarm.behaviour_mut().discover_peers(random_peer_id);
                println!("Started periodic peer discovery for random peer: {}", random_peer_id);
            }
        }
    }

    // Ok(()) // This is unreachable
}

// Enhanced P2P with comprehensive block sync
pub async fn start_p2p_with_sync(mut swarm: Swarm<MyBehaviour>, blockchain: Arc<Mutex<Blockchain>>) -> Result<(), Box<dyn Error>> {
    let mut sync_state = BlockSyncState::new();
    
    // Update local height from blockchain
    {
        let bc = blockchain.lock().unwrap();
        sync_state.local_height = bc.latest().index;
        println!("Initialized sync state with local height: {}", sync_state.local_height);
    }

    // Send initial chain summary to bootstrap sync
    let mut chain_summary_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    
    loop {
        tokio::select! {
            _ = chain_summary_interval.tick() => {
                // Periodically broadcast chain summary to all peers
                if let Err(e) = swarm.behaviour_mut().send_chain_summary(&blockchain) {
                    println!("Failed to broadcast periodic chain summary: {:?}", e);
                } else {
                    println!("Broadcasted periodic chain summary");
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(MdnsEvent::Discovered(peers))) => {
                        for (peer_id, _multiaddr) in peers {
                            println!("mDNS discovered peer: {:?}", peer_id);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            
                            // Immediately send chain summary to new peer
                            if let Err(e) = swarm.behaviour_mut().send_chain_summary(&blockchain) {
                                println!("Failed to send chain summary to discovered peer: {:?}", e);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(MdnsEvent::Expired(peers))) => {
                        for (peer_id, _multiaddr) in peers {
                            println!("mDNS peer expired: {:?}", peer_id);
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(event)) => {
                        match event {
                            KademliaEvent::RoutingUpdated { peer, .. } => {
                                println!("Kademlia routing updated: peer {:?} added to routing table", peer);
                                // Add peer to gossipsub for message propagation
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                            }
                            KademliaEvent::OutboundQueryProgressed { id, result, .. } => {
                                match result {
                                    libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                        println!("Kademlia peer discovery completed for query {:?}, found {} peers", id, ok.peers.len());
                                        for peer_id in ok.peers {
                                            println!("Discovered peer via Kademlia: {}", peer_id);
                                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                        }
                                    }
                                    libp2p::kad::QueryResult::GetRecord(Ok(ok)) => {
                                        match ok {
                                            GetRecordOk::FoundRecord(PeerRecord { record, .. }) => {
                                                println!("Retrieved record: key={:?}, value_len={}",
                                                    String::from_utf8_lossy(&record.key.to_vec()), record.value.len());
                                            }
                                            GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {}
                                        }
                                    }
                                    libp2p::kad::QueryResult::PutRecord(Ok(_)) => {
                                        println!("Kademlia put record completed for query {:?}", id);
                                    }
                                    libp2p::kad::QueryResult::Bootstrap(Ok(_)) => {
                                        println!("Kademlia bootstrap completed for query {:?}", id);
                                        // Print routing table status
                                        let peer_count = swarm.behaviour_mut().get_dht_peer_count();
                                        println!("DHT routing table now contains {} peers", peer_count);
                                    }
                                    _ => {
                                        println!("Kademlia query {:?} completed with result: {:?}", id, result);
                                    }
                                }
                            }
                            KademliaEvent::InboundRequest { request } => {
                                println!("Received Kademlia inbound request: {:?}", request);
                            }
                            _ => {
                                println!("Other Kademlia event: {:?}", event);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(GossipsubEvent::Message { 
                        propagation_source, message_id, message 
                    })) => {
                        if let Ok(block_message) = bincode::deserialize::<BlockMessage>(&message.data) {
                            match block_message {
                                BlockMessage::BlockAnnouncement(announcement) => {
                                    sync_state.update_peer_height(propagation_source, announcement.peer_height);
                                    println!("Peer {} height: {}, Local height: {}", 
                                        propagation_source, announcement.peer_height, sync_state.local_height);

                                    if sync_state.needs_sync() && !sync_state.sync_in_progress {
                                        let missing_blocks = sync_state.get_missing_blocks();
                                        if !missing_blocks.is_empty() {
                                            let start = *missing_blocks.first().unwrap();
                                            let end = *missing_blocks.last().unwrap();
                                            let request_id = swarm.behaviour_mut().request_blocks(
                                                propagation_source, start, end
                                            );
                                            sync_state.pending_requests.insert(request_id, BlockSyncRequest {
                                                start_index: start,
                                                end_index: end,
                                            });
                                            sync_state.sync_in_progress = true;
                                        }
                                    }
                                }
                                BlockMessage::BlockHeader(block_header) => {
                                    println!("Received block header from {:?} id={} block_header={:?}", 
                                        propagation_source, message_id, block_header);

                                    let blockchain = blockchain.lock().unwrap();
                                    let local_block_hash = blockchain.get_block_hash(block_header.index);

                                    if let Some(local_hash) = local_block_hash {
                                        if local_hash != block_header.hash {
                                            println!("Hash mismatch detected at index {}: local_hash={}, remote_hash={}", 
                                                block_header.index, local_hash, block_header.hash);

                                            let request_id = swarm.behaviour_mut().request_blocks(
                                                propagation_source, block_header.index, block_header.index
                                            );
                                            sync_state.pending_requests.insert(request_id, BlockSyncRequest {
                                                start_index: block_header.index,
                                                end_index: block_header.index,
                                            });
                                        }
                                    }
                                }
                                BlockMessage::ChainSummary(summary) => {
                                    println!("Received chain summary from {:?}: index={}, hash={}, length={}", 
                                        propagation_source, summary.latest_index, summary.latest_hash, summary.chain_length);
                                    if let Err(e) = handle_chain_summary(&summary, &blockchain, &mut swarm, propagation_source) {
                                        println!("Failed to handle chain summary: {:?}", e);
                                    }
                                }
                                BlockMessage::ChainRequest => {
                                    println!("Received chain request from {:?}", propagation_source);
                                    if let Err(e) = swarm.behaviour_mut().send_full_chain(&blockchain) {
                                        println!("Failed to send full chain: {:?}", e);
                                    }
                                }
                                BlockMessage::ChainData(chain_data) => {
                                    println!("Received chain data from {:?} with {} blocks", propagation_source, chain_data.len());
                                    if let Err(e) = handle_chain_data(chain_data, &blockchain) {
                                        println!("Failed to handle chain data: {:?}", e);
                                    }
                                    
                                    // Update sync state after processing chain data
                                    let bc = blockchain.lock().unwrap();
                                    sync_state.local_height = bc.latest().index;
                                    sync_state.sync_in_progress = false;
                                }
                                BlockMessage::FullBlock(block) => {
                                    println!("Received full block from {:?} index={}", propagation_source, block.index);
                                    if let Err(e) = validate_block(&block) {
                                        println!("Block validation failed: {}", e);
                                    } else {
                                        add_block(&blockchain, &block);
                                        // Update local height
                                        let bc = blockchain.lock().unwrap();
                                        sync_state.local_height = bc.latest().index;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::RequestResponse(RequestResponseEvent::Message { 
                        peer, message 
                    })) => {
                        match message {
                            libp2p::request_response::Message::Response { response, .. } => {
                                println!("Received block response from {:?} with {} blocks", peer, response.blocks.len());

                                if response.success {
                                    for block in response.blocks {
                                        add_block(&blockchain, &block);
                                    }
                                    // Update local height
                                    let bc = blockchain.lock().unwrap();
                                    sync_state.local_height = bc.latest().index;
                                } else {
                                    println!("Block response failed: {:?}", response.error_message);
                                }

                                sync_state.sync_in_progress = false;
                            }
                            libp2p::request_response::Message::Request { request, channel, .. } => {
                                println!("Received block request from {:?} for blocks {}-{}", peer, request.start_index, request.end_index);
                                swarm.behaviour_mut().respond_to_block_request(request, channel, &blockchain);
                            }
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Listening on: {:?}", address);
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(GossipsubEvent::Subscribed { peer_id, topic })) => {
                        println!("Peer {:?} subscribed to topic: {:?}", peer_id, topic);
                        // Send chain summary when a peer subscribes to our topics
                        if let Err(e) = swarm.behaviour_mut().send_chain_summary(&blockchain) {
                            println!("Failed to send chain summary to subscribed peer: {:?}", e);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

// Standalone blockchain helpers
pub fn validate_chain(chain: &[Block]) -> bool {
    if chain.is_empty() {
        return false;
    }
    
    // Check genesis block
    let genesis = &chain[0];
    if genesis.index != 0 || genesis.prev_hash != "0" {
        return false;
    }
    
    // Validate each subsequent block
    for i in 1..chain.len() {
        let current = &chain[i];
        let previous = &chain[i - 1];
        
        if current.index != previous.index + 1 {
            return false;
        }
        
        if current.prev_hash != previous.hash {
            return false;
        }
        
        if let Err(_) = validate_block(current) {
            return false;
        }
    }
    
    true
}

pub fn handle_chain_summary(
    summary: &ChainSummary, 
    blockchain: &Arc<Mutex<Blockchain>>, 
    swarm: &mut Swarm<MyBehaviour>,
    propagation_source: libp2p::PeerId
) -> Result<(), Box<dyn Error>> {
    let local_blockchain = blockchain.lock().unwrap();
    let (local_index, local_hash, local_length) = local_blockchain.get_chain_summary();
    
    println!("Comparing chains - Local: index={}, hash={}, length={} | Remote: index={}, hash={}, length={}", 
        local_index, local_hash, local_length,
        summary.latest_index, summary.latest_hash, summary.chain_length);
    
    let needs_sync = local_blockchain.needs_sync(summary.latest_index, &summary.latest_hash);
    
    if needs_sync {
        if summary.chain_length > local_length as u64 {
            // Remote chain is longer - request full chain
            println!("Remote chain is longer, requesting full chain from peer");
            drop(local_blockchain); // Release lock before calling swarm methods
            swarm.behaviour_mut().request_full_chain(propagation_source)?;
        } else if summary.chain_length == local_length as u64 && 
                  summary.latest_index == local_index &&
                  summary.latest_hash != local_hash {
            // Same length but different hash - conflict detected
            println!("Chain conflict detected at same height - requesting full chain for resolution");
            drop(local_blockchain); // Release lock before calling swarm methods
            swarm.behaviour_mut().request_full_chain(propagation_source)?;
        }
    } else if summary.chain_length < local_length as u64 {
        // Local chain is longer - send our chain summary back
        println!("Local chain is longer, sending our chain data");
        drop(local_blockchain); // Release lock before calling swarm methods
        swarm.behaviour_mut().send_full_chain(blockchain)?;
    } else {
        println!("Chains are in sync");
    }
    
    Ok(())
}

pub fn handle_chain_data(
    chain_data: Vec<Block>, 
    blockchain: &Arc<Mutex<Blockchain>>
) -> Result<(), Box<dyn Error>> {
    println!("Received chain data with {} blocks", chain_data.len());
    
    let mut local_blockchain = blockchain.lock().unwrap();
    
    match local_blockchain.resolve_chain_conflict(chain_data) {
        Ok(true) => {
            println!("Chain was replaced with received chain");
        }
        Ok(false) => {
            println!("Kept local chain (it was better or equal)");
        }
        Err(e) => {
            println!("Failed to resolve chain conflict: {}", e);
            return Err(e.into());
        }
    }
    
    Ok(())
}

// Simple P2P Network implementation for AdminNode and PublicNode

#[derive(Clone)]
pub struct P2PNetwork {
    port: u16,
    swarm: Arc<Mutex<Swarm<MyBehaviour>>>,
}

impl P2PNetwork {

    /// Subscribe to a gossipsub topic by name. Used for governance_events integration.
    pub fn subscribe_topic(&self, topic_name: &str) {
        use libp2p::gossipsub::IdentTopic as Topic;
        let topic = Topic::new(topic_name);
        let mut swarm = self.swarm.lock().unwrap();
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
            println!("[WARN] Failed to subscribe to {} topic: {:?}", topic_name, e);
        } else {
            println!("[INFO] Subscribed to {} topic", topic_name);
        }
    }
    pub async fn new(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let swarm = build_swarm()?;
        let swarm = Arc::new(Mutex::new(swarm));
        
        Ok(P2PNetwork { port, swarm })
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("P2P network started on port {}", self.port);
        
        let mut swarm = self.swarm.lock().unwrap();
        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", self.port);
        Swarm::listen_on(&mut *swarm, listen_addr.parse()?)?;
        
        // Subscribe to common topics to ensure proper discovery
        let admin_topic = Topic::new("admin_actions");
        let chain_topic = Topic::new("chain_sync");
        let receipts_topic = Topic::new("admin_receipts");
        let general_topic = Topic::new("general");
        
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&admin_topic) {
            println!("Warning: Failed to subscribe to admin_actions topic: {:?}", e);
        }
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&chain_topic) {
            println!("Warning: Failed to subscribe to chain_sync topic: {:?}", e);
        }
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&receipts_topic) {
            println!("Warning: Failed to subscribe to admin_receipts topic: {:?}", e);
        }
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&general_topic) {
            println!("Warning: Failed to subscribe to general topic: {:?}", e);
        }
        
        println!("P2P network subscribed to discovery topics");
        
        // Release the lock before spawning the event loop
        drop(swarm);
        
        // Start the event processing loop
        let swarm_clone = self.swarm.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            
            loop {
                interval.tick().await;
                
                // Try to process events without blocking
                let events_to_process = {
                    let mut swarm = match swarm_clone.try_lock() {
                        Ok(guard) => guard,
                        Err(_) => {
                            // Lock is busy, skip this iteration
                            continue;
                        }
                    };
                    
                    let mut events = Vec::new();
                    // Poll for multiple events to process them in batch
                    use std::task::{Context, Poll};
                    use std::pin::Pin;
                    use futures::task::noop_waker;
                    
                    let waker = noop_waker();
                    let mut cx = Context::from_waker(&waker);
                    
                    for _ in 0..10 {
                        match Pin::new(&mut *swarm).poll_next(&mut cx) {
                            Poll::Ready(Some(event)) => events.push(event),
                            Poll::Ready(None) => break,
                            Poll::Pending => break,
                        }
                    }
                    events
                };

                // Process events outside the lock
                for event in events_to_process {
                    if let Ok(mut swarm) = swarm_clone.try_lock() {
                        match event {
                            SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(MdnsEvent::Discovered(peers))) => {
                                for (peer_id, _multiaddr) in peers {
                                    println!("P2P: mDNS discovered peer: {:?}", peer_id);
                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                }
                            }
                            SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(MdnsEvent::Expired(peers))) => {
                                for (peer_id, _multiaddr) in peers {
                                    println!("P2P: mDNS peer expired: {:?}", peer_id);
                                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                }
                            }
                            SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(event)) => {
                                match event {
                                    KademliaEvent::RoutingUpdated { peer, .. } => {
                                        println!("Kademlia routing updated: peer {:?} added to routing table", peer);
                                        // Add peer to gossipsub for message propagation
                                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                                    }
                                    KademliaEvent::OutboundQueryProgressed { id, result, .. } => {
                                        match result {
                                            libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                                println!("Kademlia peer discovery completed for query {:?}, found {} peers", id, ok.peers.len());
                                                for peer_id in ok.peers {
                                                    println!("Discovered peer via Kademlia: {}", peer_id);
                                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                                }
                                            }
                                            libp2p::kad::QueryResult::GetRecord(Ok(ok)) => {
                                                match ok {
                                                    GetRecordOk::FoundRecord(PeerRecord { record, .. }) => {
                                                        println!("Retrieved record: key={:?}, value_len={}",
                                                            String::from_utf8_lossy(&record.key.to_vec()), record.value.len());
                                                    }
                                                    GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {}
                                                }
                                            }
                                            libp2p::kad::QueryResult::PutRecord(Ok(_)) => {
                                                println!("Kademlia put record completed for query {:?}", id);
                                            }
                                            libp2p::kad::QueryResult::Bootstrap(Ok(_)) => {
                                                println!("Kademlia bootstrap completed for query {:?}", id);
                                                // Print routing table status
                                                let peer_count = swarm.behaviour_mut().get_dht_peer_count();
                                                println!("DHT routing table now contains {} peers", peer_count);
                                            }
                                            _ => {
                                                println!("Kademlia query {:?} completed with result: {:?}", id, result);
                                            }
                                        }
                                    }
                                    KademliaEvent::InboundRequest { request } => {
                                        println!("Received Kademlia inbound request: {:?}", request);
                                    }
                                    _ => {
                                        println!("Other Kademlia event: {:?}", event);
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(GossipsubEvent::Message {
                                propagation_source, message, ..
                            })) => {
                                // Handle message processing here if needed
                                let _ = message; // Suppress unused warning
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                println!("P2P: Listening on: {:?}", address);
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                println!("P2P: Connection established with peer: {:?}", peer_id);
                            }
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                println!("P2P: Connection closed with peer: {:?}", peer_id);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    pub async fn broadcast(&self, message: Message) -> Result<(), Box<dyn std::error::Error>> {
        let topic_name = match message.message_type.as_str() {
            "admin_action" => "admin_actions",
            "chain_summary" => "chain_sync",
            "admin_event_receipt" => "admin_receipts",
            _ => "general",
        };

        let topic = Topic::new(topic_name);
        let serialized_message = message.to_json();
        
        let mut swarm = self.swarm.lock().unwrap();
        match swarm.behaviour_mut().gossipsub.publish(topic, serialized_message.as_bytes()) {
            Ok(_) => {
                println!("P2P: Published message on topic '{}': {}", topic_name, serialized_message);
                Ok(())
            }
            Err(libp2p::gossipsub::PublishError::InsufficientPeers) => {
                println!("P2P: No peers available to broadcast message on topic '{}' (this is normal when nodes are starting)", topic_name);
                Ok(()) // Don't treat this as a fatal error
            }
            Err(e) => {
                println!("P2P: Failed to publish message on topic '{}': {:?}", topic_name, e);
                Err(Box::new(e))
            }
        }
    }
    
    pub async fn listen<F>(&self, message_type: &str, handler: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(&str) + Send + 'static + Clone,
    {
        let topic_name = match message_type {
            "admin_action" => "admin_actions",
            "chain_summary" => "chain_sync",
            "admin_event_receipt" => "admin_receipts",
            _ => "general",
        };

        let topic = Topic::new(topic_name);
        
        // Subscribe to the topic
        {
            let mut swarm = self.swarm.lock().unwrap();
            swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        }

        println!("P2P: Subscribed to topic '{}'", topic_name);

        // Use a simpler approach - just check for messages periodically
        let swarm_clone = Arc::clone(&self.swarm);
        let topic_name = topic_name.to_string();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
            
            loop {
                interval.tick().await;
                
                // Try to get events without blocking
                let mut events_to_process = Vec::new();
                
                // Quickly grab events and release the lock
                {
                    let mut swarm = match swarm_clone.try_lock() {
                        Ok(guard) => guard,
                        Err(_) => {
                            // Lock is busy, skip this iteration
                            continue;
                        }
                    };
                    
                    // Poll for events without blocking
                    use std::task::{Context, Poll};
                    use std::pin::Pin;
                    use futures::task::noop_waker;
                    
                    let waker = noop_waker();
                    let mut cx = Context::from_waker(&waker);
                    
                    // Try to get a few events
                    for _ in 0..5 {
                        match Pin::new(&mut *swarm).poll_next(&mut cx) {
                            Poll::Ready(Some(event)) => {
                                events_to_process.push(event);
                            }
                            Poll::Ready(None) => break, // Stream ended
                            Poll::Pending => break, // No more events available right now
                        }
                    }
                }
                
                // Process events without holding the lock
                for event in events_to_process {
                    match event {
                        SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(GossipsubEvent::Message { 
                            message, .. 
                        })) => {
                            let received_message = String::from_utf8_lossy(&message.data);
                            
                            if let Some(parsed_message) = Message::from_json(&received_message) {
                                let expected_topic = match parsed_message.message_type.as_str() {
                                    "admin_action" => "admin_actions",
                                    "chain_summary" => "chain_sync",
                                    "admin_event_receipt" => "admin_receipts",
                                    _ => "general",
                                };
                                
                                if expected_topic == topic_name {
                                    println!("P2P: Received message on topic '{}': {}", topic_name, received_message);
                                    handler(&received_message);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(MdnsEvent::Discovered(peers))) => {
                            if let Ok(mut swarm) = swarm_clone.try_lock() {
                                for (peer_id, _) in peers {
                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                    println!("P2P: Discovered peer: {:?}", peer_id);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(MdnsEvent::Expired(peers))) => {
                            if let Ok(mut swarm) = swarm_clone.try_lock() {
                                for (peer_id, _) in peers {
                                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                    println!("P2P: Peer expired: {:?}", peer_id);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(event)) => {
                            if let Ok(mut swarm) = swarm_clone.try_lock() {
                                match event {
                                    KademliaEvent::RoutingUpdated { peer, .. } => {
                                        println!("Kademlia routing updated: peer {:?} added to routing table", peer);
                                        // Add peer to gossipsub for message propagation
                                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                                    }
                                    KademliaEvent::OutboundQueryProgressed { id, result, .. } => {
                                        match result {
                                            libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                                println!("Kademlia peer discovery completed for query {:?}, found {} peers", id, ok.peers.len());
                                                for peer_id in ok.peers {
                                                    println!("Discovered peer via Kademlia: {}", peer_id);
                                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                                }
                                            }
                                            libp2p::kad::QueryResult::GetRecord(Ok(ok)) => {
                                                match ok {
                                                    GetRecordOk::FoundRecord(PeerRecord { record, .. }) => {
                                                        println!("Retrieved record: key={:?}, value_len={}",
                                                            String::from_utf8_lossy(&record.key.to_vec()), record.value.len());
                                                    }
                                                    GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {}
                                                }
                                            }
                                            libp2p::kad::QueryResult::PutRecord(Ok(_)) => {
                                                println!("Kademlia put record completed for query {:?}", id);
                                            }
                                            libp2p::kad::QueryResult::Bootstrap(Ok(_)) => {
                                                println!("Kademlia bootstrap completed for query {:?}", id);
                                                // Print routing table status
                                                let peer_count = swarm.behaviour_mut().get_dht_peer_count();
                                                println!("DHT routing table now contains {} peers", peer_count);
                                            }
                                            _ => {
                                                println!("Kademlia query {:?} completed with result: {:?}", id, result);
                                            }
                                        }
                                    }
                                    KademliaEvent::InboundRequest { request } => {
                                        println!("Received Kademlia inbound request: {:?}", request);
                                    }
                                    _ => {
                                        println!("Other Kademlia event: {:?}", event);
                                    }
                                }
                            }
                        }
                        _ => {} // Handle all other SwarmEvent variants
                    }
                }
            }
        });
        
        Ok(())
    }

    // Connect to a peer by address
    pub async fn connect_to_peer(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut swarm = self.swarm.lock().unwrap();
        let address: Multiaddr = addr.parse()?;
        swarm.dial(address)?;
        Ok(())
    }

    // Get count of peers in the DHT routing table
    pub async fn get_peer_count(&self) -> usize {
       let mut swarm = self.swarm.lock().unwrap();
       swarm.behaviour_mut().get_dht_peer_count()
    }
}
