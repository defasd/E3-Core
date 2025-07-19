use rdkafka::consumer::{StreamConsumer, Consumer};
use rdkafka::ClientConfig;
use rdkafka::Message;
use futures::StreamExt;
use serde_json;
use crate::consensus_pos::PublicTx;
use crate::public_node::PublicNode;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct KafkaConsumer {
    consumer: StreamConsumer,
    topic: String,
}

impl KafkaConsumer {
    pub fn new(bootstrap_servers: &str, group_id: &str, topic: &str) -> Result<Self, rdkafka::error::KafkaError> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", group_id)
            .set("bootstrap.servers", bootstrap_servers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .set("auto.offset.reset", "earliest")
            .create()?;

        consumer.subscribe(&[topic])?;

        Ok(KafkaConsumer {
            consumer,
            topic: topic.to_string(),
        })
    }

    pub async fn consume_admin_events(&self, public_node: Arc<Mutex<PublicNode>>) {
        println!("Starting Kafka consumer for topic: {}", self.topic);
        
        while let Some(message) = self.consumer.stream().next().await {
            match message {
                Ok(m) => {
                    if let Some(payload) = m.payload() {
                        match serde_json::from_slice::<PublicTx>(payload) {
                            Ok(tx) => {
                                let mut node = public_node.lock().await;
                                
                                // Process different types of admin events
                                match &tx {
                                    PublicTx::AdminMint { to, amount, admin_block_hash } => {
                                        println!("Kafka: Processing AdminMint - to: {}, amount: {}, block: {}", 
                                                to, amount, admin_block_hash);
                                        
                                        // Apply the mint directly to the consensus
                                        if let Err(e) = node.admin_mint(to.clone(), *amount, admin_block_hash.clone()).await {
                                            eprintln!("Failed to process admin mint event: {}", e);
                                        }
                                    }
                                    PublicTx::AdminBurn { from, amount, admin_block_hash } => {
                                        println!("Kafka: Processing AdminBurn - from: {}, amount: {}, block: {}", 
                                                from, amount, admin_block_hash);
                                        
                                        if let Err(e) = node.admin_burn(from.clone(), *amount, admin_block_hash.clone()).await {
                                            eprintln!("Failed to process admin burn event: {}", e);
                                        }
                                    }
                                    PublicTx::AdminProofOfReserve { details, admin_block_hash } => {
                                        println!("Kafka: Processing AdminProofOfReserve - details: {}, block: {}", 
                                                details, admin_block_hash);
                                        
                                        if let Err(e) = node.admin_proof_of_reserve(details.clone(), admin_block_hash.clone()).await {
                                            eprintln!("Failed to process admin proof of reserve event: {}", e);
                                        }
                                    }
                                    _ => {
                                        // Handle other transaction types if needed
                                        println!("Kafka: Received non-admin transaction: {:?}", tx);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to deserialize Kafka message: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Kafka consumer error: {:?}", e);
                }
            }
        }
    }
}
