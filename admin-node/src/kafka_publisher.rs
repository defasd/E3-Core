use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use serde_json;
use std::time::Duration;

// Admin event structure that matches PublicTx enum
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum AdminEvent {
    AdminMint { to: String, amount: u64, admin_block_hash: String },
    AdminBurn { from: String, amount: u64, admin_block_hash: String },
    AdminProofOfReserve { details: String, admin_block_hash: String },
}

pub struct AdminKafkaPublisher {
    producer: FutureProducer,
    topic: String,
}

impl AdminKafkaPublisher {
    pub fn new(bootstrap_servers: &str, topic: &str) -> Result<Self, rdkafka::error::KafkaError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", bootstrap_servers)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.messages", "10000")
            .set("queue.buffering.max.kbytes", "1048576")
            .set("batch.num.messages", "1000")
            .create()?;

        Ok(AdminKafkaPublisher {
            producer,
            topic: topic.to_string(),
        })
    }

    pub async fn publish_mint_event(&self, to: String, amount: u64, admin_block_hash: String) -> Result<(), Box<dyn std::error::Error>> {
        let event = AdminEvent::AdminMint { to, amount, admin_block_hash };
        self.publish_event(&event, "mint").await
    }

    pub async fn publish_burn_event(&self, from: String, amount: u64, admin_block_hash: String) -> Result<(), Box<dyn std::error::Error>> {
        let event = AdminEvent::AdminBurn { from, amount, admin_block_hash };
        self.publish_event(&event, "burn").await
    }

    pub async fn publish_proof_of_reserve_event(&self, details: String, admin_block_hash: String) -> Result<(), Box<dyn std::error::Error>> {
        let event = AdminEvent::AdminProofOfReserve { details, admin_block_hash };
        self.publish_event(&event, "proof-of-reserve").await
    }

    async fn publish_event(&self, event: &AdminEvent, event_type: &str) -> Result<(), Box<dyn std::error::Error>> {
        let event_json = serde_json::to_string(event)?;
        let key = format!("admin-{}", event_type);
        
        let record = FutureRecord::to(&self.topic)
            .payload(&event_json)
            .key(&key);

        match self.producer.send(record, Duration::from_secs(0)).await {
            Ok(_) => {
                println!("Admin {} event published to Kafka: {:?}", event_type, event);
                Ok(())
            }
            Err((kafka_error, _)) => {
                eprintln!("Failed to publish admin {} event to Kafka: {:?}", event_type, kafka_error);
                Err(Box::new(kafka_error))
            }
        }
    }
}
