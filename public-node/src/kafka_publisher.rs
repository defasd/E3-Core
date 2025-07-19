use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use serde_json;
use crate::consensus_pos::PublicTx;
use std::time::Duration;

pub struct KafkaPublisher {
    producer: FutureProducer,
    topic: String,
}

impl KafkaPublisher {
    pub fn new(bootstrap_servers: &str, topic: &str) -> Result<Self, rdkafka::error::KafkaError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", bootstrap_servers)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.messages", "10000")
            .set("queue.buffering.max.kbytes", "1048576")
            .set("batch.num.messages", "1000")
            .create()?;

        Ok(KafkaPublisher {
            producer,
            topic: topic.to_string(),
        })
    }

    pub async fn publish_admin_event(&self, tx: &PublicTx) -> Result<(), Box<dyn std::error::Error>> {
        let event = serde_json::to_string(tx)?;
        
        let record = FutureRecord::to(&self.topic)
            .payload(&event)
            .key("admin-event");

        match self.producer.send(record, Duration::from_secs(0)).await {
            Ok(_) => {
                println!("Admin event published to Kafka: {:?}", tx);
                Ok(())
            }
            Err((kafka_error, _)) => {
                eprintln!("Failed to publish admin event to Kafka: {:?}", kafka_error);
                Err(Box::new(kafka_error))
            }
        }
    }

    pub async fn publish_transaction(&self, tx: &PublicTx) -> Result<(), Box<dyn std::error::Error>> {
        let event = serde_json::to_string(tx)?;
        
        let record = FutureRecord::to(&self.topic)
            .payload(&event)
            .key("transaction");

        match self.producer.send(record, Duration::from_secs(0)).await {
            Ok(_) => {
                println!("Transaction published to Kafka: {:?}", tx);
                Ok(())
            }
            Err((kafka_error, _)) => {
                eprintln!("Failed to publish transaction to Kafka: {:?}", kafka_error);
                Err(Box::new(kafka_error))
            }
        }
    }
}
