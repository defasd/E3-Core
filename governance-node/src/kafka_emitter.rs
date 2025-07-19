use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use serde::Serialize;
use std::time::Duration;

pub struct KafkaEmitter {
    producer: FutureProducer,
    topic: String,
}

impl KafkaEmitter {
    pub fn new(brokers: &str, topic: &str) -> Self {
        let producer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .create()
            .expect("Producer creation error");
        KafkaEmitter {
            producer,
            topic: topic.to_string(),
        }
    }

    pub async fn emit_event<T: Serialize>(&self, event_type: &str, payload: &T) {
        let key = event_type;
        let value = serde_json::to_string(payload).unwrap();
        let _ = self.producer
            .send(
                FutureRecord::to(&self.topic)
                    .key(key)
                    .payload(&value),
                Duration::from_secs(0),
            )
            .await;
    }
}
