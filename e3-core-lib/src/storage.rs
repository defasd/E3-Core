use rocksdb::{Options, DB};

pub struct Storage {
    db: DB,
}

impl Storage {
    pub fn new(path: &str) -> Self {
        let db = open_db(path).expect("Failed to open DB");
        Self { db }
    }

    pub fn save_data(&self, key: &str, value: &str) -> Result<(), rocksdb::Error> {
        self.db.put(key, value.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    pub fn get_data(&self, key: &str) -> Option<String> {
        self.db.get(key).ok().flatten()
            .and_then(|ivec| String::from_utf8(ivec.to_vec()).ok())
    }
}

pub fn open_db(path: &str) -> Result<DB, rocksdb::Error> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let cfs = vec!["blocks", "transactions", "metadata"];
    DB::open_cf(&opts, path, cfs)
}

pub fn store_block(db: &DB, block_hash: &str, block_data: &[u8]) -> Result<(), rocksdb::Error> {
    let blocks_cf = db.cf_handle("blocks").unwrap();
    db.put_cf(blocks_cf, block_hash, block_data)
}

pub fn store_transaction(db: &DB, tx_hash: &str, tx_data: &[u8]) -> Result<(), rocksdb::Error> {
    let txs_cf = db.cf_handle("transactions").unwrap();
    db.put_cf(txs_cf, tx_hash, tx_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_get() {
        let storage = Storage::new("test_db");
        storage.save_data("foo", "bar").unwrap();
        let value = storage.get_data("foo").unwrap();
        assert_eq!(value, "bar");
    }
}
