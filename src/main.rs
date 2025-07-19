use std::env;

mod node;
mod blockchain;
mod storage;
mod p2p;
mod block;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Booting E3-Core...");

    // Get node type, database path and port from command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <admin|public> <db_path> <port>", args[0]);
        return Ok(());
    }
    let node_type = &args[1];
    let _db_path = &args[2];
    let port = &args[3];
    let _port: u16 = port.parse().map_err(|_| {
        format!("Invalid port number: {}", port)
    })?;

    match node_type.as_str() {
        "admin" => {
            println!("Starting Admin Node...");
            println!("Use 'cargo run --bin admin-node -- <db_path> <port>' to run the admin node");
        },
        "public" => {
            println!("Starting Public Node...");
            println!("Use 'cargo run --bin public-node -- <db_path> <port>' to run the public node");
        },
        _ => {
            eprintln!("Unknown node type: {}. Use 'admin' or 'public'", node_type);
        }
    }
    Ok(())
}

// fn init_blockchain(storage: Storage) -> Blockchain {
//     let mut blockchain = Blockchain::new(storage);
//     // Genesis block is automatically created in Blockchain::new()
//     println!("Blockchain initialized with {} block(s)", blockchain.chain.len());
//     blockchain
// }