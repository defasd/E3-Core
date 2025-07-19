# E3 Wallet CLI

A simple command-line wallet for the Ellipe 3 (E3) Core DAO system. Supports Gold Units (GU), Standard Units (SU), optional DID, and mnemonic (recovery phrase) for backup and restore.

## Features
- Generate new wallet with Ed25519 keypair and 12-word mnemonic
- Import wallet from file or mnemonic
- Optional DID support
- View GU/SU balances
- Send tokens (stub; integrate with node API)

## Usage

```
cargo run -- <command> [args]
```

### Commands
- `new [did]` - Create a new wallet (optionally with DID)
- `import <wallet.json>` - Import wallet from file
- `import-mnemonic <mnemonic> [did]` - Import wallet from mnemonic
- `balance` - Show wallet balances
- `send <to_pubkey> <amount> <GU|SU>` - Send tokens (stub)

### Example
```
cargo run -- new
cargo run -- new did:example:1234
cargo run -- import wallet.json
cargo run -- import-mnemonic "word1 word2 ... word12" did:example:5678
cargo run -- balance
cargo run -- send <to_pubkey> 100 GU
```

## Security
- Keep your mnemonic phrase and wallet.json file safe!
- This CLI is for demonstration and development. For production, use secure key derivation and storage.

## Next Steps
- Integrate with E3 node HTTP API for real balance and send operations.
- Add encryption for wallet file.
