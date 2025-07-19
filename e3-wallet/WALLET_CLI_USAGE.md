# E3 Wallet CLI Usage Guide

## Overview
The E3 Wallet CLI is a secure, password-protected command-line wallet for the Ellipe 3 (E3) Core DAO system. It supports:
- Ed25519 key generation and mnemonic backup
- Multi-wallet management
- Password-encrypted wallet files
- GU/SU token balances
- Transaction history
- DID (Decentralized Identifier) management

Wallets are stored in the `wallets/` directory, each as an encrypted `.wallet` file. You "log in" by decrypting a wallet with its password.

---

## Commands

### Create a New Wallet
```
cargo run -p e3-wallet -- new <wallet_name>
```
- Prompts for a password (used to encrypt the wallet file)
- Prints your public key and mnemonic (save this phrase!)

### List All Wallets
```
cargo run -p e3-wallet -- list
```
- Shows all wallet names in the `wallets/` directory

### View (Login to) a Wallet
```
cargo run -p e3-wallet -- view <wallet_name>
```
- Prompts for the wallet password
- Prints wallet info: name, address, mnemonic, balances, DID

### Show Balances
```
cargo run -p e3-wallet -- balance [wallet_name]
```
- Prompts for the wallet password
- Shows GU and SU balances

### Show Transaction History
```
cargo run -p e3-wallet -- history <wallet_name>
```
- Prompts for the wallet password
- Prints all transactions for the wallet

### Show DID
```
cargo run -p e3-wallet -- did <wallet_name>
```
- Prompts for the wallet password
- Prints the wallet's DID (if set)

### Import Wallet from File
```
cargo run -p e3-wallet -- import <wallet.json> [wallet_name]
```
- Prompts for a password to encrypt the imported wallet

### Import Wallet from Mnemonic
```
cargo run -p e3-wallet -- import-mnemonic "<mnemonic phrase>" [wallet_name]
```
- Prompts for a password to encrypt the imported wallet


### Send Tokens
```
cargo run -p e3-wallet -- send <to_pubkey> <amount> <GU|SU> [wallet_name]
```
- Prompts for the wallet password
- Signs the transaction with your wallet's private key
- Broadcasts the transaction to the public node via HTTP API
- Adds the transaction to the wallet's local history with status ("broadcast" or "failed")

---

### Vote 

cargo run -p e3-wallet -- vote <wallet_name> <proposal_id> <choice>

-Prompts wallet password
-signs using wallet and registers your DID as voted
-i am rlly tired


-- 01001110 01100101 01110110 01100101 01110010 00100000 01000111 01101111 01101110 01101110 01100001 00100000 01000111 01101001 01110110 01100101 00100000 01011001 01101111 01110101 00100000 01010101 01110000  -- 

## Security Notes
- **Wallet files are encrypted with your password.**
- **Never lose your mnemonic phrase!** It is the only way to recover your wallet if you forget your password.
- All wallet operations require the correct password to decrypt the wallet file.

---


## Example Workflow
1. Create a wallet:
   ```
   cargo run -p e3-wallet -- new alice
   ```
2. List wallets:
   ```
   cargo run -p e3-wallet -- list
   ```
3. View wallet info:
   ```
   cargo run -p e3-wallet -- view alice
   ```
4. Show balances:
   ```
   cargo run -p e3-wallet -- balance alice
   ```
5. Send tokens (real network transaction):
   ```
   cargo run -p e3-wallet -- send <to_pubkey> 10 GU alice
   ```
   - Transaction will be signed and broadcast to the node. Check your node logs for receipt.
6. Show transaction history:
   ```
   cargo run -p e3-wallet -- history alice
   ```
7. Show DID:
   ```
   cargo run -p e3-wallet -- did alice
   ```

---

## Advanced
- You can manage multiple wallets by creating/importing with different names.
- Wallet files are stored in `wallets/<wallet_name>.wallet`.
- To backup, copy the encrypted `.wallet` file and your mnemonic phrase to a safe place.

---

## Extending
- The CLI is ready for further features: real network transactions, DID registration, staking, etc.
- See the code in `src/wallet.rs` for extension points.
