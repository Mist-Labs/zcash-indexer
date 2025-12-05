# ⚡ Zcash HTLC Indexer
### _Real-time Zcash Shielded HTLC Event Indexer + Secure Relayer Transport_

This service scans the **Zcash blockchain** for **shielded HTLC transactions**, decodes events, stores them in a database, and securely sends them to a **Rust relayer** using **HMAC-signed webhooks**.  

It is designed to support **cross-chain swaps** (like STRK ↔ ZEC) by detecting and relaying HTLC events in real-time.

---

## 🚀 Features

### ✅ Zcash Event Indexing
- Scans **shielded transactions** for HTLC-related memos  
- Detects the following events:
  - `htlc_created` – HTLC initialized  
  - `htlc_redeemed` – HTLC unlocked with secret  
  - `htlc_refunded` – HTLC refunded  

### 🔐 Secure Relayer Delivery
- HMAC-SHA256 signatures for event authenticity  
- Timestamp-based replay protection  
- Retry logic (up to 3 attempts)  
- Timeout-safe (60s)  

### 🗄 Database Persistence
- Stores HTLC records using **Postgres**  
- Maintains scan checkpoints to resume after restarts  

### 🧰 Robust Decoding
- Decrypts **shielded memo fields**  
- Validates:
  - Hash locks  
  - Timelocks  
  - Amounts  
  - Secret lengths  

### 🧩 Powered by Rust
- Async runtime via **Tokio**  
- HTTP client: **reqwest**  
- Logging: **tracing**  
- Cryptography: **HMAC + SHA256**

---

## 📡 Events Detected

| Event Type       | Meaning                              |
|-----------------|--------------------------------------|
| `htlc_created`   | HTLC initialized in shielded memo    |
| `htlc_redeemed`  | HTLC redeemed with secret            |
| `htlc_refunded`  | HTLC refunded (expired or cancelled) |

---

## 🧾 Payload Sent to Relayer

```json
{
  "event_type": "htlc_created",
  "chain": "zcash",
  "transaction_hash": "txid_here",
  "hash_lock": "hashlock_here",
  "secret": null,
  "timestamp": 1699999999,
  "amount": "10.5"
}
```

## 🔧 Tech Stack

**Languages / Frameworks / Libraries**
- Rust  
- Tokio (async runtime)  
- Reqwest (HTTP client)  
- Tracing (logging)  
- HMAC + SHA256 (crypto signatures)  

**Database**
- PostgreSQL (via Database abstraction layer)  

**Blockchain Concepts**
- Shielded transactions (Zcash)  
- HTLCs (Hashed Time-Locked Contracts)  
- Memos (encrypted data in shielded outputs)  

---

## 🧠 How It Works

1. Filters blocks based on configured start block.  
2. Scans transactions using Zcash RPC.  
3. Decrypts shielded memos for HTLC data.  
4. Classifies event types:  
   - `htlc_created` → HTLC created  
   - `htlc_redeemed` → HTLC redeemed  
   - `htlc_refunded` → HTLC refunded  
5. Stores events in Postgres database.  
6. Signs & sends events to Rust Relayer via HMAC-signed HTTP requests.  
7. Retries failed pushes (up to 3x).  
8. Logs decoding errors.  
9. Ignores unsupported events safely.  
10. Timeout handling ensures no hanging requests (60s).  

---

## ⚙️ Environment Variables

| Variable          | Required | Description                                     |
|------------------|----------|-------------------------------------------------|
| `ZEC_RPC_URL`     | ✅       | URL of Zcash node RPC endpoint                 |
| `ZEC_RPC_USER`    | ✅       | RPC username                                   |
| `ZEC_RPC_PASSWORD`| ✅       | RPC password                                   |
| `ZEC_WALLET_NAME` | ✅       | Wallet used to decrypt shielded transactions  |
| `RELAYER_API_URL` | ✅       | URL of Rust relayer endpoint                   |
| `HMAC_SECRET`     | ✅       | Secret key used to sign relayer payloads      |
| `DATABASE_URL`    | ✅       | PostgreSQL database connection string         |

## 🛠 Local Development

### 1️⃣ Clone Repository
```bash
git clone https://github.com/YOUR_ORG/zcash-htlc-indexer
cd zcash-htlc-indexer
```

### 2️⃣ Set Environment Variables
```bash
export ZEC_RPC_URL="http://127.0.0.1:8232"
export ZEC_RPC_USER="rpcuser"
export ZEC_RPC_PASSWORD="rpcpassword"
export ZEC_WALLET_NAME="default_wallet"
export RELAYER_API_URL="http://127.0.0.1:8080/indexer/events"
export HMAC_SECRET="supersecretkey"
export DATABASE_URL="postgres://user:password@localhost:5432/zcash_indexer"
```

### 3️⃣ Run the Indexer
`cargo run --release`




