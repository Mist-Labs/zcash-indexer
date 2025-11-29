use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{database::database::Database, indexer::node_client::ZcashNodeClient};

// =================================================================
// Indexer/Relayer Communication Contract
// =================================================================

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IndexerEventRequest {
    pub event_type: String,
    pub chain: String,
    pub transaction_hash: String,
    pub timestamp: i64,

    pub swap_id: Option<String>,
    pub commitment: Option<String>,
    pub nullifier: Option<String>,
    pub hash_lock: Option<String>,
    pub secret: Option<String>,
    pub amount: Option<String>,
    pub stealth_initiator: Option<String>,
    pub stealth_participant: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndexerEventResponse {
    pub success: bool,
    pub message: String,
    pub error: Option<String>,
}

// =================================================================
// Configuration Models
// =================================================================
#[derive(Clone)]
pub struct ZcashIndexer {
    pub node_client: ZcashNodeClient,
    pub config: IndexerConfig,
    pub http_client: Client,
    pub database: Arc<Database>,
}


#[derive(Debug, Clone, Deserialize)]
pub struct ZcashConfig {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub wallet_name: String,
}

#[derive(Clone)]
pub struct IndexerConfig {
    pub relayer_api_url: String,
    pub hmac_secret: String, 
    pub scan_interval_seconds: u64,
    pub start_block: u64,
}

// =================================================================
// Zcash RPC/Transaction Models (Read-Only)
// =================================================================

#[derive(Serialize)]
pub struct ZcashRpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ZcashRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ZcashRpcResponse<T> {
    pub result: Option<T>,
    pub error: Option<ZcashRpcError>,
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZcashTransactionOutput {
    pub enc_ciphertext: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZcashTransaction {
    pub txid: String,
    pub confirmations: u32,
    pub blocktime: u64,
    pub vshieldedoutput: Vec<ZcashTransactionOutput>, 
    pub time: Option<u64>,
    pub vjoinsplit: Vec<serde_json::Value>,
    pub vshieldedspend: Vec<serde_json::Value>, 
}