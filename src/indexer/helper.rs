use reqwest::Client;
use serde::Deserialize;
use tracing::info;

use crate::models::{ZcashConfig, ZcashRpcRequest, ZcashRpcResponse, ZcashTransaction};

/// ZcashNodeClient handles all read-only RPC communication with the Zcash full node (zcashd).
#[derive(Clone)]
pub struct ZcashNodeClient {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub client: Client,
}

impl ZcashNodeClient {
    pub fn new(config: &ZcashConfig) -> Self {
        Self {
            rpc_url: config.rpc_url.clone(),
            rpc_user: config.rpc_user.clone(),
            rpc_password: config.rpc_password.clone(),
            client: reqwest::Client::new(),
        }
    }

    // ==================== Indexer Reader Functions ====================

    /// Retrieves a Zcash transaction by ID in verbose format.
    pub async fn get_transaction(
        &self,
        txid: &str,
    ) -> Result<ZcashTransaction, Box<dyn std::error::Error>> {
        info!("Fetching transaction {}", txid);
        self.rpc_call(
            "getrawtransaction",
            vec![serde_json::json!(txid), serde_json::json!(1)],
        )
        .await
        .map_err(|e| format!("Failed to get transaction {}: {}", txid, e).into())
    }

    /// Attempts to decrypt a shielded note's memo field using the wallet's keys.
    pub async fn try_decrypt_memo(
        &self,
        enc_ciphertext: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("Attempting to decrypt memo...");
        self.rpc_call("z_viewtransaction", vec![serde_json::json!(enc_ciphertext)])
            .await
            .map(|v: serde_json::Value| v.as_str().unwrap_or("").to_string())
            .map_err(|e| format!("Failed to decrypt memo: {}", e).into())
    }

    // ==================== Core RPC Call ====================

    /// Generic RPC call method
    pub async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let request = ZcashRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "1".to_string(),
            method: method.to_string(),
            params,
        };

        let response = self
            .client
            .post(&self.rpc_url)
            .basic_auth(&self.rpc_user, Some(&self.rpc_password))
            .json(&request)
            .send()
            .await?;

        let rpc_response: ZcashRpcResponse<T> = response.json().await?;

        if let Some(error) = rpc_response.error {
            return Err(format!("RPC error {}: {}", error.code, error.message).into());
        }

        rpc_response
            .result
            .ok_or_else(|| "No result in RPC response".into())
    }
}
