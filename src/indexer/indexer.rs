use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};
use reqwest::{Client, StatusCode};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::database::database::Database;
use crate::database::model::{Chain, HTLCState, ZcashHTLCDatabase};
use crate::indexer::node_client::ZcashNodeClient;
use crate::models::{IndexerConfig, IndexerEventRequest, ZcashConfig, ZcashIndexer, ZcashTransaction};

type HmacSha256 = Hmac<Sha256>;

impl ZcashIndexer {
    pub fn new(
        zcash_config: &ZcashConfig, 
        indexer_config: IndexerConfig,
        database: Arc<Database>,
    ) -> Self {
        info!("🔎 Initializing Zcash Indexer");
        ZcashIndexer {
            node_client: ZcashNodeClient::new(zcash_config),
            config: indexer_config,
            http_client: Client::new(),
            database,
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        let mut current_block_height = self.config.start_block;
        
        loop {
            info!("🔍 Zcash Indexer scanning block: {}", current_block_height);
            
            // Get block hash
            let block_hash: String = match self.node_client.rpc_call(
                "getblockhash", 
                vec![serde_json::json!(current_block_height)]
            ).await {
                Ok(hash) => hash,
                Err(e) => {
                    error!("Failed to get block hash for height {}: {}", current_block_height, e);
                    sleep(Duration::from_secs(self.config.scan_interval_seconds)).await;
                    continue;
                }
            };

            // Get block data
            let block: serde_json::Value = match self.node_client.rpc_call(
                "getblock",
                vec![serde_json::json!(block_hash), serde_json::json!(1)]
            ).await {
                Ok(block) => block,
                Err(e) => {
                    error!("Failed to get block {}: {}", block_hash, e);
                    sleep(Duration::from_secs(self.config.scan_interval_seconds)).await;
                    continue;
                }
            };

            // Process transactions in block
            if let Some(tx_ids) = block["tx"].as_array() {
                for tx_id in tx_ids {
                    if let Some(txid) = tx_id.as_str() {
                        if let Err(e) = self.scan_transaction(txid).await {
                            error!("Error scanning transaction {}: {}", txid, e);
                        }
                    }
                }
            }

            // Save checkpoint - using the same pattern as main relayer
            if let Err(e) = self.save_checkpoint(current_block_height).await {
                warn!("Failed to save checkpoint for block {}: {}", current_block_height, e);
            }

            current_block_height += 1;
            sleep(Duration::from_secs(self.config.scan_interval_seconds)).await;
        }
    }

    async fn scan_transaction(&self, txid: &str) -> Result<(), String> {
        let tx: ZcashTransaction = self.node_client
            .get_transaction(txid)
            .await
            .map_err(|e| format!("Failed to get transaction: {}", e))?;
        
        let block_timestamp = tx.blocktime as i64; 

        for output in tx.vshieldedoutput.iter() {
            if let Some(ciphertext) = output.enc_ciphertext.as_ref() {
                let decrypted_memo = self.node_client
                    .try_decrypt_memo(ciphertext)
                    .await
                    .map_err(|e| format!("Failed to decrypt memo: {}", e))?;

                if let Some(payload) = ZcashIndexer::extract_htlc_payload(&decrypted_memo, txid, block_timestamp) {
                    // Handle HTLC events based on type
                    if payload.event_type == "htlc_created" {
                        self.handle_htlc_created(txid, &payload).await?;
                    } else if payload.event_type == "htlc_redeemed" {
                        self.handle_htlc_redeemed(txid).await?;
                    }
                    
                    // Report to relayer
                    self.report_event_to_relayer(payload).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_htlc_created(&self, txid: &str, payload: &IndexerEventRequest) -> Result<(), String> {
        // Create HTLC record in database
        let htlc = ZcashHTLCDatabase {
            hash_lock: payload.hash_lock.clone().unwrap_or_default(),
            timelock: payload.timestamp as u64 + 86400, // 24h from now
            recipient: payload.stealth_participant.clone().unwrap_or_default(),
            amount: payload.amount.clone().unwrap_or_default().parse().unwrap_or(0),
            state: HTLCState::Pending,
        };

        self.database
            .record_zcash_htlc(txid, &htlc)
            .map_err(|e| format!("Database error recording HTLC: {}", e))?;

        info!("✅ Recorded HTLC creation for tx: {}", txid);
        Ok(())
    }

    async fn handle_htlc_redeemed(&self, txid: &str) -> Result<(), String> {
        self.database
            .update_zcash_htlc_state(txid, HTLCState::Redeemed)
            .map_err(|e| format!("Database error updating HTLC: {}", e))?;

        info!("✅ Updated HTLC state to Redeemed for tx: {}", txid);
        Ok(())
    }

    async fn save_checkpoint(&self, height: u64) -> Result<(), String> {
        self.database
            .save_indexer_checkpoint(Chain::Zcash, height as u32)
            .map_err(|e| format!("Database checkpoint error: {}", e))
    }

    fn extract_htlc_payload(decrypted_memo: &str, txid: &str, timestamp: i64) -> Option<IndexerEventRequest> {
        if decrypted_memo.contains("HTLC_CREATE") {
            info!("🔨 HTLC Creation detected in tx: {}", txid);
            return Some(IndexerEventRequest {
                event_type: "htlc_created".to_string(),
                chain: "zcash".to_string(),
                transaction_hash: txid.to_string(),
                timestamp,
                
                swap_id: None,
                commitment: Some("MOCK_COMMITMENT_123".to_string()),
                hash_lock: Some("MOCK_HASH_LOCK_ABC".to_string()),
                secret: None,
                nullifier: None,
                amount: Some("1.0".to_string()),
                stealth_initiator: Some("MOCK_INITIATOR_ADDR".to_string()),
                stealth_participant: Some("MOCK_PARTICIPANT_ADDR".to_string()),
            });
        }
        
        if decrypted_memo.contains("HTLC_REDEEM") {
             info!("🔓 HTLC Redemption detected in tx: {}", txid);
            return Some(IndexerEventRequest {
                event_type: "htlc_redeemed".to_string(),
                chain: "zcash".to_string(),
                transaction_hash: txid.to_string(),
                timestamp,
                
                swap_id: None,
                commitment: Some("MOCK_COMMITMENT_123".to_string()),
                hash_lock: None,
                secret: Some("MOCK_SECRET_XYZ".to_string()),
                nullifier: None,
                amount: Some("1.0".to_string()),
                stealth_initiator: None,
                stealth_participant: None,
            });
        }
        
        None
    }

    async fn report_event_to_relayer(&self, payload: IndexerEventRequest) -> Result<(), String> {
        let current_time_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("System time error: {}", e))?
            .as_millis()
            .to_string();

        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| format!("JSON serialization error: {}", e))?;
        
        let signature = self.generate_hmac_signature(&current_time_ms, &payload_json)?;

        info!(
            "📤 Reporting event {} for tx {} to {}",
            payload.event_type, payload.transaction_hash, self.config.relayer_api_url
        );

        let response = self.http_client
            .post(&self.config.relayer_api_url)
            .header("x-timestamp", &current_time_ms)
            .header("x-signature", &signature)
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                let response_body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;
                info!("✅ Successfully reported event. Relayer response: {:?}", response_body);
                Ok(())
            }
            status => {
                let text = response.text().await.unwrap_or_else(|_| "No response body".to_string());
                Err(format!("Relayer API failed with status {}: {}", status, text))
            }
        }
    }
    
    fn generate_hmac_signature(&self, timestamp: &str, body: &str) -> Result<String, String> {
        let message = format!("{}{}", timestamp, body);

        let mut mac = HmacSha256::new_from_slice(self.config.hmac_secret.as_bytes())
            .map_err(|e| format!("Error creating HMAC key: {}", e))?;
        
        mac.update(message.as_bytes());
        
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}