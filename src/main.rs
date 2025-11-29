mod database;
mod indexer;
mod models;

use crate::{
    database::database::Database,
    database::model::Chain,
    models::{IndexerConfig, ZcashConfig, ZcashIndexer},
};
use std::sync::Arc;
use tokio::task;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zcash_indexer=info,diesel=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🚀 Starting Zcash Indexer Service");

    let zcash_config = ZcashConfig {
        rpc_url: std::env::var("ZEC_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8232".to_string()),
        rpc_user: std::env::var("ZEC_RPC_USER").unwrap_or_else(|_| "rpc_user".to_string()),
        rpc_password: std::env::var("ZEC_RPC_PASSWORD")
            .unwrap_or_else(|_| "rpc_password".to_string()),
        wallet_name: std::env::var("ZEC_WALLET_NAME")
            .unwrap_or_else(|_| "default_wallet".to_string()),
    };

    let mut indexer_config = IndexerConfig {
        relayer_api_url: std::env::var("RELAYER_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/indexer/events".to_string()),
        hmac_secret: std::env::var("HMAC_SECRET")
            .unwrap_or_else(|_| "a_secure_long_secret_key_for_hmac_auth".to_string()),
        scan_interval_seconds: 10,
        start_block: 500_000,
    };

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost:5432/zcash_indexer".to_string());
    let database =
        Arc::new(Database::new(&database_url, 5).expect("Failed to initialize database pool"));

    info!("📊 Running database migrations");
    database.run_migrations().expect("Failed to run migrations");

    let start_block = match database.get_indexer_checkpoint(Chain::Zcash) {
        Ok(Some(last_block)) => {
            info!("✅ Resuming scan from block: {}", last_block + 1);
            last_block as u64 + 1
        }
        _ => {
            info!(
                "📍 Starting scan from configured block: {}",
                indexer_config.start_block
            );
            indexer_config.start_block
        }
    };
    indexer_config.start_block = start_block;

    let indexer = Arc::new(ZcashIndexer::new(
        &zcash_config,
        indexer_config,
        database.clone(),
    ));

    info!("🔗 Starting Zcash Indexer service loop");

    let indexer_handle = task::spawn(async move {
        if let Err(e) = indexer.run().await {
            error!("❌ Zcash Indexer service stopped with fatal error: {}", e);
        }
    });

    info!("✅ Zcash Indexer service started successfully. Monitoring task...");

    match indexer_handle.await {
        Ok(()) => {
            info!("✅ Zcash Indexer task completed");
        }
        Err(e) => {
            error!("❌ Zcash Indexer task panicked: {}", e);
        }
    }

    Ok(())
}
