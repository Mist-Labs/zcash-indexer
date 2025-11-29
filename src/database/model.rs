use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

// --- Core Enums ---

#[derive(Debug, Clone, Copy)]
pub enum Chain {
    Zcash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum HTLCState {
    Pending = 0,
    Redeemed = 1,
    Refunded = 2,
}

// --- Zcash HTLC Application Model (Used by Database Impl) ---

#[derive(Debug, Clone)]
pub struct ZcashHTLCDatabase {
    pub hash_lock: String,
    pub timelock: u64,
    pub recipient: String,
    pub amount: u64,
    pub state: HTLCState,
}

// ==================== Zcash HTLC Diesel Models ====================

#[derive(Insertable)]
#[diesel(table_name = crate::database::schema::zcash_htlcs)]
pub struct NewZcashHTLC<'a> {
    pub txid: &'a str,
    pub hash_lock: &'a str,
    pub timelock: i64,
    pub recipient: &'a str,
    pub amount: f64,
    pub state: i16,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::database::schema::zcash_htlcs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DbZcashHTLC {
    pub id: i32,
    pub txid: String,
    pub hash_lock: String,
    pub timelock: i64,
    pub recipient: String,
    pub amount: f64,
    pub state: i16,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ==================== Indexer Checkpoint Diesel Models ====================

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::database::schema::indexer_checkpoints)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct IndexerCheckpoint {
    pub chain: String,
    pub last_block: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::database::schema::indexer_checkpoints)]
pub struct NewIndexerCheckpoint<'a> {
    pub chain: &'a str,
    pub last_block: i32,
    pub updated_at: DateTime<Utc>,
}