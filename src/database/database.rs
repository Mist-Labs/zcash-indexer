use chrono::Utc;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, Pool};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::database::model::{Chain, NewIndexerCheckpoint, NewZcashHTLC, ZcashHTLCDatabase, HTLCState};
use crate::database::schema::zcash_htlcs::dsl;
use crate::database::schema::zcash_htlcs;
use crate::database::schema::indexer_checkpoints;

impl Chain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Chain::Zcash => "zcash",
        }
    }
}

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("src/database/migrations");

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Debug)]
pub enum DatabaseSetupError {
    DbConnectionError(::r2d2::Error),
    DieselError(diesel::result::Error),
    DatabaseUrlNotSet,
    ErrorRunningMigrations,
}

impl std::fmt::Display for DatabaseSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseSetupError::DbConnectionError(e) => {
                write!(f, "Database connection error: {}", e)
            }
            DatabaseSetupError::DieselError(e) => write!(f, "Diesel error: {}", e),
            DatabaseSetupError::DatabaseUrlNotSet => write!(f, "DATABASE_URL not set"),
            DatabaseSetupError::ErrorRunningMigrations => write!(f, "Error running migrations"),
        }
    }
}

impl std::error::Error for DatabaseSetupError {}

#[derive(Clone)]
pub struct Database {
    pool: DbPool,
}

impl Database {
    pub fn new(
        database_url: &str,
        max_connection: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder().max_size(max_connection).build(manager)?;

        Ok(Database { pool })
    }

    pub fn get_connection(
        &self,
    ) -> Result<r2d2::PooledConnection<ConnectionManager<PgConnection>>, Box<dyn std::error::Error>>
    {
        Ok(self.pool.get()?)
    }

    pub fn run_migrations(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| format!("Migration error: {}", e))?;
        Ok(())
    }

    pub fn record_zcash_htlc(
        &self,
        txid: &str,
        htlc: &ZcashHTLCDatabase,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let new_htlc = NewZcashHTLC {
            txid,
            hash_lock: &htlc.hash_lock,
            timelock: htlc.timelock as i64,
            recipient: &htlc.recipient,
            amount: htlc.amount as f64,
            state: htlc.state as i16,
        };

        diesel::insert_into(zcash_htlcs::table)
            .values(&new_htlc)
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn update_zcash_htlc_state(
        &self,
        txid: &str,
        state: HTLCState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        diesel::update(dsl::zcash_htlcs.filter(dsl::txid.eq(txid)))
            .set((dsl::state.eq(state as i16), dsl::updated_at.eq(Utc::now())))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_zcash_htlc_by_nullifier(
        &self,
        _nullifier: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let result = dsl::zcash_htlcs
            .filter(dsl::state.eq(HTLCState::Pending as i16))
            .select(dsl::txid)
            .first::<String>(&mut conn)
            .optional()?;

        Ok(result)
    }

    pub fn save_indexer_checkpoint(
        &self,
        chain: Chain,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let chain_str = chain.as_str();

        let new_checkpoint = NewIndexerCheckpoint {
            chain: chain_str,
            last_block: height as i32,
            updated_at: Utc::now(),
        };

        diesel::insert_into(indexer_checkpoints::table)
            .values(&new_checkpoint)
            .on_conflict(indexer_checkpoints::chain)
            .do_update()
            .set((
                indexer_checkpoints::last_block.eq(height as i32),
                indexer_checkpoints::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_indexer_checkpoint(
        &self,
        chain: Chain,
    ) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;
        let chain_str = chain.as_str();

        let result = indexer_checkpoints::table
            .filter(indexer_checkpoints::chain.eq(chain_str))
            .select(indexer_checkpoints::last_block)
            .first::<i32>(&mut conn)
            .optional()?;

        Ok(result.map(|b| b as u32))
    }
}