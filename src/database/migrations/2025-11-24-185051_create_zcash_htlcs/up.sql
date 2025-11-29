-- Your SQL goes here
CREATE TABLE zcash_htlcs (
    id SERIAL PRIMARY KEY,
    txid VARCHAR NOT NULL UNIQUE,
    hash_lock VARCHAR NOT NULL,
    timelock BIGINT NOT NULL,
    recipient VARCHAR NOT NULL,
    amount DOUBLE PRECISION NOT NULL,
    -- State 0: Pending, 1: Redeemed, 2: Refunded
    state SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index on hash_lock for quick lookup
CREATE UNIQUE INDEX zcash_htlcs_hash_lock_idx ON zcash_htlcs (hash_lock);
