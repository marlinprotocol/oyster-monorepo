-- Up

-- Job events table
CREATE TABLE job_events (
    id BIGSERIAL PRIMARY KEY,
    block_id BIGINT NOT NULL, -- Sui: checkpoint_sequence_number; Eth/Arbitrum: block_number; Solana: slot_index
    tx_hash VARCHAR(100) NOT NULL,
    event_seq BIGINT NOT NULL,
    block_timestamp TIMESTAMPTZ NOT NULL,
    sender VARCHAR(66) NOT NULL,
    event_name VARCHAR(255) NOT NULL,
    event_data JSONB NOT NULL,
    job_id VARCHAR(66) NOT NULL,
    indexer_process_time TIMESTAMPTZ DEFAULT now()
);


-- Indexer state table to track progress
CREATE TABLE indexer_state (
    id INT PRIMARY KEY,
    last_processed_block BIGINT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Initial values
INSERT INTO indexer_state (id, last_processed_block) VALUES (1, -1);

-- Useful indexes
CREATE INDEX idx_job_events_polling ON job_events (indexer_process_time);
CREATE INDEX idx_job_events_full_fetch ON job_events (block_id, event_seq);
CREATE INDEX idx_job_events_event_name_job_id ON job_events (event_name, job_id);

-- -- Down
-- --sqlx DOWN

-- DROP INDEX idx_job_events_polling;
-- DROP INDEX idx_job_events_full_fetch;
-- DROP TABLE indexer_state;
-- DROP TABLE job_events;
