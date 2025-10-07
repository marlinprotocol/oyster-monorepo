-- Up

-- Create ENUM type for event names
CREATE TYPE event_name AS ENUM (
'Opened', 
'Closed', 
'Deposited', 
'Settled', 
'MetadataUpdated', 
'Withdrew', 
'ReviseRateInitiated',
'ReviseRateCancelled',
'ReviseRateFinalized'
);

-- Job events table
CREATE TABLE job_events (
    id BIGSERIAL PRIMARY KEY,
    job_id VARCHAR(66) NOT NULL,
    event_name event_name NOT NULL,
    event_data JSONB NOT NULL,
    indexer_process_time TIMESTAMPTZ DEFAULT now()
);

-- Indexer state table to track progress
CREATE TABLE indexer_state (
    id INT PRIMARY KEY,
    chain_id VARCHAR(66),
    last_processed_block BIGINT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Table to track terminated jobs
CREATE TABLE terminated_jobs (
    job_id VARCHAR(66) PRIMARY KEY,
    terminated_at TIMESTAMPTZ DEFAULT now()
);

-- Initial values
INSERT INTO indexer_state (id, last_processed_block) VALUES (1, -1);

-- Useful index (for querying active job_id's based on the JobOpened & JobClosed events)
CREATE INDEX idx_job_events_event_name_job_id ON job_events (event_name, job_id); 

-- -- Down

-- --sqlx DOWN

-- DROP INDEX idx_job_events_event_name_job_id;
-- DROP TABLE indexer_state;
-- DROP TABLE job_events;
-- DROP TYPE event_name;
