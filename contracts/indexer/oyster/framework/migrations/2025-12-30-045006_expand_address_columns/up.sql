-- Convert CHAR columns to VARCHAR to avoid space-padding issues
-- VARCHAR stores strings at their actual length without padding

-- Jobs table
ALTER TABLE jobs ALTER COLUMN id TYPE VARCHAR(66);
ALTER TABLE jobs ALTER COLUMN owner TYPE VARCHAR(66);
ALTER TABLE jobs ALTER COLUMN provider TYPE VARCHAR(66);

-- Providers table
ALTER TABLE providers ALTER COLUMN id TYPE VARCHAR(66);
ALTER TABLE providers ALTER COLUMN tx_hash TYPE VARCHAR(66);

-- Rate revisions table
ALTER TABLE rate_revisions ALTER COLUMN job_id TYPE VARCHAR(66);

-- Revise rate requests table
ALTER TABLE revise_rate_requests ALTER COLUMN id TYPE VARCHAR(66);

-- Settlement history table
ALTER TABLE settlement_history ALTER COLUMN id TYPE VARCHAR(66);

-- Transactions table
ALTER TABLE transactions ALTER COLUMN tx_hash TYPE VARCHAR(66);
ALTER TABLE transactions ALTER COLUMN job TYPE VARCHAR(66);

