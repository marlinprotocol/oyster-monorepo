-- Revert VARCHAR columns back to CHAR

-- Jobs table
ALTER TABLE jobs ALTER COLUMN id TYPE CHAR(66);
ALTER TABLE jobs ALTER COLUMN owner TYPE CHAR(42);
ALTER TABLE jobs ALTER COLUMN provider TYPE CHAR(42);

-- Providers table
ALTER TABLE providers ALTER COLUMN id TYPE CHAR(42);
ALTER TABLE providers ALTER COLUMN tx_hash TYPE CHAR(66);

-- Rate revisions table
ALTER TABLE rate_revisions ALTER COLUMN job_id TYPE CHAR(66);

-- Revise rate requests table
ALTER TABLE revise_rate_requests ALTER COLUMN id TYPE CHAR(66);

-- Settlement history table
ALTER TABLE settlement_history ALTER COLUMN id TYPE CHAR(66);

-- Transactions table
ALTER TABLE transactions ALTER COLUMN tx_hash TYPE CHAR(66);
ALTER TABLE transactions ALTER COLUMN job TYPE CHAR(66);

