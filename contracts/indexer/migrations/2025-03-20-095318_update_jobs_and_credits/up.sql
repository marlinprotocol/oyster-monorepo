-- Make existing columns nullable and set balance default to 0
ALTER TABLE jobs
ALTER COLUMN last_settled DROP NOT NULL,
ALTER COLUMN balance DROP NOT NULL,
ALTER COLUMN balance SET DEFAULT 0,
ALTER COLUMN rate DROP NOT NULL,
ALTER COLUMN created DROP NOT NULL;

-- Add new balance columns to jobs table
ALTER TABLE jobs
ADD COLUMN usdc_balance NUMERIC DEFAULT 0,
ADD COLUMN credits_balance NUMERIC DEFAULT 0;

-- Add new columns to transactions table
ALTER TABLE transactions
ADD COLUMN is_usdc BOOLEAN DEFAULT true;