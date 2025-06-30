-- Make columns not nullable again
ALTER TABLE jobs
ALTER COLUMN last_settled SET NOT NULL,
ALTER COLUMN balance SET NOT NULL,
ALTER COLUMN rate SET NOT NULL,
ALTER COLUMN created SET NOT NULL;

-- Remove new balance columns from jobs table
ALTER TABLE jobs
DROP COLUMN usdc_balance,
DROP COLUMN credits_balance;

-- Remove new columns from transactions table
ALTER TABLE transactions
DROP COLUMN is_usdc;