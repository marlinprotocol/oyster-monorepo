-- Expand address columns to support both EVM (42 chars) and Sui (66 chars) addresses

-- Providers table
ALTER TABLE providers ALTER COLUMN id TYPE CHAR(66);

-- Jobs table
ALTER TABLE jobs ALTER COLUMN owner TYPE CHAR(66);
ALTER TABLE jobs ALTER COLUMN provider TYPE CHAR(66);

