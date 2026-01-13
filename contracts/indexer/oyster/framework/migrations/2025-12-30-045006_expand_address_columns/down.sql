-- Revert address columns back to EVM-only size

-- Providers table
ALTER TABLE providers ALTER COLUMN id TYPE CHAR(42);

-- Jobs table
ALTER TABLE jobs ALTER COLUMN owner TYPE CHAR(42);
ALTER TABLE jobs ALTER COLUMN provider TYPE CHAR(42);

