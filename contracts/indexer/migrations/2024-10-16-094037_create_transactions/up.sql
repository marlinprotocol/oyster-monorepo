CREATE TABLE transactions (
  block BIGINT NOT NULL,
  idx BIGINT NOT NULL,
  tx_hash CHAR(66) NOT NULL,
  job CHAR(66) NOT NULL REFERENCES jobs (id),
  amount NUMERIC NOT NULL,
  tx_type VARCHAR NOT NULL CHECK (tx_type IN ('deposit', 'withdraw', 'settle', 'rate_revision')),
  PRIMARY KEY(block, idx)
);

CREATE INDEX transactions_block_idx_idx ON transactions (block, idx);
CREATE INDEX transactions_job_idx ON transactions (job);
