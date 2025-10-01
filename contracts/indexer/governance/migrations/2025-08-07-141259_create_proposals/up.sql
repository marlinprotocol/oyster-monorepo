CREATE TYPE result_outcome AS ENUM ('PENDING', 'PASSED', 'FAILED', 'VETOED');

CREATE TABLE proposals (
  id CHAR(66) PRIMARY KEY,
  job_id CHAR(66),
  proposer CHAR(42) NOT NULL,
  nonce NUMERIC NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  tx_hash CHAR(66) NOT NULL,
  executed BOOLEAN NOT NULL,
  proposal_created_at NUMERIC NOT NULL,
  proposal_end_time NUMERIC NOT NULL,
  voting_start_time NUMERIC NOT NULL,
  voting_end_time NUMERIC NOT NULL,
  outcome result_outcome NOT NULL
);
