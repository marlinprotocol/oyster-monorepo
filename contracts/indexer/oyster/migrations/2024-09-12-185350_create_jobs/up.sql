CREATE TABLE jobs (
  id CHAR(66) PRIMARY KEY,
  metadata text NOT NULL,
  owner CHAR(42) NOT NULL,
  provider CHAR(42) NOT NULL,
  rate NUMERIC NOT NULL,
  balance NUMERIC NOT NULL,
  last_settled TIMESTAMP NOT NULL,
  created TIMESTAMP NOT NULL,
  is_closed BOOLEAN NOT NULL
);

CREATE INDEX jobs_owner_idx ON jobs (owner);
CREATE INDEX jobs_provider_idx ON jobs (provider);
CREATE INDEX jobs_created_idx ON jobs (created);
CREATE INDEX jobs_is_closed_idx ON jobs (is_closed);
