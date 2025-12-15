CREATE TABLE revise_rate_requests (
  id CHAR(66) PRIMARY KEY REFERENCES jobs (id),
  value NUMERIC NOT NULL,
  updates_at TIMESTAMP NOT NULL
)
