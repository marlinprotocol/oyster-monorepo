CREATE TABLE rate_revisions (
  job_id CHAR(66) REFERENCES jobs (id),
  value NUMERIC NOT NULL,
  block BIGINT NOT NULL,
  PRIMARY KEY (job_id, block)
)
