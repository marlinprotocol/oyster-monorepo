CREATE TABLE votes (
  proposal_id CHAR(66) NOT NULL REFERENCES proposals(id),
  voter CHAR(42) NOT NULL,
  PRIMARY KEY (proposal_id, voter)
);