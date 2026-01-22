CREATE TABLE votes (
  proposal_id CHAR(66) NOT NULL REFERENCES proposals(id),
  voter CHAR(42) NOT NULL,
  delegator CHAR(42) NOT NULL,
  tx_hash CHAR(66) NOT NULL,
  delegator_chain_id NUMERIC NOT NULL,
  vote_idx NUMERIC NOT NULL,
  PRIMARY KEY (proposal_id, voter)
);