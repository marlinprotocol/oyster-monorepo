CREATE TYPE result_outcome AS ENUM ('PENDING', 'PASSED', 'FAILED', 'VETOED');

CREATE TABLE results (
    proposal_id CHAR(66) NOT NULL PRIMARY KEY REFERENCES proposals(id),
    yes NUMERIC NOT NULL,
    no NUMERIC NOT NULL,
    abstain NUMERIC NOT NULL,
    no_with_veto NUMERIC NOT NULL,
    total_voting_power NUMERIC NOT NULL,
    outcome result_outcome NOT NULL,
    tx_hash CHAR(66) NOT NULL
);