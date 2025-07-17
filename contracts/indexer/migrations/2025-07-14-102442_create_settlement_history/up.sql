create table settlement_history (
    id CHAR(66) REFERENCES jobs (id),
    amount NUMERIC NOT NULL,
    timestamp NUMERIC NOT NULL,
    block BIGINT NOT NULL,
    PRIMARY KEY (id, block)
);