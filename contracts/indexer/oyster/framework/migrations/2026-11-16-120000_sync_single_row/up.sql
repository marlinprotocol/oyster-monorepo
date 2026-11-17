-- sync holds the last indexed block and must have exactly one row
-- pin it with a fixed primary key so a second row can never be added

DO $$
DECLARE
  n BIGINT;
BEGIN
  SELECT count(*) INTO n FROM sync;
  IF n <> 1 THEN
    RAISE EXCEPTION 'sync table has % rows, expected exactly 1. Delete the wrong rows by hand (keep the last block that was really indexed) and start the indexer again.', n;
  END IF;
END $$;

ALTER TABLE sync DROP CONSTRAINT sync_pkey;
ALTER TABLE sync ADD COLUMN id INT NOT NULL DEFAULT 1 CHECK (id = 1);
ALTER TABLE sync ADD PRIMARY KEY (id);
