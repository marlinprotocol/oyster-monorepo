# Oyster indexers

This directory contains the indexers that follow Oyster contracts and store their state in Postgres.

- [`oyster/evm`](./oyster/evm): indexer for the Oyster marketplace contract on EVM chains.
- [`oyster/sui`](./oyster/sui): indexer for the Oyster marketplace package on Sui.
- [`oyster/framework`](./oyster/framework): event loop, schema and migrations shared by the two above.
- [`governance`](./governance): indexer for the governance contracts.

Each indexer only writes to its database. It does not serve the data. To serve it over GraphQL, run [PostGraphile](https://www.graphile.org/postgraphile/) in front of the database as described below.

## Deployment

### Database roles

Use two roles in each indexer database:

- The indexer role. It owns the tables, applies migrations and writes the indexed data. This is the role in the indexer's `DATABASE_URL`.
- A read-only role for PostGraphile and for anything else that reads the data.

> [!WARNING]
> Never give the indexer role, or any role that can write, to PostGraphile or to any other service that is reachable from outside. PostGraphile exposes whatever its role is allowed to do. With the indexer role, anyone who can reach the GraphQL endpoint can create, change and delete rows in every table. A changed or deleted row can stop the indexer or make it skip blocks, and readers cannot tell forged rows from indexed ones.

Create the read-only role as a superuser or as the database owner, after the indexer has run once and applied its migrations. Replace `<db>` and the password.

```sql
CREATE ROLE indexer_ro LOGIN PASSWORD '<password>';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE <db> TO indexer_ro;
GRANT USAGE ON SCHEMA public TO indexer_ro;

GRANT SELECT ON jobs, providers, rate_revisions, revise_rate_requests,
                settlement_history, transactions, lock_duration, sync
             TO indexer_ro;

REVOKE EXECUTE ON FUNCTION diesel_manage_updated_at(regclass) FROM PUBLIC;

ALTER ROLE indexer_ro SET default_transaction_read_only = on;
ALTER ROLE indexer_ro SET statement_timeout = '5s';
```

The table list above is for the Oyster marketplace indexers. If a later migration adds a table that should be served, grant `SELECT` on it as well. `diesel_manage_updated_at` is a helper created by the migrations that can add triggers to tables. PostGraphile would list it as a mutation if the role could execute it, which is why `EXECUTE` is revoked.

Check the result before exposing anything. Connected as `indexer_ro`, a write must fail:

```sql
INSERT INTO sync (block) VALUES (1);
-- ERROR:  cannot execute INSERT in a read-only transaction
```

### PostGraphile

Run PostGraphile with the read-only role, with mutations and GraphiQL turned off. The flags below are for PostGraphile v4, check `postgraphile --help` if you run another version.

```bash
postgraphile \
  --connection postgres://indexer_ro:<password>@127.0.0.1/<db> \
  --schema public \
  --host 127.0.0.1 \
  --port 5000 \
  --disable-default-mutations \
  --disable-graphiql \
  --no-ignore-rbac \
  --append-plugins postgraphile-plugin-connection-filter
```

- `--disable-default-mutations` removes the create, update and delete mutations for every table.
- `--disable-graphiql` removes the GraphiQL page.
- `--no-ignore-rbac` makes PostGraphile leave out anything the role has no permission for.
- `postgraphile-plugin-connection-filter` provides the filters used by `oyster-cvm` and the Hub.

Keep PostGraphile on localhost and put a reverse proxy in front of it for TLS. PostGraphile has no limit on query size by default, so set a request rate limit on the proxy. The `statement_timeout` on the read-only role stops queries that run for too long.

After it is up, check that the endpoint has no mutations. The following query must return `null` for `mutationType`:

```bash
curl -s https://<endpoint>/graphql \
  -H 'content-type: application/json' \
  -d '{"query":"{ __schema { mutationType { name } } }"}'
```

### Running the indexer

Run the indexer under a supervisor that restarts it when it exits, for example systemd with `Restart=always`. The indexer retries RPC errors by itself. It exits with a non-zero status on errors it cannot recover from, such as a database error. The error message has the block and the log index it stopped at.

Do not expose Postgres itself. Keep it on localhost or on a private network.

### The `sync` table

`sync` has exactly one row, which holds the last block that was indexed. The database enforces this, a second row cannot be inserted.

The migration that adds this check stops with an error if `sync` does not have exactly one row at that point:

```
sync table has 2 rows, expected exactly 1. Delete the wrong rows by hand (keep the last block that was really indexed) and start the indexer again.
```

If you see it, look at the rows, delete the ones that are wrong and start the indexer again:

```sql
SELECT * FROM sync;
DELETE FROM sync WHERE block = <wrong block>;
```
