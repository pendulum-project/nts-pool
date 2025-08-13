# NTS Pool
This project contains a work in progress pool management system for NTS servers.

## Development
The easiest way to get started is by using the provided docker compose
configuration. This will start both the management-server and the key exchange
server, in addition to a database server and two NTP/NTS servers that can be
added to the pool. The servers should be configured so they are reachable from
your local computer.

To start, simply run `docker compose up` (or `docker compose up -d` to run in
the background). To run database migrations (an up to date schema is needed to
compile the management server), run
`docker compose run --rm management sqlx migrate run`. If any of the
queries used in the backend are changed, you will have to update the offline
sqlx data by running
`docker compose run --rm management cargo sqlx prepare`. This will make
sure that the management server can also be compiled when no database is active.
If you do not intend to change any of the queries or update anything from the
database schema, you may also set the `SQLX_OFFLINE=1` environment variable to
disable requiring an up to date database. This variable is also respected by the
compose file.
