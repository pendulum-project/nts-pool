# NTS Pool
This project contains a work in progress pool management system for NTS servers.

## Development
The easiest way to get started is by using the provided docker compose
configuration. This will start both the management-server and the key exchange
server, in addition to a database server and two NTP/NTS servers that can be
added to the pool. The servers should be configured so they are reachable from
your local computer, so that when you point your NTS client to the pool
configured in the compose file you should be able to get NTP responses.

Here are the main steps/actions required to run the project:

- The docker compose configuration mounts your local directories. To prevent
  generated files from being owned by the wrong user set the USER_ID and
  GROUP_ID environment variables to your current user id/group id, e.g.:
  `export USER_ID=$(id -u)` and `export GROUP_ID=$(id -g)`. Note: this has no
  effect when you use docker desktop, but we require these values anyway, you
  may also set them to any other id to run as any user you would prefer.
- Run migrations using: `docker compose run --rm management sqlx migrate run`
  This will ensure that the database schema is up to date.
- Start application: `docker compose up` (or `docker compose up -d` to run in
  the background). If there are no users in the database, this will
  automatically populate it with some fixture data suitable for the container
  setup.
- Updating SQLx queries: `docker compose run --rm management cargo sqlx prepare`
  Whenever you change any of the queries used by the management interface you
  will need to run this script to generate updated query information that SQLx
  uses to enable compilation without a running database.
- Use `export DOCKER_SQLX_OFFLINE=1` (or `export SQLX_OFFLINE=1` outside of the
  docker setup) and run any command to use the query cache. This can be used to
  run without a database.
- Use `docker compose run --rm management cargo sqlx database reset -y --force`
  to reset the database whenever you need a completely fresh database. This
  command removes the database and runs migrations again. After the reset, you
  may want to restart the management interface to reload the fixture data.
- To completely get rid of all containers and any associated storage you can run
  `docker compose down` in the root of the project. Careful: This also
  completely removes the database.

The data created from the fixture data in the database creates two users:

- An administrator: `admin@example.com` with password `admin`
- A server manager user: `manager@example.com` with password `manager`

Additionally, two servers (time-a and time-b) are created under the admin
account. A testmonitor is also created.
