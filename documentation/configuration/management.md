# Management server configuration

The management server is configured primarily through environment variables, which are inspected once at boot time of the server.

## Logging
- `RUST_LOG`: The log level the server will operate on. The main levels are `trace`, `debug`, `info`, `warn`, and `error`. See [the tracing documentation](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/index.html#filtering-events-with-environment-variables) for more detail. (Default: `error`)

## Base website settings
- `NTSPOOL_BASE_URL`: The base url at which the server is reached by clients. This should be the full URL including protocol of the root path of the server. (Example: `http://localhost:3000/`)
- `NTSPOOL_ASSETS_DIR`: The directory with all the static assets for the server. MUST point to (a copy of) the directory `nts-pool-management/assets`. (Default: `./assets`)

## Updater configuration
- `NTSPOOL_CONFIG_UPDATER_SECRET`: Secret used to authenticate the KELB configuration updater. (Example: `UNSAFE_SECRET`)

## Database configuration
- `NTSPOOL_DATABASE_URL`/`DATABASE_URL`: Connection url for the database. (Example: `postgres://nts-pool@localhost:5432/nts-pool`)
- `NTSPOOL_DATABASE_RUN_MIGRATIONS`: Whether or not to run database migrations on startup. Must be a boolean value (true/false/1/0). (Default: `false`)

## Secrets
- `NTSPOOL_JWT_SECRET`: Secret used to verify and sign jwts used to login users. (Example: `UNSAFE_SECRET`)
- `NTSPOOL_COOKIE_SECRET`: Secret used to tamper-proof various internal non-authentication cookies. (Example: `UNSAFE_SECRET`)

## Pool secrets
- `NTSPOOL_BASE_SHARED_SECRET`: Newest secret used to derive the shared secrets the KELB uses to authenticate to time sources (Example: `UNSAFE_SECRET`)
- `NTSPOOL_BASE_SECRET_INDEX`: Index number of the secret provided in `NTSPOOL_BASE_SHARED_SECRET`. (Example: 0)

## Email configuration
- `NTSPOOL_MAIL_FROM_ADDRESS`: Email address to use as sender address in emails sent from the management system. (Example: `noreply@example.com`)
- `NTSPOOL_SMTP_URL`: Connection information for the email server to use for sending emails. (Example: `smtp://localhost:25`)

## Monitoring configuration
- `NTSPOOL_POOLKE_NAME`: Dns name of the poolke servers managed by this management server. (Example: `localhost:4460`)
- `NTSPOOL_MONITOR_RESULT_BATCHSIZE`: Number of results monitors should at most collect before pushing them back to the management server. (Example: `4`)
- `NTSPOOL_MONITOR_RESULT_BATCHTIME`: Maximum time a monitor should wait before sending a result back to the management server, in seconds. Together with `NTSPOOL_MONITOR_RESULT_BATCHSIZE`, this manages the number of http calls made for reporting results back to the management server. (Example: `60`)
- `NTSPOOL_MONITOR_UPDATE_INTERVAL`: Time between requests from monitors for new configuration data, in seconds. (Example: `60`)
- `NTSPOOL_MONITOR_PROBE_INTERVAL`: Time between individual probes of a time source for a given protocol, in seconds. (Example: `4`)
- `NTSPOOL_MONITOR_NTS_TIMEOUT`: Maximum time the monitor will wait for an NTS key exchange with a time source before declaring it unreachable, in milliseconds. (Example: `1000`)
- `NTSPOOL_MONITOR_NTP_TIMEOUT`: Maximum time the monitor will wait for an NTP message exchange with a time source before declaring it unreachable, in milliseconds. (Example: `1000`)

## Time source weight configuration
- `NTSPOOL_MAX_TIMESOURCE_WEIGHT`: Maximum weight that can be given to a timesource by the user. (Example: `10`)
