# CLAUDE.md

Read `AGENTS.md`. It wins if this file disagrees.

sahconnect opens agent-PTY shells through systemapi, does device login, calls systemapi with a bearer token or `X-API-Key`, and execs the `adssh` binary. It does not embed SSH. The suite contract is `~/development/systemapi.io/docs/sah-suite.md`.

## Next

`go test ./...`
