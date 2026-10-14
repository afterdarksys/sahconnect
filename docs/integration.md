# sahconnect integration

sahconnect is a client. It does not import `github.com/afterdarksys/adssh` and it does not run SSH itself. `sahconnect <host>` opens a shell through SystemAPI: the host's agent runs the PTY and the session is recorded by adssh on the host (terminal protocol, `~/development/systemapi.io/docs/sahconnect-terminal-protocol.md`). `ssh` is `exec` of the operator's adssh binary, so adssh policy still applies.

`login` is a client of `controlplane/oauth.js` (`POST /oauth/device`, `POST /oauth/token`). It stores an opaque bearer. It does not import OIDC groups.

`api` talks to whatever origin `SYSTEMAPI_URL` names, within the rules in `docs/usage.md`. It is not limited to the three paths sahapi proxies. sahapi is the loopback service. This is the CLI.

Do not add SSH protocol code here. A second SSH stack would bypass adssh policy.

The suite contract is `~/development/systemapi.io/docs/sah-suite.md`. Enrollment of a computeapi machine is not this client's job and is not wired.

## Next

`go test ./internal/client/ -count=1`
