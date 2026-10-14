# sahconnect

SSH and systemapi client.

**sah** means Service Automation Hub. The hub encompasses the platform and the suite of utilities.

`sahconnect <host>` opens an interactive shell on a host through SystemAPI. The host's outbound agent runs the PTY, so the host needs no inbound SSH. `sahconnect login` gets a bearer token by OAuth device login. `sahconnect api` calls the operator's systemapi. `sahconnect ssh` execs the `adssh` binary. This module does not embed an SSH stack and it is not an exploit tool.

```bash
go install ./cmd/sahconnect
export SYSTEMAPI_URL=https://systemapi.example
sahconnect login --username alice     # prints a URL to approve; stores ~/.config/sahconnect/token (0600)
sahconnect web1                       # shell on web1 (exit code is the remote shell's)
sahconnect web1 --root                # root shell; needs the terminal:root scope
echo uptime | sahconnect web1         # piped stdin, no raw mode
sahconnect logout
sahconnect api GET /api/v1/fleet      # SYSTEMAPI_API_KEY works too, for automation
sahconnect ssh -- version
```

- **Credentials.** The token file records the origin that issued it, and its bearer goes only to that origin, as `Authorization: Bearer`. Otherwise `SYSTEMAPI_API_KEY` is sent as `X-API-Key`. Neither is printed, and neither goes in a URL.
- **Transport.** Plain `http` and `ws` are accepted only for loopback. Everything else is TLS 1.3 with system CAs, no proxy, and no redirects.
- **Config.** `~/.config/sahconnect/config.toml`, which respects `XDG_CONFIG_HOME` and `SAHCONNECT_CONFIG`. A symlinked config, one owned by someone else, or one that others can write is refused.
- **Phase 1.** Only `method = agent` runs. `ssh` arrives in phase 3, behind a signed connect policy.
- **Host names.** A host named like a subcommand (`version`, `help`, `api`, `ssh`, `login`, `logout`, `connect`) needs `sahconnect connect <name>`.

Libraries:

- `github.com/coder/websocket`: context-aware, zero dependencies, actively maintained. It takes our guarded `http.Client` for the handshake.
- `github.com/BurntSushi/toml`: small, zero dependencies, and the reference Go TOML decoder. It reports undecoded keys, so unknown keys can be refused.
- `golang.org/x/term`: raw mode.

Usage: `docs/usage.md`. Terminal protocol: `~/development/systemapi.io/docs/sahconnect-terminal-protocol.md`. Suite contract: `~/development/systemapi.io/docs/sah-suite.md`.

## Next

`go test ./...`
