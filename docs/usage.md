# sahconnect usage

Module `github.com/afterdarksys/sahconnect`. Version 0.2.0.

## Commands

| Command | Does |
| --- | --- |
| `sahconnect <host> [--root] [--method agent]` | Opens an interactive shell on `<host>` through SystemAPI. |
| `sahconnect connect <host> [--root] [--method agent]` | The same. Use this form when the host's name is a subcommand name. |
| `sahconnect login [--url URL] [--username USER]` | OAuth device login. Stores a bearer token. |
| `sahconnect logout` | Deletes the token file. |
| `sahconnect api METHOD /path [?query]` | One HTTP call to systemapi. |
| `sahconnect ssh -- ARGS` | Execs `adssh`. |
| `sahconnect version` | Prints the version. |

**Subcommand names win.** `version`, `help`, `api`, `ssh`, `login`, `logout`, and `connect` are never read as a host name. A host with one of those names is reached with `sahconnect connect <name>`. An argument that starts with `-` is never read as a host name either.

## Config

The file is `$XDG_CONFIG_HOME/sahconnect/config.toml`. Without `XDG_CONFIG_HOME` it is `~/.config/sahconnect/config.toml`. `SAHCONNECT_CONFIG` names another file, and that file must exist. A missing default file is fine.

```toml
systemapi_url = "https://systemapi.example"
method = ["agent"]               # or "agent", "ssh", "agent,ssh"
token_file = "~/.config/sahconnect/token"   # the default
```

- **Writable by others: refused.** A config file that is group- or world-writable, or is not a regular file, is refused. Fix it with `chmod go-w`.
- **Unknown keys: refused.** So a typo cannot silently drop a setting.
- **Environment beats the file.** `SYSTEMAPI_URL` overrides `systemapi_url`. `SYSTEMAPI_API_KEY` is read only from the environment. The file holds no secret.
- **`method`.** The list orders the client's preference. Each entry is `agent` or `ssh`, with no duplicates. Phase 1 runs only `agent`. A list without `agent` fails with "not available until phase 3". `agent,ssh` runs `agent`, and an agent failure never falls back to ssh. Falling back needs the signed connect policy, which arrives in phase 2.
- **`token_file`.** An absolute path, or one that starts with `~/`.

## Credentials

1. **The token file wins.** If the token file exists, sahconnect sends `Authorization: Bearer <token>`.
2. **Otherwise the API key.** Without a token file, `SYSTEMAPI_API_KEY` is sent as `X-API-Key`.
3. **Exactly one credential per request.** It never goes in a query string, and it is never printed.

A token file that exists but is readable or writable by others, is not a regular file (a symlink, for example), or holds an invalid token is an error. sahconnect does not fall back to the API key in that case.

This precedence applies to `connect` and `api`.

## Login

```
sahconnect login --url https://systemapi.example --username alice
```

1. **Start.** sahconnect POSTs `username` to `/oauth/device` (`controlplane/oauth.js`). The username must be a member. It defaults to `$USER`. The URL defaults to `SYSTEMAPI_URL` or `systemapi_url`.
2. **Approve.** sahconnect prints the verification URL and the code on stderr. Open the URL and approve it. The URL must be on the same origin as the control plane, at `/oauth/device/verify`. Otherwise login stops with `url_rejected`.
3. **Poll.** sahconnect polls `/oauth/token` with the device grant at the server's interval. `slow_down` adds 5 s to the interval. `expired_token`, `access_denied`, and `invalid_grant` end the login with a non-zero exit. The wait is capped at the code's lifetime, which is 10 minutes.
4. **Store.** The bearer token is written to `token_file`:
   - mode 0600, in a 0700 directory;
   - atomically, through a temp file that is fsynced and renamed;
   - a group- or world-writable directory is refused.

   sahconnect prints the file path and a 16-character SHA-256 fingerprint. It never prints the token.
5. **Expiry.** The server issues the token for one hour. When it expires, requests fail with 403; run `sahconnect login` again.

`sahconnect logout` deletes the token file. There is no server-side revoke endpoint yet. The token stays valid on the server until it expires.

## Connect (Method A, agent)

The steps follow the terminal protocol, `~/development/systemapi.io/docs/sahconnect-terminal-protocol.md`.

1. **Resolve.** `GET /api/v1/hosts/resolve?name=<host>`. The name must be 1–253 characters of `[A-Za-z0-9._-]`. Otherwise it is refused before any request is sent.
   - 404: "host not found".
   - 409: "ambiguous; use the host_id". Run again with the `host_id`.
   - 400: "invalid host name".
2. **Ticket.** `POST /api/v1/ws-ticket` with `{"host_id", "purpose"}`. The purpose is `terminal:open`, or `terminal:root` with `--root` (admin scope). The ticket is single-use and lasts 60 s. It is never printed.
3. **Socket.** sahconnect dials `wss://<origin>/api/v1/systems/terminal/<host_id>?ticket=…&purpose=…&rows=…&cols=…`.
   - TLS 1.3 or newer, with the system CA pool.
   - No proxy and no redirects.
   - Plain `ws://` only for a loopback origin.
   - Metadata and link-local hosts are refused.
   - The socket sends no credential header. The ticket is its authentication.
4. **Raw mode.** When stdin is a terminal, it goes into raw mode. sahconnect restores it on exit, on error, on panic, and on SIGINT, SIGTERM, or SIGHUP. Piped stdin works without raw mode: `echo uptime | sahconnect web1`.
5. **Frames.**
   - stdin goes out as `pty_input` with `data_b64`, in chunks of at most 16 KiB.
   - SIGWINCH goes out as `pty_resize`.
   - stdin EOF goes out as `pty_eof`.
   - Binary frames from the server go to stdout.

### Exit codes

| Exit | When |
| --- | --- |
| The remote shell's status | `pty_exit` with reason `exited` and a code from 0 to 255. |
| 255 | Any other `pty_exit` reason (`max_duration`, `agent_disconnected`, `stopped`), or `exited` with code -1. A message names the reason. |
| 255 | A `pty_status` error. The code and an explanation are printed, for example `recording_unavailable`. |
| 255 | The socket closed before `pty_exit`, the handshake was refused, or TLS failed. |
| 1 | Resolve or ticket refused, or an HTTP failure. |
| 2 | Usage, config, method, URL, or credential problem. |

## Call systemapi

1. **Origin.** `SYSTEMAPI_URL` (or `systemapi_url`) is an origin with no userinfo, query, or path. `https` is required except for `localhost` or a loopback IP, which may use `http`.
2. **Credential.** The precedence in Credentials above.
3. **Call.** `sahconnect api METHOD /path` with an optional `?query`. Methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. The path is absolute ASCII. It contains no `..`, `//`, `\`, `?`, or `#`.
4. **Body and response.** A request body is stdin, at most 256 KiB. The response is copied to stdout, at most 1 MiB.

Query names `api_key`, `access_token`, `token`, and `device_code` are rejected before the request is sent. Redirects are refused. TLS is 1.3 or newer, with system CAs and no environment proxy.

Errors are fixed codes on stderr:

- `invalid_url`
- `invalid_query`
- `key_rejected`
- `token_rejected`
- `credentials_missing`
- `bad_method`
- `bad_path`
- `too_large`
- `redirect_denied`
- `request_failed`
- `response_too_large`

The credential is never part of the text.

## Exec adssh

1. `sahconnect ssh -- ARGS` runs `SAHCONNECT_ADSSH` if set, otherwise `adssh` on `PATH`.
2. Arguments after `--` are the adssh arguments. sahconnect adds none.
3. The exit code is adssh's exit code. A missing binary prints `adssh_missing` and exits 2. A binary that is not a regular executable file is also `adssh_missing`.

## Not yet (later phases)

- **Phase 2.** Fetch and verify the signed connect policy, then choose the method by policy. Until then `ssh` stays refused.
- **Phase 3.** Method B: `adssh` with a pinned host key.

## Next

`sahconnect version`
