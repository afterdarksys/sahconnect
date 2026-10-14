# AGENTS.md

sahconnect is the SSH and systemapi client. `<host>`/`connect` opens a shell through SystemAPI's agent PTY (terminal protocol: `~/development/systemapi.io/docs/sahconnect-terminal-protocol.md`). `login` is the OAuth device flow against `controlplane/oauth.js`. `ssh` execs `adssh`. `api` calls systemapi over HTTP.

Usage: `docs/usage.md`. Suite contract: `~/development/systemapi.io/docs/sah-suite.md`.

## Do this

1. Read `docs/usage.md` before changing a flag or an environment variable.
2. A change to URL checks, credential headers, the token file, the ticket, or redirects includes a negative test that the error text does not contain the secret. Done when `go test ./...` reports ok.
3. A change to the terminal frames changes the protocol doc and the systemapi server in the same change. The protocol doc wins.

## Rules

- Send one credential per request: the token file as `Authorization: Bearer`, else `SYSTEMAPI_API_KEY` as `X-API-Key`. A query parameter leaks into logs and Referer headers. The terminal ticket is the only query secret. Error strings do not contain a key, token, ticket, or the terminal URL.
- The token file is versioned JSON holding the issuing origin and the token, 0600 in a 0700 directory you own, written by temp file plus rename. Send the bearer only to its origin. A token file that is unsafe or invalid is an error, never a silent fallback to the key. Replace or delete only a valid token file. Print only its SHA-256 fingerprint.
- Open trusted files with O_NOFOLLOW and check the open descriptor (`internal/secfile`). Every dial goes through `client.DialGuard`.
- A config file that is a symlink, owned by another user, or group- or world-writable is refused. It holds no secret.
- Accept `http` and `ws` only for `localhost` or a loopback IP. `https` and `wss` use the system CA pool and TLS 1.3 or newer. Leave `InsecureSkipVerify` unset. Set `Proxy` to nil so the process environment cannot redirect the call. Refuse redirects.
- Restore the local tty on every exit path: return, error, panic, and signal.
- Phase 1 runs only Method A (agent). Do not fall back to ssh because agent failed. That downgrade needs the signed policy (phase 2).
- Reject query names `api_key`, `access_token`, `token`, and `device_code` before sending.
- `ssh` execs `SAHCONNECT_ADSSH` or `adssh` and passes the operator's arguments through. Do not embed an SSH implementation. A second stack would skip adssh policy.
- Device login is a client of `controlplane/oauth.js`. Do not add an OAuth server or IdP code here.

## Next

`go test ./...`
