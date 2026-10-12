# AGENTS.md

sahconnect is the SSH and systemapi client. `ssh` execs `adssh`. `api` calls systemapi over HTTP.

Usage: `docs/usage.md`. Suite contract: `~/development/systemapi.io/docs/sah-suite.md`.

## Do this

1. Read `docs/usage.md` before changing a flag or an environment variable.
2. A change to URL checks, the API key header, or redirects includes a negative test that the error text does not contain the key. Done when `go test ./...` reports ok.

## Rules

- Send `SYSTEMAPI_API_KEY` as `X-API-Key` only. A query parameter leaks into logs and Referer headers. Error strings stay fixed codes and do not contain the key.
- Accept `http` only for `localhost` or a loopback IP. `https` uses the system CA pool and TLS 1.3 or newer. Leave `InsecureSkipVerify` unset. Set `Proxy` to nil so the process environment cannot redirect the call. Refuse redirects.
- Reject query names `api_key`, `access_token`, `token`, and `device_code` before sending.
- `ssh` execs `SAHCONNECT_ADSSH` or `adssh` and passes the operator's arguments through. Do not embed an SSH implementation. A second stack would skip adssh policy.
- Do not add device login here. That flow is the systemapi CLI and `controlplane/oauth.js`.

## Next

`go test ./...`
