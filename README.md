# sahconnect

SSH and systemapi client.

**sah** means Service Automation Hub. The hub encompasses the platform and the suite of utilities.

`sahconnect api` calls the operator's systemapi. `sahconnect ssh` execs the `adssh` binary. This module does not embed an SSH stack and it is not an exploit tool.

```bash
go install ./cmd/sahconnect
export SYSTEMAPI_URL=https://systemapi.example
export SYSTEMAPI_API_KEY=...
sahconnect api GET /api/v1/fleet
sahconnect ssh -- version
```

The API key is sent as `X-API-Key` and is not printed. Plain `http` is accepted only for loopback.

Usage: `docs/usage.md`. Suite contract: `~/development/systemapi.io/docs/sah-suite.md`.

## Next

`go test ./...`
