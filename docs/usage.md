# sahconnect usage

Module `github.com/afterdarksys/sahconnect`. Version 0.1.0.

## Call systemapi

1. Set `SYSTEMAPI_URL` to an origin with no userinfo, query, or path. `https` is required except for `localhost` or a loopback IP, which may use `http`.
2. Set `SYSTEMAPI_API_KEY`. The key is sent only as `X-API-Key`.
3. `sahconnect api METHOD /path` with optional `?query`. Methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. The path is absolute, ASCII, and contains no `..`, `//`, `\`, `?`, or `#`.
4. A request body is stdin, at most 256 KiB. The response is copied to stdout, at most 1 MiB.

Query names `api_key`, `access_token`, `token`, and `device_code` are rejected before the request is sent. Redirects are refused. TLS is 1.3 or newer, system CAs, no environment proxy.

Errors are fixed codes on stderr (`invalid_url`, `invalid_query`, `key_rejected`, `bad_method`, `bad_path`, `too_large`, `redirect_denied`, `request_failed`, `response_too_large`). The key is not part of the text.

This command does not read a token file and it does not perform device login. Device login stays the systemapi CLI.

## Exec adssh

1. `sahconnect ssh -- ARGS` runs `SAHCONNECT_ADSSH` if set, otherwise `adssh` on `PATH`.
2. Arguments after `--` are the adssh arguments. sahconnect adds none.
3. The exit code is adssh's exit code. A missing binary prints `adssh_missing` and exits 2. A binary that is not a regular executable file is `adssh_missing`.

## Next

`sahconnect version`
