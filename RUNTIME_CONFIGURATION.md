# Runtime Configuration

LucidGate can be configured with `lucidgate.toml`, command-line flags, or environment variables. Precedence is: defaults < TOML < environment < flags.

## Options

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--config` | `LUCIDGATE_CONFIG` | `lucidgate.toml` when present | Path to the TOML configuration file. |
| `--listen` | `LUCIDGATE_LISTEN_ADDR` | `127.0.0.1:8080` | Local proxy listen address. |
| `--cert-dir` | `LUCIDGATE_CERT_DIR` | `certs` | Directory for `ca.crt` and `ca.key`. |
| `--max-connections` | `LUCIDGATE_MAX_CONNECTIONS` | `1024` | Maximum concurrent CONNECT tunnels. |
| `--io-timeout` | `LUCIDGATE_IO_TIMEOUT` | `30s` | Per-operation relay read/write timeout. |
| `--dial-timeout` | `LUCIDGATE_DIAL_TIMEOUT` | `10s` | Upstream TCP/uTLS dial timeout. |
| `--handshake-timeout` | `LUCIDGATE_HANDSHAKE_TIMEOUT` | `5s` | Browser-side TLS handshake timeout. |
| `--log-bodies` | `LUCIDGATE_LOG_BODIES` | `true` | Capture request/response bodies to log byte counts. |
| `--max-capture-bytes` | `LUCIDGATE_MAX_CAPTURE_BYTES` | `1048576` | Maximum bytes captured per body. `0` disables body capture. |
| `--dump-dir` | `LUCIDGATE_DUMP_DIR` | empty | Directory to write cleartext request/response dumps in JSONL format. |
| `--dump-on-policy-hit` | `LUCIDGATE_DUMP_ON_POLICY_HIT` | `false` | Only write dumps when a policy blocks or matches audit logs. |
| `--dump-credentials-cleartext` | `LUCIDGATE_DUMP_CREDENTIALS_CLEARTEXT` | `false` | Enable cleartext credentials dumping (authorized forensic environments only, requires `dump_on_policy_hit=true`). |
| `--audit-key` | `LUCIDGATE_AUDIT_KEY` | empty | Secret key for cryptographically hashing sensitive credentials (HMAC-SHA256) for forensic correlation. |
| `--upstream-insecure-skip-verify` | `LUCIDGATE_UPSTREAM_INSECURE_SKIP_VERIFY` | `false` | Skip upstream TLS verification. Lab/smoke only. |
| `--version` | none | `false` | Print version and exit. |

## Local Example

```bash
./build/lucidgate \
  --listen=127.0.0.1:8080 \
  --cert-dir=./certs \
  --max-connections=1024 \
  --io-timeout=30s \
  --dial-timeout=5s \
  --handshake-timeout=5s \
  --log-bodies=true \
  --max-capture-bytes=65536
```

## Environment Example

```bash
export LUCIDGATE_LISTEN_ADDR=127.0.0.1:8080
export LUCIDGATE_CERT_DIR=./certs
export LUCIDGATE_DIAL_TIMEOUT=5s
export LUCIDGATE_HANDSHAKE_TIMEOUT=5s
export LUCIDGATE_LOG_BODIES=true
export LUCIDGATE_MAX_CAPTURE_BYTES=65536

./build/lucidgate
```

## Systemd Package Defaults

The Debian package installs a systemd unit that runs:

```text
/usr/bin/lucidgate --listen=127.0.0.1:8080 --cert-dir=/var/lib/lucidgate/certs --max-capture-bytes=1048576
```

Generated CA material is stored under:

```text
/var/lib/lucidgate/certs/
```

## Security Notes

- Keep `ca.key` private.
- Import only `ca.crt` into the browser/client trust store.
- `--upstream-insecure-skip-verify` is intended only for local smoke tests and controlled lab upstreams.
- Body logging can retain sensitive data in memory and logs. Use `--log-bodies=false` or `--max-capture-bytes=0` when byte-level inspection is not needed.
- **Forensic Attribution & Privacy:** By default, credentials (passwords, JWTs, HTTP authorization headers, cookies) are replaced with `[REDACTED]` or `[REDACTED:HMAC-...]` in log dumps to prevent credential theft.
- **HMAC Correlation:** Setting `--audit-key` enables secure forensic correlation by replacing credentials with `HMAC-SHA256(audit_key, secret)`, allowing you to verify matching credentials across transactions without exposing the cleartext secrets.
- **Cleartext Mode:** Setting `--dump-credentials-cleartext=true` is a highly sensitive setting that dumps credentials in cleartext. It is strictly disabled by default, requires `--dump-on-policy-hit=true` to prevent indiscriminate dumping, prints a loud warning at startup, sets restrictive permissions on logs (`0600` for files, `0700` for directories), and labels logs with `"contains_cleartext_credentials": true`. Only enable this mode in fully authorized forensic environments.

## Smoke Test Configuration

`make smoke` runs the built binary with dynamic loopback ports and a temporary CA directory. It uses:

```text
--upstream-insecure-skip-verify
```

only because the smoke upstream uses a throwaway self-signed certificate.

Legacy `CLEARGATE_*` environment variables are still accepted during the rename window, but new deployments should use `LUCIDGATE_*`.
