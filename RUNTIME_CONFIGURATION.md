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

## Smoke Test Configuration

`make smoke` runs the built binary with dynamic loopback ports and a temporary CA directory. It uses:

```text
--upstream-insecure-skip-verify
```

only because the smoke upstream uses a throwaway self-signed certificate.

Legacy `CLEARGATE_*` environment variables are still accepted during the rename window, but new deployments should use `LUCIDGATE_*`.
