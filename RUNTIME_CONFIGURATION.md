# Runtime Configuration

LucidGate can be configured with `lucidgate.toml`, command-line flags, or environment variables. Precedence is: **defaults < TOML < environment < flags**. Runtime-mutable options (relay timeouts, dump settings, rules, semantic/masking/substitution filters, MITM bypass list, per-profile QoS, breaker/DNS settings) are reloaded on `SIGHUP` via `atomic.Value` snapshots without locks on the hot path.

## Flags and Environment Variables

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--config` | `LUCIDGATE_CONFIG` | `lucidgate.toml` when present | Path to the TOML configuration file. |
| `--listen` | `LUCIDGATE_LISTEN_ADDR` | `127.0.0.1:8080` | Local proxy listen address. |
| `--cert-dir` | `LUCIDGATE_CERT_DIR` | `certs` | Directory for `ca.crt` and `ca.key`. |
| `--max-connections` | `LUCIDGATE_MAX_CONNECTIONS` | `1024` | Maximum concurrent CONNECT tunnels (global semaphore). |
| `--wait-timeout` | `LUCIDGATE_WAIT_TIMEOUT` | `250ms` | Admission queue wait timeout before returning `503`. `0` = instant 503 on saturation. |
| `--io-timeout` | `LUCIDGATE_IO_TIMEOUT` | `30s` | Per-operation relay read/write timeout. |
| `--ws-idle-timeout` | `LUCIDGATE_WS_IDLE_TIMEOUT` | `5m` | Per-direction idle timeout for raw WebSocket sessions after Upgrade. |
| `--dial-timeout` | `LUCIDGATE_DIAL_TIMEOUT` | `10s` | Upstream TCP/uTLS dial timeout. |
| `--upstream-max-idle-conns-per-host` | `LUCIDGATE_UPSTREAM_MAX_IDLE_CONNS_PER_HOST` | `32` | Maximum idle upstream keep-alive connections per destination; `0` disables pooling. |
| `--upstream-idle-timeout` | `LUCIDGATE_UPSTREAM_IDLE_TIMEOUT` | `90s` | Maximum time an idle upstream keep-alive connection stays pooled. |
| `--handshake-timeout` | `LUCIDGATE_HANDSHAKE_TIMEOUT` | `5s` | Local TLS handshake timeout. |
| `--cert-workers` | `LUCIDGATE_CERT_WORKERS` | `runtime.NumCPU()` | Background workers that pre-generate MITM leaf certificates. |
| `--mitm-prewarm-hosts` | `LUCIDGATE_MITM_PREWARM_HOSTS` | empty | Comma-separated popular hostnames to pre-generate MITM leaf certificates for. |
| — | `LUCIDGATE_MITM_BYPASS_HOSTS` | empty | Comma-separated hosts that bypass TLS interception (zero-copy CONNECT tunnel). Same as `[mitm].bypass_hosts`. Wildcards `*.example.com` supported. |
| `--reuseport` | `LUCIDGATE_REUSEPORT` | `false` | Enable `SO_REUSEPORT` with `GOMAXPROCS` concurrent listeners (Linux/UNIX only). |
| `--http3-enabled` | `LUCIDGATE_HTTP3_ENABLED` | `false` | Enable concurrent HTTP/3 (QUIC) downstream listener on the same UDP port. |
| `--circuit-breaker-enabled` | `LUCIDGATE_CIRCUIT_BREAKER_ENABLED` | `true` | Enable per-host upstream circuit breaker. |
| `--circuit-breaker-failures` | `LUCIDGATE_CIRCUIT_BREAKER_FAILURES` | `5` | Consecutive failures before tripping the breaker open. |
| `--circuit-breaker-timeout` | `LUCIDGATE_CIRCUIT_BREAKER_TIMEOUT` | `30s` | Open-state duration before transitioning to half-open. |
| `--dns-cache-enabled` | `LUCIDGATE_DNS_CACHE_ENABLED` | `true` | Enable internal TTL-cached DNS resolver. |
| `--dns-cache-ttl` | `LUCIDGATE_DNS_CACHE_TTL` | `60s` | TTL for cached DNS records. |
| `--tracing-enabled` | `LUCIDGATE_TRACING_ENABLED` | `false` | Enable OpenTelemetry distributed tracing. |
| `--tracing-endpoint` | `LUCIDGATE_TRACING_ENDPOINT` | `localhost:4317` | OTLP gRPC collector endpoint. |
| `--tracing-insecure` | `LUCIDGATE_TRACING_INSECURE` | `true` | Use insecure (plaintext) gRPC against the OTLP collector. |
| `--tracing-service-name` | `LUCIDGATE_TRACING_SERVICE_NAME` | `lucidgate` | `service.name` attribute. |
| `--tracing-sample-rate` | `LUCIDGATE_TRACING_SAMPLE_RATE` | `1.0` | Trace sample rate (`0.0`–`1.0`). |
| `--log-bodies` | `LUCIDGATE_LOG_BODIES` | `true` | Capture request/response bodies to log byte counts. |
| — | `LUCIDGATE_LOG_BODIES_SAMPLE_RATE` | `1.0` | Probability (`0.0`–`1.0`) of sampling an exchange for body byte counting. |
| `--max-capture-bytes` | `LUCIDGATE_MAX_CAPTURE_BYTES` | `1048576` | Maximum bytes captured per body. `0` disables body capture. |
| `--dump-dir` | `LUCIDGATE_DUMP_DIR` | empty | Directory for cleartext request/response dumps in JSONL format. |
| `--dump-on-policy-hit` | `LUCIDGATE_DUMP_ON_POLICY_HIT` | `false` | Only write dumps when a policy blocks or matches audit logs. |
| `--dump-credentials-cleartext` | `LUCIDGATE_DUMP_CREDENTIALS_CLEARTEXT` | `false` | Enable cleartext credentials dumping (forensic environments only; requires `dump_on_policy_hit=true`). |
| `--audit-key` | `LUCIDGATE_AUDIT_KEY` | empty | Secret key for HMAC-SHA256 hashing of credentials. |
| `--dump-max-size-mb` | `LUCIDGATE_DUMP_MAX_SIZE_MB` | `100` | Maximum size of a single dump file (MB) before rotation. |
| `--dump-max-backups` | `LUCIDGATE_DUMP_MAX_BACKUPS` | `10` | Maximum rotated dump backups to keep. |
| `--dump-min-free-space-mb` | `LUCIDGATE_DUMP_MIN_FREE_SPACE_MB` | `1024` | Minimum free disk space (MB) before skipping dumps with a warning. |
| `--dump-compress` | `LUCIDGATE_DUMP_COMPRESS` | `true` | Compress rotated dump files with gzip. |
| — | `LUCIDGATE_METRICS_ENABLED` | `false` | Mount Prometheus `/metrics` on the admin server. |
| — | `LUCIDGATE_METRICS_LISTEN_ADDR` | `127.0.0.1:6060` | Admin server listen address (`/metrics`, `/debug/pprof`, `/livez`, `/readyz`). |
| `--upstream-insecure-skip-verify` | `LUCIDGATE_UPSTREAM_INSECURE_SKIP_VERIFY` | `false` | Skip upstream TLS verification. Lab/smoke only. |
| `--version` | none | `false` | Print version and exit. |

Antivirus settings (`[antivirus]` section) have no CLI flags and are read from TOML or `LUCIDGATE_ANTIVIRUS_ENABLED`, `LUCIDGATE_ANTIVIRUS_CLAMAV_ADDR`, `LUCIDGATE_ANTIVIRUS_TEMP_DIR`, `LUCIDGATE_ANTIVIRUS_TRICKLE_INTERVAL`, `LUCIDGATE_ANTIVIRUS_SCAN_TIMEOUT`.

Legacy `CLEARGATE_*` environment variables are still accepted during the rename window; new deployments should use `LUCIDGATE_*`.

## Hot Reload (SIGHUP)

Re-read `lucidgate.toml` and publish a new immutable snapshot for the relay options, rule lists, semantic/masking/substitution filters, MITM bypass list, per-profile QoS, breaker/DNS cache settings, and dump rotation parameters:

```bash
kill -HUP "$(pgrep -f lucidgate)"
```

The `/readyz` probe returns `503` while the reload is in progress. Options that change listener bindings (`listen_addr`, `cert_dir`, `http3_enabled`, `reuseport`) require a process restart or a `SIGUSR2` hot upgrade.

## Hot Restart (SIGUSR2)

Replace the binary at its installed path and send `SIGUSR2`. `cloudflare/tableflip` re-execs the process inheriting listening sockets without dropping new connections; in-flight CONNECT/WebSocket tunnels are drained with a 30 s grace timeout before the old process exits:

```bash
kill -USR2 "$(pgrep -f lucidgate)"
```

## Local Example

```bash
./build/lucidgate \
  --listen=127.0.0.1:8080 \
  --cert-dir=./certs \
  --max-connections=2048 \
  --wait-timeout=250ms \
  --io-timeout=30s \
  --dial-timeout=5s \
  --handshake-timeout=5s \
  --cert-workers=4 \
  --reuseport \
  --http3-enabled \
  --circuit-breaker-enabled \
  --dns-cache-enabled \
  --log-bodies=true \
  --max-capture-bytes=65536
```

## Environment Example

```bash
export LUCIDGATE_LISTEN_ADDR=127.0.0.1:8080
export LUCIDGATE_CERT_DIR=./certs
export LUCIDGATE_DIAL_TIMEOUT=5s
export LUCIDGATE_HANDSHAKE_TIMEOUT=5s
export LUCIDGATE_MITM_BYPASS_HOSTS="*.bbva.es,*.icloud.com"
export LUCIDGATE_METRICS_ENABLED=true
export LUCIDGATE_TRACING_ENABLED=true
export LUCIDGATE_TRACING_ENDPOINT=otel-collector:4317

./build/lucidgate
```

## Systemd Package Defaults

The Debian package installs a systemd unit that runs:

```text
/usr/bin/lucidgate --listen=127.0.0.1:8080 --cert-dir=/var/lib/lucidgate/certs --max-capture-bytes=1048576
```

Generated CA material is stored under `/var/lib/lucidgate/certs/`.

## Admin Server

The admin server is loopback-only by default and exposes:

- `/livez` — liveness probe (always `200 OK`).
- `/readyz` — readiness probe (`503` during reload, shutdown, or saturation).
- `/debug/pprof/*` — Go pprof endpoints.
- `/metrics` — Prometheus exposition (when `[metrics].enabled = true`).

## Security Notes

- Keep `ca.key` private. Import only `ca.crt` into the browser/client trust store.
- `--upstream-insecure-skip-verify` is intended only for local smoke tests and controlled lab upstreams.
- Body logging can retain sensitive data in memory and logs. Use `--log-bodies=false` or `--max-capture-bytes=0` when byte-level inspection is not needed.
- **Forensic Attribution & Privacy:** By default, credentials (passwords, JWTs, HTTP authorization headers, cookies) are replaced with `[REDACTED]` or `[REDACTED:HMAC-...]` in log dumps.
- **HMAC Correlation:** Setting `--audit-key` enables secure forensic correlation by replacing credentials with `HMAC-SHA256(audit_key, secret)` without exposing cleartext.
- **Cleartext Credentials Mode:** `--dump-credentials-cleartext=true` is highly sensitive: disabled by default, requires `--dump-on-policy-hit=true`, prints a loud warning at startup, sets restrictive permissions on logs (`0600` files, `0700` dirs), and labels logs with `"contains_cleartext_credentials": true`. Only enable in fully authorized forensic environments.
- **MITM Bypass:** Hosts listed in `[mitm].bypass_hosts` skip TLS termination and all content filters. Domain-level policy (bans, schedules, access profiles) still applies on the CONNECT target.

## Smoke Test Configuration

`make smoke` runs the built binary with dynamic loopback ports and a temporary CA directory. It uses `--upstream-insecure-skip-verify` only because the smoke upstream uses a throwaway self-signed certificate.
