# LucidGate

LucidGate is a local HTTPS interception proxy for controlled blue-team analysis and policy enforcement. It terminates browser TLS locally with dynamically generated certificates, connects upstream with a Firefox-like uTLS ClientHello, and relays HTTP bodies with bounded streaming inspection.

Use it only on systems and traffic you own or are explicitly authorized to inspect.

## What It Does

- Local HTTPS proxy, default `127.0.0.1:8080`.
- Local root CA generation under `certs/`.
- Per-host leaf certificates signed by the local CA.
- CONNECT hijacking and browser-side TLS termination.
- Upstream TLS dialing via `github.com/refraction-networking/utls`.
- Header sanitization for `Proxy-Connection`, `X-Forwarded-For`, `Via`, and `X-Real-IP`.
- Streaming request/response relay using pooled 32 KiB buffers.
- Per-operation network deadlines and configurable concurrent connection limit.
- Hot reload on `SIGHUP` using immutable rules published through `atomic.Value`.
- Domain fast-fail before hijack/upstream dial.
- Client access profiles by CIDR.
- Per-profile schedule windows.
- HTML block pages for fast-fail decisions.
- Semantic response filtering with Aho-Corasick.
- Textual gzip/deflate/br response decompression, inspection, and recompression.
- Weighted phrase scoring with stream-local accumulated score.
- Basic HTML visible-text tokenization for semantic filtering.
- Text masking for non-HTML textual responses.
- Phrase substitution for textual responses.
- Literal and regex request-body substitution for mutable uploads, with safety validation for broad request regexes.
- HTML banner injection before `</body>`.
- Streaming textual upload inspection for `POST`, `PUT`, and `PATCH`.
- Bypass for binary, multipart, request-compressed, and unsupported response-compressed payloads.
- Optional bounded JSONL body dump for offline analysis.
- External e2guardian-style phrase, masking, and substitution lists with `.Include<...>` recursion and per-file/line error reporting.
- Per-host MITM bypass list (`mitm.bypass_hosts`) for HSTS-pinned/banking/mTLS sites, with `*.example.com` wildcards and zero-copy `splice(2)` tunneling.
- Target-aware audit scope: classify traffic as `root`, `dependency`, or `none` from configured domains and propagate scope through `Referer`/`Origin`.
- Optional HTTP/3 (QUIC) downstream listener via `quic-go/http3` with dynamic MITM leaf certificates.
- Per-host upstream circuit breaker (`sony/gobreaker`), TTL-cached internal DNS resolver, `SO_REUSEPORT` multi-listener mode, and zero-downtime hot restart via `cloudflare/tableflip` (`SIGUSR2`).
- Per-profile concurrency cap (`max_conns`) and per-client-IP token-bucket rate limiting (`rate_limit`/`rate_burst`).
- OpenTelemetry distributed tracing of every exchange (parent span + dial/handshake/request/response children) via OTLP gRPC; noop fallback with zero cost when disabled.
- Liveness/readiness probes (`/livez`, `/readyz`) and Prometheus rejection counters by reason on the loopback admin server.
- Dump rotation, gzip compression, and disk-space-aware skipping for forensic JSONL files.

## Security Notes

LucidGate performs HTTPS interception. The generated `ca.key` is a sensitive private key. If it leaks, any host that trusts the matching `ca.crt` can be impersonated.

- Import only `ca.crt` into clients.
- Never share or commit `ca.key`.
- Use `upstream.insecure_skip_verify = true` only for local smoke tests or lab upstreams.
- Body dumps can contain credentials, tokens, and private content. Keep `dump_dir` protected and disable dumps when not needed.

## Requirements

- Go 1.25 or newer.
- GNU Make.
- `openssl` for CA inspection.
- `dpkg-deb` only if building Debian packages.
- A browser or client configured to use LucidGate as an HTTPS proxy.

## Quick Start

```bash
make build
./build/lucidgate --config lucidgate.toml
```

On first start, LucidGate creates:

```text
certs/ca.crt
certs/ca.key
```

Import `certs/ca.crt` into the browser/client trust store, then configure the client to use:

```text
HTTPS proxy: 127.0.0.1
Port:        8080
```

For Firefox: Settings -> Network Settings -> Manual proxy configuration. Import the CA under Settings -> Privacy & Security -> Certificates -> Authorities.

## Configuration Model

Configuration precedence is:

```text
defaults < lucidgate.toml < environment < flags
```

LucidGate automatically loads `lucidgate.toml` from the working directory if present. You can override it:

```bash
./build/lucidgate --config /path/to/lucidgate.toml
```

Runtime options that affect relay/rules are reloaded on `SIGHUP`:

```bash
kill -HUP "$(pgrep -f 'lucidgate')"
```

Legacy `CLEARGATE_*` environment variables are still accepted during the rename window, but new deployments should use `LUCIDGATE_*`.

## Full TOML Example

```toml
[server]
listen_addr = "127.0.0.1:8080"
cert_dir = "certs"
handshake_timeout = "5s"
max_connections = 1024
io_timeout = "30s"
ws_idle_timeout = "5m"

[upstream]
dial_timeout = "10s"
max_idle_conns_per_host = 32
idle_timeout = "90s"
insecure_skip_verify = false

[mitm]
prewarm_hosts = ["www.google.com", "www.gstatic.com"]
bypass_hosts = [
  "claude.ai",
  "*.claude.ai",
]

[logging]
log_bodies = true
max_capture_bytes = 1048576
dump_dir = ""

[metrics]
enabled = true
listen_addr = "127.0.0.1:6060"

[rules]
# Plain domain blocklists. Directories or single files are accepted; entries
# are read in alphabetical order. Lines starting with '#' are comments.
include_dir = ["rules.d", "lists/sites"]

[[access.profile]]
name = "default"
default = true
clients = ["127.0.0.1/32", "::1/128"]

[[schedule.window]]
profile = "default"
days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
start = "00:00"
end = "24:00"

[semantic]
blocked_phrases = ["blocked phrase"]
score_threshold = 100
# External e2guardian-style lists. Embedded entries above are merged with
# the contents of these files. See "External Phrase Lists" below.
blocked_phrase_lists   = ["lists/phraselists/bannedphraselist"]
weighted_phrase_lists  = ["lists/phraselists/weightedphraselist"]
exception_phrase_lists = ["lists/phraselists/exceptionphraselist"]

[[semantic.weighted_phrase]]
phrase = "malware"
weight = 20

[[semantic.weighted_phrase]]
phrase = "credential dump"
weight = 80

[masking]
phrases      = ["secret token"]
phrase_lists = ["lists/masking/maskedphraselist"]

[substitution]
rule_lists = ["lists/substitution/substitutionlist"]

[[substitution.rule]]
search = "internal codename"
replace = "public project"

[request_substitution]
rule_lists = ["lists/substitution/requestsubstitutionlist"]
regex_rule_lists = ["lists/substitution/requestregexsubstitutionlist"]

[audit_scope]
enabled = true
mode = "target_aware"
roots = []
root_domain_lists = ["lists/audit/targetdomainslist"]
dependency_ttl = "30m"
max_dependencies = 8192
none_mode = "tunnel"
dependency_mutations = "restricted"
discover_html = true
discover_css = true
discover_js = true

[injection]
html_banner = "<div style=\"position:fixed;left:0;right:0;bottom:0;z-index:2147483647;background:#111827;color:#fff;padding:8px 12px;font:14px sans-serif;text-align:center\">LucidGate inspected this page</div>"
```

## Flags And Environment

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--config` | `LUCIDGATE_CONFIG` | `lucidgate.toml` when present | TOML configuration path. |
| `--listen` | `LUCIDGATE_LISTEN_ADDR` | `127.0.0.1:8080` | Local proxy listen address. |
| `--cert-dir` | `LUCIDGATE_CERT_DIR` | `certs` | Directory for `ca.crt` and `ca.key`. |
| `--max-connections` | `LUCIDGATE_MAX_CONNECTIONS` | `1024` | Maximum concurrent CONNECT tunnels. |
| `--wait-timeout` | `LUCIDGATE_WAIT_TIMEOUT` | `250ms` | Connection admission queue wait timeout before returning `503`. `0` disables waiting (instant 503 on saturation). |
| `--io-timeout` | `LUCIDGATE_IO_TIMEOUT` | `30s` | Per-operation relay read/write timeout. |
| `--ws-idle-timeout` | `LUCIDGATE_WS_IDLE_TIMEOUT` | `5m` | Per-direction idle timeout for raw WebSocket sessions after a successful Upgrade. |
| `--dial-timeout` | `LUCIDGATE_DIAL_TIMEOUT` | `10s` | Upstream TCP/uTLS dial timeout. |
| `--upstream-max-idle-conns-per-host` | `LUCIDGATE_UPSTREAM_MAX_IDLE_CONNS_PER_HOST` | `32` | Maximum idle upstream keep-alive connections per destination; `0` disables pooling. |
| `--upstream-idle-timeout` | `LUCIDGATE_UPSTREAM_IDLE_TIMEOUT` | `90s` | Maximum time an idle upstream keep-alive connection stays pooled. |
| `--handshake-timeout` | `LUCIDGATE_HANDSHAKE_TIMEOUT` | `5s` | Browser-side TLS handshake timeout. |
| `--cert-workers` | `LUCIDGATE_CERT_WORKERS` | `runtime.NumCPU()` | Background workers that pre-generate MITM leaf certificates outside the hot handshake path. |
| `--mitm-prewarm-hosts` | `LUCIDGATE_MITM_PREWARM_HOSTS` | empty | Comma-separated popular hostnames to pre-generate MITM leaf certificates for. |
| — | `LUCIDGATE_MITM_BYPASS_HOSTS` | empty | Comma-separated hostnames (supports `*.example.com`) that bypass TLS interception and tunnel CONNECT with zero-copy `splice(2)`. Same as `[mitm].bypass_hosts` in TOML. |
| `--reuseport` | `LUCIDGATE_REUSEPORT` | `false` | Enable `SO_REUSEPORT` with `GOMAXPROCS` concurrent listeners (Linux/UNIX only). |
| `--http3-enabled` | `LUCIDGATE_HTTP3_ENABLED` | `false` | Enable concurrent HTTP/3 (QUIC) downstream listener on the same UDP port. |
| `--circuit-breaker-enabled` | `LUCIDGATE_CIRCUIT_BREAKER_ENABLED` | `true` | Enable per-host upstream circuit breaker. |
| `--circuit-breaker-failures` | `LUCIDGATE_CIRCUIT_BREAKER_FAILURES` | `5` | Consecutive failures before tripping the breaker open. |
| `--circuit-breaker-timeout` | `LUCIDGATE_CIRCUIT_BREAKER_TIMEOUT` | `30s` | Time the breaker stays open before transitioning to half-open. |
| `--dns-cache-enabled` | `LUCIDGATE_DNS_CACHE_ENABLED` | `true` | Enable internal TTL-cached DNS resolver. |
| `--dns-cache-ttl` | `LUCIDGATE_DNS_CACHE_TTL` | `60s` | TTL for cached DNS records. |
| `--tracing-enabled` | `LUCIDGATE_TRACING_ENABLED` | `false` | Enable OpenTelemetry distributed tracing of every exchange. |
| `--tracing-endpoint` | `LUCIDGATE_TRACING_ENDPOINT` | `localhost:4317` | OTLP gRPC collector endpoint (`host:port`). |
| `--tracing-insecure` | `LUCIDGATE_TRACING_INSECURE` | `true` | Use insecure (plaintext) gRPC against the OTLP collector. |
| `--tracing-service-name` | `LUCIDGATE_TRACING_SERVICE_NAME` | `lucidgate` | `service.name` attribute reported to the collector. |
| `--tracing-sample-rate` | `LUCIDGATE_TRACING_SAMPLE_RATE` | `1.0` | Trace sample rate (`0.0` disables exports while keeping context propagation). |
| `--log-bodies` | `LUCIDGATE_LOG_BODIES` | `true` | Enable byte-count body capture behavior. |
| — | `LUCIDGATE_LOG_BODIES_SAMPLE_RATE` | `1.0` | Probability (`0.0`–`1.0`) that an exchange is sampled for body byte counting. |
| `--max-capture-bytes` | `LUCIDGATE_MAX_CAPTURE_BYTES` | `1048576` | Maximum bytes captured per body; `0` disables capture. |
| `--dump-dir` | `LUCIDGATE_DUMP_DIR` | empty | Write bounded JSONL cleartext dumps when non-empty. |
| `--dump-on-policy-hit` | `LUCIDGATE_DUMP_ON_POLICY_HIT` | `false` | If true, only write body dumps to `dump-dir` when a policy blocks or matches audit logs. |
| `--dump-credentials-cleartext` | `LUCIDGATE_DUMP_CREDENTIALS_CLEARTEXT` | `false` | Enable cleartext credentials dumping (authorized environments only, requires `dump_on_policy_hit=true`). |
| `--audit-key` | `LUCIDGATE_AUDIT_KEY` | empty | Secret key for cryptographically hashing sensitive credentials (HMAC-SHA256) for forensic correlation. |
| `--dump-max-size-mb` | `LUCIDGATE_DUMP_MAX_SIZE_MB` | `100` | Maximum size of a single dump file (MB) before rotation. |
| `--dump-max-backups` | `LUCIDGATE_DUMP_MAX_BACKUPS` | `10` | Maximum rotated dump backups to keep. |
| `--dump-min-free-space-mb` | `LUCIDGATE_DUMP_MIN_FREE_SPACE_MB` | `1024` | Minimum free disk space (MB) before skipping payload dumps with a `low disk space` warning. |
| `--dump-compress` | `LUCIDGATE_DUMP_COMPRESS` | `true` | Compress rotated dump files with gzip in background. |
| — | `LUCIDGATE_METRICS_ENABLED` | `false` | Mount Prometheus `/metrics` on the admin server. Same as `[metrics].enabled` in TOML. |
| — | `LUCIDGATE_METRICS_LISTEN_ADDR` | `127.0.0.1:6060` | Admin server listen address (`/metrics`, `/debug/pprof`, `/livez`, `/readyz`). |
| `--upstream-insecure-skip-verify` | `LUCIDGATE_UPSTREAM_INSECURE_SKIP_VERIFY` | `false` | Skip upstream TLS verification. Lab/smoke only. |
| `--version` | none | `false` | Print version and exit. |

Target-aware audit scope is configured primarily through `[audit_scope]` in TOML. The supported environment overrides are `LUCIDGATE_AUDIT_SCOPE_ENABLED`, `LUCIDGATE_AUDIT_SCOPE_ROOTS`, `LUCIDGATE_AUDIT_SCOPE_DEPENDENCY_TTL`, `LUCIDGATE_AUDIT_SCOPE_MAX_DEPENDENCIES`, `LUCIDGATE_AUDIT_SCOPE_NONE_MODE`, and `LUCIDGATE_AUDIT_SCOPE_DEPENDENCY_MUTATIONS`.

The antivirus subsystem is configured exclusively via `[antivirus]` in TOML (`enabled`, `clamav_addr`, `temp_dir`, `trickle_interval`, `scan_timeout`) or matching `LUCIDGATE_ANTIVIRUS_*` environment variables. There are no command-line flags for antivirus.

## Observability

The admin server is loopback-only by default. `pprof` is always mounted under `127.0.0.1:6060/debug/pprof/`; Prometheus metrics are mounted at `/metrics` when enabled:

```toml
[metrics]
enabled = true
listen_addr = "127.0.0.1:6060"
```

```bash
curl http://127.0.0.1:6060/metrics
```

Useful LucidGate metrics:

- `lucidgate_active_connections`
- `lucidgate_bytes_total{direction="in|out"}`
- `lucidgate_connections_rejected_total{reason="max_connections|wait_timeout|rate_limit|profile_saturated|access_denied|schedule_denied|circuit_open"}`
- `lucidgate_cert_cache_requests_total`
- `lucidgate_cert_cache_hits_total`
- `lucidgate_cert_generation_duration_seconds`
- `lucidgate_rule_hits_total{profile,policy_list,action="block|log"}`
- `lucidgate_inspection_duration_seconds`
- `lucidgate_tls_handshake_duration_seconds{direction="downstream"}`
- `lucidgate_alt_svc_stripped_total`
- `lucidgate_websocket_sessions_total{result="opened|denied|error|upstream_refused"}`
- `lucidgate_websocket_bytes_total{direction="in|out"}`

The Prometheus Go/process collectors are also available from the same endpoint. Use `go_goroutines`, `process_open_fds`, and `process_max_fds` while running connection-load tests.

The admin server also exposes:

- `GET /livez` — liveness probe, always `200 OK` while the process is alive.
- `GET /readyz` — readiness probe. Returns `503 Service Unavailable` while a `SIGHUP` reload is in progress, during shutdown, or when the global connection semaphore is saturated; `200 OK` otherwise.
- `GET /debug/pprof/*` — standard Go pprof endpoints.

## Advanced Operations

### MITM Bypass (HSTS-pinned, banking, mTLS apps)

Some hosts (banks, government portals, apps with certificate pinning) reject the locally-generated leaf certificate and will not work through a MITM proxy. Add them to `[mitm].bypass_hosts` to tunnel CONNECT verbatim with zero-copy `splice(2)` instead of terminating TLS locally:

```toml
[mitm]
bypass_hosts = [
  "*.bancosantander.es",
  "*.bbva.es",
  "agenciatributaria.gob.es",
  "*.icloud.com",
]
```

Bypassed hosts skip TLS termination and all content filters (semantic, masking, substitution, antivirus). Domain-level policy (`bannedsitelist`, access profiles, schedules) still applies because they are evaluated against the CONNECT target before bypass takes effect. Wildcards (`*.example.com`) match the apex domain and every subdomain.

Current `lucidgate.toml` uses a minimal compatibility tunnel for:

```toml
[mitm]
bypass_hosts = [
  "claude.ai",
  "*.claude.ai",
]
```

This is intentionally narrow. Firefox traffic showed that Claude's `edge-api/bootstrap/.../app_start` endpoint returns `500` under TLS/HTTP re-emission even when filters and request substitutions are disabled. Keeping only `claude.ai` in the tunnel avoids breaking Claude while leaving Anthropic auxiliary hosts such as `api.anthropic.com`, `a-api.anthropic.com`, `assets-proxy.anthropic.com`, `a-cdn.anthropic.com`, and `s-cdn.anthropic.com` inspectable.

### Target-Aware Audit Scope

Target-aware audit scope narrows LucidGate's active inspection to explicitly declared roots and the dependencies reached from those roots. This is intended for blue-team audits of a specific web app without building fragile combinations of global allow, exception, log, nolog, and substitution lists.

```toml
[audit_scope]
enabled = true
mode = "target_aware"
roots = ["example.com", "app.example.com"]
root_domain_lists = ["lists/audit/targetdomainslist"]
dependency_ttl = "30m"
max_dependencies = 8192
none_mode = "tunnel"                  # tunnel | noinspect
dependency_mutations = "restricted"   # none | restricted | full
discover_html = true
discover_css = true
discover_js = true
```

Traffic is classified into three classes:

- `root`: direct target domains. Full audit behavior and configured mutations are allowed.
- `dependency`: hosts associated with a root through propagation. Auditing remains enabled, but active mutations are restricted by default.
- `none`: traffic outside the target. With `none_mode = "tunnel"`, CONNECT traffic bypasses MITM; otherwise payload inspection and mutation are disabled.

Root domains can be declared inline in `roots` or loaded from `root_domain_lists`. `*.example.com` is normalized to `example.com`; domain matching covers the apex and subdomains.

The current sample list `lists/audit/targetdomainslist` is configured for AI web-app testing. It includes ChatGPT/OpenAI, Gemini/AI Studio, Claude/Anthropic, Perplexity, Poe, Copilot, Grok/xAI, Mistral, DeepSeek, and Character.AI roots. `Referer` and `Origin` currently propagate dependencies; passive HTML/CSS/JS discovery and `Sec-Fetch-*` enrichment are planned next.

### HTTP/3 (QUIC) Downstream

```toml
[server]
http3_enabled = true
```

When enabled, LucidGate opens a UDP listener on the same port as the TCP listener and serves `h3` via `quic-go/http3`. Browser clients that prefer QUIC will negotiate H3 directly against the proxy. The downstream TLS handshake reuses the same dynamic leaf certificate cache. Upstream traffic still uses TCP (HTTP/1.1 or H2). This avoids browsers leaking traffic over QUIC straight to the Internet when `Alt-Svc` advertising is stripped from upstream responses.

### Upstream Circuit Breaker

A per-host circuit breaker (`sony/gobreaker`) opens after a configurable number of consecutive upstream failures and short-circuits with `HTTP 502 Bad Gateway` until the cooldown window elapses, protecting local FDs and RAM during upstream outages.

```toml
[server]
circuit_breaker_enabled  = true
circuit_breaker_failures = 5
circuit_breaker_timeout  = "30s"
```

### DNS Cache

```toml
[server]
dns_cache_enabled = true
dns_cache_ttl     = "60s"
```

The internal resolver caches `A`/`AAAA` lookups with TTL to avoid repeated syscalls on the hot dial path. Raw IPv4/IPv6 literals bypass the cache. Disable only for short-lived hosts whose DNS changes faster than the TTL.

### SO_REUSEPORT (Linux)

```toml
[server]
reuseport = true
```

LucidGate opens `GOMAXPROCS` parallel listeners on the same `listen_addr` using `SO_REUSEPORT`, letting the kernel load-balance accept queues across cores. Useful above ~10k accepted connections/sec.

### OpenTelemetry Tracing

```toml
[tracing]
enabled      = true
endpoint     = "localhost:4317"
insecure     = true
service_name = "lucidgate"
sample_rate  = 1.0
```

When disabled (default) the tracer falls back to a noop provider with zero allocations on the hot path. When enabled, each exchange produces a parent `Exchange` span with child spans for `Upstream Dial`, `TLS Handshake Downstream`, `Request Processing`, and `Response Processing`, exported via OTLP gRPC. Standard W3C Trace Context headers are propagated so traces correlate across services. Span flush has a 5 s shutdown budget.

### Per-Profile QoS

Each access profile can declare its own concurrency cap and token-bucket rate limit, on top of the global `max_connections` semaphore:

```toml
[[access.profile]]
name       = "students"
clients    = ["10.0.10.0/24"]
max_conns  = 256          # per-profile concurrent slots
rate_limit = 50           # tokens per second per client IP
rate_burst = 100          # burst budget per client IP
```

Per-IP rate limiters live in a 16,384-entry LRU and run in the *fail-fast* phase before any handshake. Abusive IPs receive `HTTP 429` without consuming concurrency slots. `rate_limit` and `rate_burst` must be configured together.

### Hot Restart (zero-downtime upgrade)

Send `SIGUSR2` to the running process to re-exec the binary inheriting listening sockets via `cloudflare/tableflip`. In-flight CONNECT/WebSocket tunnels are drained with a 30 s grace timeout (`drainHijacked`) before the old process exits, so existing downloads and WebSocket sessions are not interrupted.

```bash
# Replace /usr/bin/lucidgate atomically, then:
kill -USR2 "$(pgrep -f lucidgate)"
```

### Dump Rotation and Disk Quotas

Forensic dumps rotate by size, are gzip-compressed in background, and are skipped automatically when free disk space falls below a configurable threshold:

```toml
[logging]
dump_dir              = "dumps"
dump_max_size_mb      = 100
dump_max_backups      = 10
dump_min_free_space_mb = 1024     # skip writes if free space falls below this
dump_compress         = true
```

If free space is below `dump_min_free_space_mb`, the dump entry is annotated with `skipped: "low disk space warning"` and the payload is dropped without touching disk. The free-space check walks up the path to the closest existing ancestor, so the dump directory does not need to exist yet.

## Rule Lists

`rules.include_dir` loads LucidGate/e2guardian-style rule files. Unknown file names keep the legacy behavior: each non-empty, non-comment line is treated as a blocked domain and applies to that domain plus all subdomains.

```text
example.com
school.test
```

Each entry in `include_dir` may be a directory (every regular file inside is read in alphabetical order) or a single file. Relative paths resolve against the directory holding `lucidgate.toml`. Lines starting with `#` are comments and blank lines are ignored.

Example:

```toml
[rules]
include_dir = ["rules.d", "profiles.d", "lists/sites"]
```

Recognized e2guardian-style site and URL files:

- `bannedsitelist`: blocked domains, compiled into the reverse domain trie.
- `exceptionsitelist`: allowed domain overrides.
- `bannedregexpsitelist`: blocked domain regexes.
- `exceptionregexpsitelist`: allowed domain regex overrides.
- `bannedsiteiplist`: blocked destination IPs/CIDRs, checked before upstream dial for IP-literal hosts and DNS-resolved hosts.
- `exceptionsiteiplist`: destination IP/CIDR overrides for `bannedsiteiplist`.
- `greysiteiplist`: accepted for compatibility; it means allow the destination IP while keeping normal content inspection.
- `bannedurllist`: blocked canonical URLs (`scheme://host/path?query`).
- `exceptionurllist`: allowed URL overrides.
- `refererexceptionsitelist`: allowed `Referer` domains that bypass content filters.
- `refererexceptionsiteiplist`: allowed `Referer` IP/CIDR sources that bypass content filters.
- `refererexceptionurllist`: allowed `Referer` URL prefixes that bypass content filters.
- `bannedregexpurllist`: blocked URL regexes.
- `exceptionregexpurllist`: allowed URL regex overrides.
- `bannedextensionlist`: blocked download/request path extensions such as `.exe` or `zip`.
- `exceptionextensionlist`: allowed extension overrides.
- `bannedmimetypelist`: blocked response MIME types such as `application/x-msdownload`; `type/*` wildcards are supported.
- `exceptionmimetypelist`: allowed MIME overrides.
- `bannedfilenamelist`: blocked basename matches from URL path or `Content-Disposition`.
- `exceptionfilenamelist`: allowed filename overrides.
- `bannedheaderlist`: blocked request/response header phrases matched against `Header-Name: value`.
- `exceptionheaderlist`: allowed header phrase overrides.
- `bannedregexpheaderlist`: blocked request/response header regexes matched against `Header-Name: value`.
- `exceptionregexpheaderlist`: allowed header regex overrides.
- `bannedcookiephraselist`: blocked cookie phrases matched against `Cookie` and `Set-Cookie` values.
- `exceptioncookiephraselist`: allowed cookie phrase overrides.
- `bannedclientiplist`: blocked client IP addresses or CIDR prefixes.
- `exceptionclientiplist`: allowed client IP or CIDR overrides.
- `e2guardianipgroups`: mapping of client IPs/CIDRs to profile groups (syntax: `IP/CIDR = group`).
- `filtergroupslist`: list of group/profile names to assign numeric indices.
- `logsitelist`: domains to explicitly mark for auditing/logging.
- `logsiteiplist`: literal destination IPs/CIDRs to explicitly mark for auditing/logging when the request host is already an IP.
- `logurllist`: URLs to explicitly mark for auditing/logging.
- `exceptionlogurllist`: URL audit logging exclusions.
- `logregexpurllist`: URL regular expressions to mark for auditing.
- `exceptionlogregexpurllist`: URL regex audit logging exclusions.
- `logregexpsitelist`: domain regular expressions to mark for auditing.
- `exceptionlogregexpsitelist`: domain regex audit logging exclusions.
- `nologsitelist`: domain audit logging exclusions.
- `nologsiteiplist`: literal destination IP/CIDR audit logging exclusions when the request host is already an IP.
- `nologurllist`: URL audit logging exclusions.
- `nologregexpurllist`: URL regex audit logging exclusions.
- `nologextensionlist`: extension audit logging exclusions.

Precedence is explicit: exceptions win over bans. For domains, `example.com` and `.example.com` both match the root domain and subdomains. Regexes and IP/CIDR prefixes are compiled during startup/reload; an invalid regex or IP prefix aborts that reload with `file:line` in the error. HTTP requests are checked before upstream dial. HTTPS URL rules are checked after the local MITM TLS handshake, before opening the upstream connection for the decrypted request. Destination IP lists apply to IP-literal hosts immediately and to DNS-resolved hosts by resolving once, applying policy to that IP, then dialing the same resolved address.

File/download rules are checked twice. URL path filename and extension are checked before upstream dial when possible. Response `Content-Type` and `Content-Disposition` are checked after upstream headers arrive but before LucidGate transfers the body to the client.

Header and cookie rules use case-insensitive substring matching. Request headers/cookies are checked before upstream traffic. Response headers and `Set-Cookie` are checked after upstream headers arrive but before response headers/body are delivered to the client.

For external phrase, masking, and substitution lists (e2guardian style), see [External Phrase Lists](#external-phrase-lists-e2guardian-style) below.

## Configuration Files By List Type

LucidGate can keep long policies out of `lucidgate.toml` by loading named files from `rules.include_dir` and the dedicated `*_lists` settings. The recommended layout is:

```text
lists/
  sites/
    bannedsitelist
    exceptionsitelist
    bannedregexpsitelist
    exceptionregexpsitelist
    bannedsiteiplist
    exceptionsiteiplist
    greysiteiplist
    bannedurllist
    exceptionurllist
    refererexceptionsitelist
    refererexceptionsiteiplist
    refererexceptionurllist
    bannedregexpurllist
    exceptionregexpurllist
  downloads/
    bannedextensionlist
    exceptionextensionlist
    bannedmimetypelist
    exceptionmimetypelist
    bannedfilenamelist
    exceptionfilenamelist
  http/
    bannedheaderlist
    exceptionheaderlist
    bannedregexpheaderlist
    exceptionregexpheaderlist
    bannedcookiephraselist
    exceptioncookiephraselist
  phraselists/
    bannedphraselist
    weightedphraselist
    exceptionphraselist
    weightedphraseexceptions
  masking/
    maskedphraselist
  substitution/
    substitutionlist
    regexsubstitutionlist
  clients/
    bannedclientiplist
    exceptionclientiplist
    e2guardianipgroups
    filtergroupslist
  logging/
    logsitelist
    logsiteiplist
    logurllist
    exceptionlogurllist
    logregexpurllist
    exceptionlogregexpurllist
    logregexpsitelist
    exceptionlogregexpsitelist
    nologsitelist
    nologsiteiplist
    nologurllist
    nologregexpurllist
    nologextensionlist
    logphraselist
    exceptionlogphraselist
```

Wire policy lists through `rules.include_dir`:

```toml
[rules]
include_dir = [
  "lists/sites",
  "lists/downloads",
  "lists/http",
]
```

Wire content lists through their feature sections:

```toml
[semantic]
blocked_phrase_lists   = ["lists/phraselists/bannedphraselist"]
weighted_phrase_lists  = ["lists/phraselists/weightedphraselist"]
exception_phrase_lists = ["lists/phraselists/exceptionphraselist"]

[masking]
phrase_lists = ["lists/masking/maskedphraselist"]

[substitution]
rule_lists = ["lists/substitution/substitutionlist"]
regex_rule_lists = ["lists/substitution/regexsubstitutionlist"]
```

| Family | File | Syntax | Evaluated |
| --- | --- | --- | --- |
| Domain | `bannedsitelist` | one domain per line | before upstream |
| Domain | `exceptionsitelist` | one domain per line | overrides domain bans |
| Domain | `bannedregexpsitelist` | Go/RE2 regex | before upstream |
| Domain | `exceptionregexpsitelist` | Go/RE2 regex | overrides domain regex bans |
| Site IP | `bannedsiteiplist` | IP or CIDR per line | before upstream for IP-literal and DNS-resolved hosts |
| Site IP | `exceptionsiteiplist` | IP or CIDR per line | overrides site IP bans |
| Site IP | `greysiteiplist` | IP or CIDR per line | allow with normal content inspection |
| URL | `bannedurllist` | `scheme://host/path?query` prefix | before upstream when URL is known |
| URL | `exceptionurllist` | URL prefix | overrides URL bans |
| Referer | `refererexceptionsitelist` | one domain per line | bypasses content filters when `Referer` host matches |
| Referer | `refererexceptionsiteiplist` | IP or CIDR per line | bypasses content filters when `Referer` host is an IP match |
| Referer | `refererexceptionurllist` | URL prefix | bypasses content filters when `Referer` URL matches |
| URL | `bannedregexpurllist` | Go/RE2 regex | before upstream when URL is known |
| URL | `exceptionregexpurllist` | Go/RE2 regex | overrides URL regex bans |
| Downloads | `bannedextensionlist` | `.exe` or `exe` | URL path before upstream |
| Downloads | `exceptionextensionlist` | `.ok` or `ok` | overrides extension bans |
| Downloads | `bannedmimetypelist` | `application/x-msdownload`, `type/*` | response headers before body |
| Downloads | `exceptionmimetypelist` | MIME or `type/*` | overrides MIME bans |
| Downloads | `bannedfilenamelist` | basename, e.g. `secret.bin` | URL path or `Content-Disposition` |
| Downloads | `exceptionfilenamelist` | basename | overrides filename bans |
| HTTP | `bannedheaderlist` | substring against `Header-Name: value` | request/response headers |
| HTTP | `exceptionheaderlist` | substring | overrides header bans |
| HTTP | `bannedregexpheaderlist` | Go/RE2 regex against `Header-Name: value` | request/response headers |
| HTTP | `exceptionregexpheaderlist` | Go/RE2 regex | overrides header regex bans |
| HTTP | `bannedcookiephraselist` | substring in `Cookie`/`Set-Cookie` | request/response cookies |
| HTTP | `exceptioncookiephraselist` | substring | overrides cookie bans |
| Semantic | `bannedphraselist` | one phrase per line | response/request body text stream |
| Semantic | `weightedphraselist` | `<phrase><weight>` | response/request body scoring |
| Semantic | `exceptionphraselist` | one phrase per line | suppresses subsequent hard/score blocks in the same stream |
| Semantic | `weightedphraseexceptions` | `<phrase><weight>` | excludes those phrases from `weightedphraselist` scoring at build time |
| Masking | `maskedphraselist` | one phrase per line | non-HTML text mutation |
| Substitution | `substitutionlist` | `search => replace` | mutable text/HTML response |
| Substitution | `regexsubstitutionlist` | `pattern => replace` | mutable text/HTML response |
| Request substitution | `requestsubstitutionlist` | `search => replace` | mutable request body |
| Request substitution | `requestregexsubstitutionlist` | `pattern => replace` | mutable request body |
| Audit scope | `targetdomainslist` | one domain per line | target-aware root matching |
| Client | `bannedclientiplist` | IP or CIDR per line | request source IP check |
| Client | `exceptionclientiplist` | IP or CIDR per line | overrides client IP bans |
| Client | `e2guardianipgroups` | `IP/CIDR = group` | maps client IPs to profile groups |
| Client | `filtergroupslist` | group names per line | defines ordered group profiles |
| Log | `logsitelist` | one domain per line | marks matched domains for audit logging |
| Log | `logsiteiplist` | IP or CIDR per line | marks matched IP-literal hosts for audit logging |
| Log | `logurllist` | URL prefix | marks matched URLs for audit logging |
| Log | `exceptionlogurllist` | URL prefix | overrides URL audit logging |
| Log | `logregexpurllist` | Go/RE2 regex | marks matched URLs for audit logging |
| Log | `exceptionlogregexpurllist` | Go/RE2 regex | overrides URL audit regex logging |
| Log | `logregexpsitelist` | Go/RE2 regex | marks matched domains for audit logging |
| Log | `exceptionlogregexpsitelist` | Go/RE2 regex | overrides domain audit regex logging |
| Log | `nologsitelist` | one domain per line | suppresses audit logging for matched domains |
| Log | `nologsiteiplist` | IP or CIDR per line | suppresses audit logging for matched IP-literal hosts |
| Log | `nologurllist` | URL prefix | suppresses URL audit logging |
| Log | `nologregexpurllist` | Go/RE2 regex | suppresses URL regex audit logging |
| Log | `nologextensionlist` | `.png` or `png` | suppresses audit logging for request URL extensions |
| Log | `logphraselist` | one phrase per line | marks matched body phrases for audit logging |
| Log | `exceptionlogphraselist` | one phrase per line | overrides body phrase audit logging |

Common rules:

- Exceptions always win over bans within the same family.
- Unknown filenames under `rules.include_dir` keep legacy behavior and are treated as plain blocked-domain lists.
- Regex files are compiled during startup/reload. Invalid regexes abort that load with `file:line`.
- List files support `#` comments, blank lines, and `.Include<relative/or/absolute/path>`.
- Relative paths are resolved from the directory containing `lucidgate.toml` for TOML entries, and from the including file for `.Include`.

## Curl Policy Battery

`scripts/curl_policy_battery.sh` runs an end-to-end curl battery against a local HTTP upstream and a temporary LucidGate configuration. It uses the list files under `testdata/curl-policy-lists/` and does not depend on the public Internet.

```bash
make curl-policy
```

It validates:

- domain and URL bans/exceptions
- download extension, MIME, and filename policy
- request/response header policy
- request/response cookie policy
- semantic phrase blocking and weighted scoring
- masking
- literal substitution
- regexp substitution and capture expansion

Default ports are `127.0.0.1:18080` for the upstream and `127.0.0.1:18081` for LucidGate. Override them when needed:

```bash
LUCIDGATE_CURL_UPSTREAM_PORT=19080 \
LUCIDGATE_CURL_PROXY_PORT=19081 \
make curl-policy
```

Set `KEEP_LUCIDGATE_CURL_TMP=1` to keep the generated config, CA, and logs for debugging.

## Access Profiles

Access profiles map client IPs to policy names using CIDR prefixes. If any profiles are configured, clients not matching an allowed profile are rejected before CONNECT hijack.

```toml
[[access.profile]]
name = "students"
clients = ["192.0.2.0/24", "2001:db8::/32"]

[[access.profile]]
name = "default"
default = true
clients = ["127.0.0.1/32", "::1/128"]
```

## Schedules

Schedules allow a profile only during configured windows. Requests outside the window receive a LucidGate block page before upstream traffic starts.

```toml
[[schedule.window]]
profile = "students"
days = ["mon", "tue", "wed", "thu", "fri"]
start = "08:30"
end = "16:00"
```

Use `00:00` to `24:00` for all-day access.

E2Guardian-style `bannedtimelist` and `blankettimelist` files inside
`rules.include_dir` are also accepted. Each active line uses:

```text
start_hour start_min end_hour end_min days
```

Days are e2guardian digits `0-6` (`0` = Monday, `6` = Sunday). LucidGate
compiles these blocked time bands into per-profile schedule windows.

## Semantic Filtering

Semantic filtering uses Aho-Corasick over streaming chunks.

Immediate blocking:

```toml
[semantic]
blocked_phrases = ["credential dump", "blocked phrase"]
```

Weighted scoring:

```toml
[semantic]
score_threshold = 100

[[semantic.weighted_phrase]]
phrase = "malware"
weight = 40

[[semantic.weighted_phrase]]
phrase = "credential dump"
weight = 70
```

When the accumulated score for a stream reaches the threshold, LucidGate truncates the stream at the triggering phrase. Current behavior preserves upstream status, usually `200`, and cuts the body. Fast-fail block pages are used for pre-CONNECT policy decisions such as domain/client/schedule/connection limit.

For `text/html`, the semantic engine inspects visible text only. It ignores tags, attributes, comments, and `script`/`style` content, while sending the original HTML through until a block occurs.

## Compressed Text

For mutable textual responses (`text/*`, JSON/XML variants, JavaScript, form-urlencoded, ndjson), LucidGate can inspect:

- identity/no encoding
- `gzip` / `x-gzip`
- `deflate`
- `br`

Compressed mutable responses are decompressed, inspected, recompressed, and sent as chunked responses. Unsupported encodings are bypassed.

## Masking

Masking replaces configured phrases with `*` while preserving byte length.

```toml
[masking]
phrases = ["secret token", "api key"]
```

Masking currently applies to non-HTML textual responses. HTML masking is intentionally deferred because visible-text offsets must be mapped back to original HTML bytes without corrupting tags.

## Phrase Substitution

Phrase substitution replaces configured text with explicit replacement text.

```toml
[[substitution.rule]]
search = "Madrid"
replace = "Barcelona"

[[substitution.rule]]
search = "internal codename"
replace = "public project"

[[substitution.regex_rule]]
pattern = "ca.*sa\\.png"
replace = "carcasa.png"
max_window_bytes = 65536
```

Unlike masking, substitution does not preserve byte length and does not replace matches with `*`. It emits the configured `replace` value, so mutable textual responses are sent with `Transfer-Encoding: chunked` and without the upstream `Content-Length`.

Substitution applies to textual responses, including HTML. For HTML, it runs on the raw HTML stream; it is intended for direct phrase replacement and does not perform visible-text-only token mapping.

Regex substitution uses Go/RE2 regular expressions and is compiled during startup/reload. Capture expansion in replacements is supported (`$1`, `$2`, etc.). `max_window_bytes` bounds how many bytes a regex rule may hold to catch matches split across chunks; the default is 65536 and the hard limit is 1048576. A regex that needs to match across more bytes than that window should be made more specific.

## Request Body Substitution

Request substitution applies the same streaming literal/regex machinery to mutable request bodies. It is configured separately from response substitution so uploads are not modified by accident.

```toml
[request_substitution]
rule_lists = ["lists/substitution/requestsubstitutionlist"]
regex_rule_lists = ["lists/substitution/requestregexsubstitutionlist"]

[[request_substitution.rule]]
search = "LG_IN_TEST"
replace = "LG_IN_MUTX"

[[request_substitution.regex_rule]]
pattern = "(?i)(api[_-]?key\\s*[:=]\\s*\")sk-proj-[A-Za-z0-9._-]+(\")"
replace = "$1[REDACTED]$2"
max_window_bytes = 4096
```

Request substitution is intentionally conservative:

- It runs only on mutable textual request bodies such as JSON, text, URL-encoded forms, and selected multipart form data.
- It skips compressed uploads and unsupported framing.
- It respects policy/filter bypasses, including `exceptionsitelist` and audit-scope `dependency`/`none` decisions.
- Broad request regexes that would corrupt CSRF tokens, client-state JWTs, URL-encoded delimiters, or common structural fields are rejected during startup/reload.

Use request regexes as surgical DLP rules, not as broad "redact anything named token" rules. Modern web apps often sign payloads, bind CSRF values to cookies, or require exact JSON structure; changing unrelated values can break the upstream application.

The sample configuration currently enables a test marker:

```text
LG_IN_TEST => LG_IN_MUTX
```

Response substitution also has a test marker:

```text
LG_OUT_TEST => LG_OUT_MUTX
```

These are useful for verifying that input/output mutation is active inside the configured audit scope. `text/event-stream` responses are not mutated, even though they are textual, because changing streaming deltas can corrupt offsets, citations, and client-side state.

## External Phrase Lists (e2guardian-style)

Banned phrases, weighted phrases, exception phrases, masking phrases, and substitution rules can also live in plain external files instead of being embedded in `lucidgate.toml`. This is the same idiom e2guardian uses and keeps long lists out of the main TOML.

Recommended layout:

```text
lists/
  sites/
    bannedsitelist
  phraselists/
    bannedphraselist
    weightedphraselist
    exceptionphraselist
    weightedphraseexceptions
  masking/
    maskedphraselist
  substitution/
    substitutionlist
    regexsubstitutionlist
    requestsubstitutionlist
    requestregexsubstitutionlist
  audit/
    targetdomainslist
```

Wire the lists from `lucidgate.toml`:

```toml
[rules]
include_dir = ["lists/sites"]

[semantic]
blocked_phrases = ["embedded phrase"]
blocked_phrase_lists   = ["lists/phraselists/bannedphraselist"]
weighted_phrase_lists  = ["lists/phraselists/weightedphraselist"]
exception_phrase_lists = ["lists/phraselists/exceptionphraselist"]
score_threshold = 100

[masking]
phrases      = ["embedded secret"]
phrase_lists = ["lists/masking/maskedphraselist"]

[substitution]
rule_lists = ["lists/substitution/substitutionlist"]
regex_rule_lists = ["lists/substitution/regexsubstitutionlist"]

[request_substitution]
rule_lists = ["lists/substitution/requestsubstitutionlist"]
regex_rule_lists = ["lists/substitution/requestregexsubstitutionlist"]

[audit_scope]
enabled = true
root_domain_lists = ["lists/audit/targetdomainslist"]
```

Embedded entries (`blocked_phrases`, `[[semantic.weighted_phrase]]`, `phrases`, `[[substitution.rule]]`, `[[substitution.regex_rule]]`, `[[request_substitution.rule]]`, `[[request_substitution.regex_rule]]`, and `audit_scope.roots`) keep working and are merged with the external entries; embedded values come first.

Common parser rules for every list file:

- One entry per line; UTF-8 text.
- Lines starting with `#` (or anything after `#`) are comments.
- Blank lines are ignored.
- `.Include<path/to/file>` recursively includes another list file. Relative paths resolve against the file holding the `.Include`. Cycles are detected and rejected.
- Relative `*_lists` paths in `lucidgate.toml` resolve against the directory holding `lucidgate.toml` (not the process working directory).
- Directories are accepted in `*_lists` and `include_dir`: every regular file inside is read in alphabetical order. Single files are also accepted.
- Parser errors include the source file and line number.

Per-format syntax:

- **bannedphraselist / exceptionphraselist / maskedphraselist:** one phrase per line.

  ```text
  # banned phrases
  malware kit
  credential dump
  .Include<extra/banned_extra>
  ```

- **weightedphraselist / weightedphraseexceptions:** e2guardian `<phrase><weight>` syntax. Weight must be a positive integer.

  ```text
  <malware><60>
  <credential dump><80>
  ```

  `weightedphraseexceptions` removes phrases (matched case-insensitively after trim) from `weightedphraselist` at build time. It is a phrase-level exclusion, not an e2guardian phrase-combination exception.

- **substitutionlist:** `search => replace`. The replacement may be empty to delete the matched text.

  ```text
  Madrid => Barcelona
  internal codename => public name
  delete me =>
  ```

- **regexsubstitutionlist:** `pattern => replace`, compiled as Go/RE2 regexp. The replacement may use capture expansion (`$1`).

  ```text
  ca.*sa\.png => carcasa.png
  image-([0-9]+)\.png => asset-$1.webp
  ```

- **requestsubstitutionlist:** `search => replace`, applied to mutable request bodies.

  ```text
  LG_IN_TEST => LG_IN_MUTX
  internal codename => public name
  ```

- **requestregexsubstitutionlist:** `pattern => replace`, compiled as Go/RE2 regexp and applied to mutable request bodies. Keep these rules specific; unsafe broad request regexes are rejected at startup/reload.

  ```text
  (?i)(api[_-]?key\s*[:=]\s*")sk-proj-[A-Za-z0-9._-]+(") => $1[REDACTED]$2
  ```

- **targetdomainslist:** one audit root domain per line. These are merged into `[audit_scope].roots`.

  ```text
  chatgpt.com
  gemini.google.com
  claude.ai
  anthropic.com
  ```

### Streaming semantics for `exceptionphraselist`

- When any exception phrase matches the inspected stream, the stream becomes "excepted": from that byte onward neither hard `bannedphraselist` matches nor `weightedphraselist` score accumulation will block the response.
- Limitation: if a hard match precedes the exception in byte order, the block fires first because the proxy cannot rewind bytes already sent to the client. Place exception phrases that should reliably whitelist a page near the top of the document (titles, meta tags), or use `[rules].include_dir` regex/site exceptions to whitelist the URL up front.

### Loading phrase lists from `[rules].include_dir`

In addition to the dedicated `*_lists` keys above, the four phrase files can be loaded by filename through `[rules].include_dir`. This is the native e2guardian idiom and is convenient when sharing a single rules tree with other tooling:

```toml
[rules]
include_dir = ["lists/sites", "lists/phraselists"]

[semantic]
score_threshold = 100
```

Recognized filenames inside any `include_dir` entry: `bannedphraselist`, `exceptionphraselist`, `weightedphraselist`, `weightedphraseexceptions`, `bannedtimelist`, `blankettimelist` (plus the site/url/file/header/cookie families documented above). Files with unrecognized names keep the legacy behavior and are treated as plain blocked-domain lists.

Duplicates are deduplicated when safe (identical entries) and rejected when ambiguous: a weighted phrase declared with conflicting weights, two substitution rules with the same `search`, or two regex substitution rules with the same `pattern`, all produce a clear error pointing at the offending file and line.

## HTML Injection

LucidGate can inject a banner before `</body>` in HTML responses:

```toml
[injection]
html_banner = "<div>LucidGate inspected this page</div>"
```

The detector is streaming and handles `</body>` split across chunks. The banner is injected once. If semantic filtering blocks the response before `</body>`, no banner is injected.

## Upload Inspection

LucidGate inspects textual upload bodies for `POST`, `PUT`, and `PATCH` using the same semantic filter:

- inspected: textual content types such as `text/plain`, JSON, XML, form-urlencoded
- bypassed: multipart, binary, and compressed uploads

It does not call `ParseMultipartForm` and does not buffer full uploads. On a semantic hit, LucidGate cuts the upload stream and closes the relay. A dedicated HTTP block response for already-started uploads is a future improvement.

## Body Dumps

Set `logging.dump_dir` to write bounded JSONL body records:

```toml
[logging]
dump_dir = "dumps"
dump_on_policy_hit = true
max_capture_bytes = 8388608
```

If `dump_on_policy_hit` is true, LucidGate only writes request and response body dumps to `dump_dir` when a policy blocks the connection (antivirus, domain, URL, header, or phrase blocking) or when an audit list is matched (e.g. `logurllist`, `logphraselist`). Otherwise, benign traffic payloads are immediately discarded from memory without touching disk.

### Forensic Attribution & Security Notes

To prevent data leakage and credential theft during internal forensic analysis, LucidGate enforces high-standard data protection by default:
- **Redaction by Default:** In normal mode, sensitive credential fields detected in headers (e.g., `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`) or bodies (JSON keys or form parameters like `password`, `token`, `api_key`, `secret`, `client_secret`, JWT tokens) are replaced with `[REDACTED]`.
- **HMAC Correlation:** Configure `logging.audit_key` (or command-line flag `--audit-key` / environment variable `LUCIDGATE_AUDIT_KEY`) to replace redacted secrets with their cryptographic hash: `HMAC-SHA256(audit_key, secret_value)`. This allows secure attribution and correlation across flows without storing plain-text secrets.
- **Explicit Cleartext Mode:** You can enable dumping of plain-text credentials by setting `logging.dump_credentials_cleartext = true` (or `--dump-credentials-cleartext` / `LUCIDGATE_DUMP_CREDENTIALS_CLEARTEXT=true`).
  - **Constraints:** This setting strictly requires `dump_on_policy_hit = true` to prevent general traffic leakage. LucidGate will abort startup if this is violated.
  - **Loud Warnings:** It logs a critical safety warning at startup.
  - **Metadata:** Each dump is tagged with `"contains_cleartext_credentials": true`.
  - **Permissions:** Applies strict permissions (`0700` for dump directories, `0600` for dump files).
  - **HTTPS limitations:** Note that HTTPS request/response bodies can only be inspected and dumped if HTTPS termination/MITM intercept is actively configured and active for the traffic; pure `CONNECT` tunnels without termination cannot be decrypted.

## Curl Examples

Start LucidGate:

```bash
make build
./build/lucidgate --config lucidgate.toml
```

Trust the generated CA for curl:

```bash
curl \
  --proxy http://127.0.0.1:8080 \
  --cacert certs/ca.crt \
  https://example.com/
```

Use an environment override:

```bash
LUCIDGATE_LISTEN_ADDR=127.0.0.1:18080 \
LUCIDGATE_DUMP_DIR=./dumps \
./build/lucidgate
```

Then:

```bash
curl \
  --proxy http://127.0.0.1:18080 \
  --cacert certs/ca.crt \
  https://example.com/
```

## Logs

Relay logs use:

```text
[METHOD] [HOST] [PATH] - Status: [CODE] - ReqBytes: [X] - RespBytes: [Y]
```

`ReqBytes` and `RespBytes` are counted on the streamed body path when body byte logging is enabled. Disabled or intentionally uncaptured body counts use `-1`.

## Build And Test

Useful targets:

```bash
make help
make deps
make test
make smoke
make build
make verify
```

Run the 10 GiB streaming benchmark:

```bash
GOCACHE=/tmp/go-build go test -run '^$' -bench '^BenchmarkWriteResponseStreaming10GiB$' -benchtime=1x -benchmem ./proxy
```

Some tests open loopback listeners. If a sandbox blocks local sockets, run tests in an environment that permits loopback networking.

## Debian Package

Build a `.deb`:

```bash
make deb VERSION=0.1.0 RELEASE=1
```

Install:

```bash
sudo dpkg -i dist/lucidgate_0.1.0-1_amd64.deb
sudo systemctl enable --now lucidgate
journalctl -u lucidgate -f
```

The package stores generated CA material under:

```text
/var/lib/lucidgate/certs/
```

Copy and trust only:

```text
/var/lib/lucidgate/certs/ca.crt
```

## CA Management

Inspect the generated local CA:

```bash
make ca-info
```

Delete local generated CA files:

```bash
make cert-clean
```

Deleting the CA invalidates previously trusted generated leaf certificates and requires importing the new `ca.crt` after the next run.

## Performance Notes

- Relay body copying uses `io.CopyBuffer` and a pooled 32 KiB buffer.
- Response mutation forces chunked transfer and removes upstream `Content-Length`.
- Domain/client/schedule/connection-limit decisions happen before hijack or upstream dial where possible.
- Rules and runtime relay options are published as immutable snapshots through `atomic.Value`.
- The relay avoids `io.ReadAll`/`ioutil.ReadAll` on network request/response bodies.

## Troubleshooting

Certificate errors:

- Confirm `certs/ca.crt` is trusted by the client.
- Confirm the client is using LucidGate as HTTPS proxy.
- Restart the proxy after rotating `certs/`.

Unexpected unfiltered traffic:

- Check `Content-Type`. Binary, multipart, and unsupported encodings are bypassed.
- Check schedule/access rules and logs.
- Confirm the client is using HTTPS proxy mode, not direct mode.

Socket permission test failures:

- The environment is blocking loopback listeners.
- Run tests outside that sandbox or allow local TCP listeners.
