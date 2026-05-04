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
- HTML banner injection before `</body>`.
- Streaming textual upload inspection for `POST`, `PUT`, and `PATCH`.
- Bypass for binary, multipart, request-compressed, and unsupported response-compressed payloads.
- Optional bounded JSONL body dump for offline analysis.

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

[upstream]
dial_timeout = "10s"
insecure_skip_verify = false

[logging]
log_bodies = true
max_capture_bytes = 1048576
dump_dir = ""

[rules]
include_dir = ["rules.d"]

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

[[semantic.weighted_phrase]]
phrase = "malware"
weight = 20

[[semantic.weighted_phrase]]
phrase = "credential dump"
weight = 80

[masking]
phrases = ["secret token"]

[[substitution.rule]]
search = "internal codename"
replace = "public project"

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
| `--io-timeout` | `LUCIDGATE_IO_TIMEOUT` | `30s` | Per-operation relay read/write timeout. |
| `--dial-timeout` | `LUCIDGATE_DIAL_TIMEOUT` | `10s` | Upstream TCP/uTLS dial timeout. |
| `--handshake-timeout` | `LUCIDGATE_HANDSHAKE_TIMEOUT` | `5s` | Browser-side TLS handshake timeout. |
| `--log-bodies` | `LUCIDGATE_LOG_BODIES` | `true` | Enable byte-count body capture behavior. |
| `--max-capture-bytes` | `LUCIDGATE_MAX_CAPTURE_BYTES` | `1048576` | Maximum bytes captured per body; `0` disables capture. |
| `--dump-dir` | `LUCIDGATE_DUMP_DIR` | empty | Write bounded JSONL cleartext dumps when non-empty. |
| `--upstream-insecure-skip-verify` | `LUCIDGATE_UPSTREAM_INSECURE_SKIP_VERIFY` | `false` | Skip upstream TLS verification. Lab/smoke only. |
| `--version` | none | `false` | Print version and exit. |

## Rule Lists

`rules.include_dir` loads plain text domain lists. Each non-empty, non-comment line blocks that domain and all subdomains.

```text
example.com
school.test
```

Example:

```toml
[rules]
include_dir = ["rules.d", "profiles.d"]
```

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
```

Unlike masking, substitution does not preserve byte length and does not replace matches with `*`. It emits the configured `replace` value, so mutable textual responses are sent with `Transfer-Encoding: chunked` and without the upstream `Content-Length`.

Substitution applies to textual responses, including HTML. For HTML, it runs on the raw HTML stream; it is intended for direct phrase replacement and does not perform visible-text-only token mapping.

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
max_capture_bytes = 8388608
```

If `dump_dir` is set and `max_capture_bytes <= 0`, LucidGate uses an 8 MiB default cap for dumps. Dumps are for controlled analysis and can contain sensitive data.

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
