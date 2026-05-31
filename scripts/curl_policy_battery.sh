#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${LUCIDGATE_BIN:-$ROOT/build/lucidgate}"
UPSTREAM_PORT="${LUCIDGATE_CURL_UPSTREAM_PORT:-18080}"
PROXY_PORT="${LUCIDGATE_CURL_PROXY_PORT:-18081}"
PROXY="http://127.0.0.1:${PROXY_PORT}"
UPSTREAM="http://127.0.0.1:${UPSTREAM_PORT}"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/lucidgate-curl-battery.XXXXXX")"

UPSTREAM_PID=""
PROXY_PID=""

cleanup() {
  if [[ -n "${PROXY_PID}" ]]; then kill "${PROXY_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${UPSTREAM_PID}" ]]; then kill "${UPSTREAM_PID}" >/dev/null 2>&1 || true; fi
  wait "${PROXY_PID:-}" >/dev/null 2>&1 || true
  wait "${UPSTREAM_PID:-}" >/dev/null 2>&1 || true
  if [[ "${KEEP_LUCIDGATE_CURL_TMP:-0}" != "1" ]]; then
    rm -rf "${TMPDIR}"
  else
    printf 'keeping temp dir: %s\n' "${TMPDIR}"
  fi
}
trap cleanup EXIT

pass=0
fail=0

note() {
  printf '\n== %s ==\n' "$*"
}

ok() {
  pass=$((pass + 1))
  printf 'ok  - %s\n' "$*"
}

bad() {
  fail=$((fail + 1))
  printf 'not ok - %s\n' "$*" >&2
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$1" >&2
    exit 2
  }
}

curl_body() {
  local url="$1"
  local out="$2"
  shift 2
  curl --silent --show-error --noproxy "" --proxy "${PROXY}" \
    --connect-timeout 2 --max-time 5 \
    --output "${out}" --write-out '%{http_code}' "$@" "${url}"
}

assert_status() {
  local name="$1"
  local expected="$2"
  local url="$3"
  shift 3
  local out="${TMPDIR}/body.${pass}.${fail}.$RANDOM"
  local code
  if ! code="$(curl_body "${url}" "${out}" "$@")"; then
    bad "${name}: curl failed"
    return
  fi
  if [[ "${code}" == "${expected}" ]]; then
    ok "${name}: HTTP ${code}"
  else
    bad "${name}: HTTP ${code}, expected ${expected}; body=$(tr -d '\n' <"${out}" | head -c 180)"
  fi
}

assert_contains() {
  local name="$1"
  local needle="$2"
  local url="$3"
  shift 3
  local out="${TMPDIR}/body.${pass}.${fail}.$RANDOM"
  local code
  if ! code="$(curl_body "${url}" "${out}" "$@")"; then
    bad "${name}: curl failed"
    return
  fi
  if [[ "${code}" == "200" ]] && grep -Fq "${needle}" "${out}"; then
    ok "${name}: contains ${needle}"
  else
    bad "${name}: HTTP ${code}, missing ${needle}; body=$(tr -d '\n' <"${out}" | head -c 180)"
  fi
}

assert_not_contains() {
  local name="$1"
  local needle="$2"
  local url="$3"
  shift 3
  local out="${TMPDIR}/body.${pass}.${fail}.$RANDOM"
  local code
  if ! code="$(curl_body "${url}" "${out}" "$@")"; then
    bad "${name}: curl failed"
    return
  fi
  if [[ "${code}" == "200" ]] && ! grep -Fq "${needle}" "${out}"; then
    ok "${name}: does not contain ${needle}"
  else
    bad "${name}: HTTP ${code}, unexpected ${needle}; body=$(tr -d '\n' <"${out}" | head -c 180)"
  fi
}

wait_for_proxy() {
  local i
  local code
  for i in {1..80}; do
    code="$(curl --silent --show-error --noproxy "" --proxy "${PROXY}" \
      --connect-timeout 1 --max-time 2 \
      --output /dev/null --write-out '%{http_code}' \
      "${UPSTREAM}/ok" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  printf 'proxy did not become ready; logs:\n' >&2
  sed -n '1,160p' "${TMPDIR}/lucidgate.log" >&2 || true
  return 1
}

wait_for_upstream() {
  local i
  local code
  for i in {1..80}; do
    code="$(curl --silent --show-error --noproxy "*" \
      --connect-timeout 1 --max-time 2 \
      --output /dev/null --write-out '%{http_code}' \
      "${UPSTREAM}/ok" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  printf 'upstream did not become ready; logs:\n' >&2
  sed -n '1,160p' "${TMPDIR}/upstream.log" >&2 || true
  return 1
}

need curl
need python3

if [[ ! -x "${BIN}" ]]; then
  note "building LucidGate"
  (cd "${ROOT}" && make build)
fi

cp -R "${ROOT}/testdata/curl-policy-lists" "${TMPDIR}/lists"

cat >"${TMPDIR}/lucidgate.toml" <<EOF_CONFIG
[server]
listen_addr = "127.0.0.1:${PROXY_PORT}"
cert_dir = "${TMPDIR}/certs"
max_connections = 128
io_timeout = "5s"
dial_timeout = "2s"
handshake_timeout = "5s"
upstream_insecure_skip_verify = true

[logging]
log_bodies = false
max_capture_bytes = 0
dump_dir = ""

[rules]
include_dir = [
  "${TMPDIR}/lists/sites",
  "${TMPDIR}/lists/downloads",
  "${TMPDIR}/lists/http",
]

[semantic]
score_threshold = 100
blocked_phrase_lists = ["${TMPDIR}/lists/phraselists/bannedphraselist"]
weighted_phrase_lists = ["${TMPDIR}/lists/phraselists/weightedphraselist"]
exception_phrase_lists = ["${TMPDIR}/lists/phraselists/exceptionphraselist"]

[masking]
phrase_lists = ["${TMPDIR}/lists/masking/maskedphraselist"]

[substitution]
rule_lists = ["${TMPDIR}/lists/substitution/substitutionlist"]
regex_rule_lists = ["${TMPDIR}/lists/substitution/regexsubstitutionlist"]
EOF_CONFIG

cat >"${TMPDIR}/upstream.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os

PORT = int(os.environ["UPSTREAM_PORT"])

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def send_text(self, body, ctype="text/plain; charset=utf-8", status=200, extra=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if extra:
            for key, value in extra:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/ok":
            self.send_text("OK")
        elif path == "/plain-banned-url/allowed":
            self.send_text("plain URL exception OK")
        elif path == "/regex-blocked-url/allowed":
            self.send_text("regex URL exception OK")
        elif path == "/download/file.ok":
            self.send_text("extension exception OK")
        elif path == "/mime/allowed":
            self.send_text("MIME exception OK", "application/signed-exchange")
        elif path == "/header/allowed":
            self.send_text("header exception OK")
        elif path == "/cookie/allowed":
            self.send_text("cookie exception OK")
        elif path == "/semantic":
            self.send_text("before blocked phrase after")
        elif path == "/weighted":
            self.send_text("before red flag and payload after")
        elif path == "/mask":
            self.send_text("token apikey-12345 end")
        elif path == "/sub":
            self.send_text("<html><body>Madrid internal codename</body></html>", "text/html; charset=utf-8")
        elif path == "/regexsub":
            self.send_text('<html><body><img src="/assets/carpeta/sa.png"> image-42.png</body></html>', "text/html; charset=utf-8")
        elif path == "/mime/exe":
            self.send_response(200)
            self.send_header("Content-Type", "application/x-msdownload")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/filename/secret":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="secret.bin"')
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/response-header/blocked":
            self.send_response(200)
            self.send_header("X-Response-Block", "yes")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/set-cookie/blocked":
            self.send_response(200)
            self.send_header("Set-Cookie", "trackid=response")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_text("default OK")

server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
server.serve_forever()
PY

note "starting local upstream on 127.0.0.1:${UPSTREAM_PORT}"
UPSTREAM_PORT="${UPSTREAM_PORT}" python3 "${TMPDIR}/upstream.py" >"${TMPDIR}/upstream.log" 2>&1 &
UPSTREAM_PID="$!"
wait_for_upstream

note "starting LucidGate on 127.0.0.1:${PROXY_PORT}"
"${BIN}" --config "${TMPDIR}/lucidgate.toml" >"${TMPDIR}/lucidgate.log" 2>&1 &
PROXY_PID="$!"
wait_for_proxy

note "domain and URL policy"
assert_status "allowed baseline" 200 "${UPSTREAM}/ok"
assert_status "bannedsitelist blocks before dial" 403 "http://blocked.local:${UPSTREAM_PORT}/ok"
assert_status "bannedregexpsitelist blocks before dial" 403 "http://blocked-regex.local:${UPSTREAM_PORT}/ok"
assert_status "bannedurllist blocks exact URL prefix" 403 "${UPSTREAM}/plain-banned-url"
assert_status "exceptionurllist overrides URL ban" 200 "${UPSTREAM}/plain-banned-url/allowed"
assert_status "bannedregexpurllist blocks URL regex" 403 "${UPSTREAM}/regex-blocked-url"
assert_status "exceptionregexpurllist overrides URL regex" 200 "${UPSTREAM}/regex-blocked-url/allowed"

note "download policy"
assert_status "bannedextensionlist blocks request path" 403 "${UPSTREAM}/download/tool.exe"
assert_status "exceptionextensionlist allows request path" 200 "${UPSTREAM}/download/file.ok"
assert_status "bannedmimetypelist blocks response headers" 403 "${UPSTREAM}/mime/exe"
assert_status "exceptionmimetypelist allows response headers" 200 "${UPSTREAM}/mime/allowed"
assert_status "bannedfilenamelist blocks Content-Disposition" 403 "${UPSTREAM}/filename/secret"

note "header and cookie policy"
assert_status "bannedheaderlist blocks request header" 403 "${UPSTREAM}/ok" -H "X-Block-Me: yes"
assert_status "exceptionheaderlist allows request header" 200 "${UPSTREAM}/header/allowed" -H "X-Block-Me: allowed"
assert_status "bannedcookiephraselist blocks request cookie" 403 "${UPSTREAM}/ok" -H "Cookie: trackid=bad"
assert_status "exceptioncookiephraselist allows request cookie" 200 "${UPSTREAM}/cookie/allowed" -H "Cookie: trackid=allowed"
assert_status "bannedheaderlist blocks response header" 403 "${UPSTREAM}/response-header/blocked"
assert_status "bannedcookiephraselist blocks Set-Cookie" 403 "${UPSTREAM}/set-cookie/blocked"

note "streaming content filters"
assert_not_contains "bannedphraselist truncates semantic response" "after" "${UPSTREAM}/semantic"
assert_not_contains "weightedphraselist threshold truncates response" "after" "${UPSTREAM}/weighted"
assert_contains "maskedphraselist masks secret" "************" "${UPSTREAM}/mask"
assert_contains "substitutionlist replaces literal text" "Barcelona public name" "${UPSTREAM}/sub"
assert_contains "regexsubstitutionlist replaces regexp text" "carcasa.png" "${UPSTREAM}/regexsub"
assert_contains "regexsubstitutionlist expands captures" "asset-42.webp" "${UPSTREAM}/regexsub"

printf '\nSummary: %d passed, %d failed\n' "${pass}" "${fail}"
printf 'LucidGate log: %s\n' "${TMPDIR}/lucidgate.log"
printf 'Upstream log:  %s\n' "${TMPDIR}/upstream.log"

if (( fail > 0 )); then
  exit 1
fi
