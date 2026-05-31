SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

APP_NAME ?= lucidgate
DESCRIPTION ?= HTTPS interception proxy with uTLS Firefox upstream fingerprinting
VERSION ?= 0.1.0
RELEASE ?= 1
MAINTAINER ?= LucidGate Maintainers <root@localhost>
HOMEPAGE ?= https://example.invalid/lucidgate

GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
GOCACHE ?= /tmp/go-build
CGO_ENABLED ?= 0

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

BUILD_DIR ?= build
DIST_DIR ?= dist
COVER_DIR ?= coverage
PKG_ROOT := $(DIST_DIR)/deb/$(APP_NAME)

BIN := $(BUILD_DIR)/$(APP_NAME)
DEB_ARCH := $(GOARCH)
ifeq ($(GOARCH),arm)
DEB_ARCH := armhf
endif
ifeq ($(GOARCH),386)
DEB_ARCH := i386
endif
DEB_FILE := $(DIST_DIR)/$(APP_NAME)_$(VERSION)-$(RELEASE)_$(DEB_ARCH).deb

GOFLAGS ?= -trimpath -buildvcs=false
LDFLAGS ?= -s -w
PKGS := ./...

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: env
env: ## Print effective build variables.
	@printf "APP_NAME=%s\nVERSION=%s\nRELEASE=%s\nGOOS=%s\nGOARCH=%s\nDEB_ARCH=%s\nGOCACHE=%s\n" "$(APP_NAME)" "$(VERSION)" "$(RELEASE)" "$(GOOS)" "$(GOARCH)" "$(DEB_ARCH)" "$(GOCACHE)"

.PHONY: deps
deps: ## Download Go module dependencies.
	GOCACHE=$(GOCACHE) $(GO) mod download

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum.
	GOCACHE=$(GOCACHE) $(GO) mod tidy

.PHONY: fmt
fmt: ## Format Go source files.
	$(GO) fmt $(PKGS)

.PHONY: fmt-check
fmt-check: ## Fail if Go source files are not gofmt-formatted.
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

.PHONY: vet
vet: ## Run go vet.
	GOCACHE=$(GOCACHE) $(GO) vet $(PKGS)

.PHONY: lint
lint: ## Run golangci-lint if it is installed.
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else echo "golangci-lint not installed; skipping"; fi

.PHONY: test
test: ## Run all tests.
	GOCACHE=$(GOCACHE) $(GO) test $(PKGS)

.PHONY: test-race
test-race: ## Run tests with the race detector.
	GOCACHE=$(GOCACHE) $(GO) test -race $(PKGS)

.PHONY: smoke
smoke: build ## Run an end-to-end smoke test against the built binary.
	LUCIDGATE_BIN=$$(pwd)/$(BIN) GOCACHE=$(GOCACHE) $(GO) test -count=1 ./smoke

.PHONY: ws-smoke
ws-smoke: build ## Run the binary WebSocket smoke test.
	LUCIDGATE_BIN=$$(pwd)/$(BIN) GOCACHE=$(GOCACHE) $(GO) test -count=1 ./smoke -run TestBinaryWebSocketSmoke

.PHONY: alt-svc-smoke
alt-svc-smoke: build ## Run the binary Alt-Svc stripping smoke test.
	LUCIDGATE_BIN=$$(pwd)/$(BIN) GOCACHE=$(GOCACHE) $(GO) test -count=1 ./smoke -run TestBinaryAltSvcSmokeStripsHTTP3Advertising

.PHONY: curl-policy
curl-policy: build ## Run the curl-based e2guardian policy battery.
	LUCIDGATE_BIN=$$(pwd)/$(BIN) scripts/curl_policy_battery.sh

.PHONY: p0-smoke
p0-smoke: ws-smoke alt-svc-smoke curl-policy ## Run the P0 WebSocket, Alt-Svc, and policy smokes.

.PHONY: cover
cover: ## Run tests with coverage and write coverage/coverage.out.
	mkdir -p $(COVER_DIR)
	GOCACHE=$(GOCACHE) $(GO) test -covermode=atomic -coverprofile=$(COVER_DIR)/coverage.out $(PKGS)
	GOCACHE=$(GOCACHE) $(GO) tool cover -func=$(COVER_DIR)/coverage.out

.PHONY: cover-html
cover-html: cover ## Generate HTML coverage report at coverage/coverage.html.
	GOCACHE=$(GOCACHE) $(GO) tool cover -html=$(COVER_DIR)/coverage.out -o $(COVER_DIR)/coverage.html

.PHONY: bench
bench: ## Run benchmarks.
	GOCACHE=$(GOCACHE) $(GO) test -run '^$$' -bench=. -benchmem $(PKGS)

.PHONY: verify
verify: fmt-check vet test smoke ## Run standard verification checks plus smoke test.

.PHONY: build
build: ## Build the local binary.
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) .

.PHONY: build-debug
build-debug: ## Build without stripped symbols for debugging.
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOCACHE=$(GOCACHE) $(GO) build -o $(BIN)-debug .

.PHONY: build-all
build-all: ## Build common Linux release binaries.
	mkdir -p $(DIST_DIR)
	for arch in amd64 arm64 arm; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)_linux_$$arch . ; \
	done

.PHONY: run
run: ## Run the proxy locally on 127.0.0.1:8080.
	GOCACHE=$(GOCACHE) $(GO) run .

.PHONY: install
install: build ## Install the binary to DESTDIR/PREFIX.
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(APP_NAME)

.PHONY: uninstall
uninstall: ## Remove the installed binary from DESTDIR/PREFIX.
	rm -f $(DESTDIR)$(BINDIR)/$(APP_NAME)

.PHONY: ca-info
ca-info: ## Print information about certs/ca.crt if it exists.
	@test -f certs/ca.crt || { echo "certs/ca.crt does not exist. Run make run once to generate it."; exit 1; }
	openssl x509 -in certs/ca.crt -noout -subject -issuer -dates -fingerprint -sha256

.PHONY: cert-clean
cert-clean: ## Remove the local generated CA files under certs/.
	rm -rf certs

.PHONY: package-tree
package-tree: build ## Create the Debian package filesystem tree under dist/deb.
	rm -rf $(PKG_ROOT)
	install -d $(PKG_ROOT)/DEBIAN
	install -d $(PKG_ROOT)/usr/bin
	install -d $(PKG_ROOT)/usr/share/doc/$(APP_NAME)
	install -d $(PKG_ROOT)/lib/systemd/system
	install -d $(PKG_ROOT)/var/lib/$(APP_NAME)
	install -m 0755 $(BIN) $(PKG_ROOT)/usr/bin/$(APP_NAME)
	install -m 0644 README.md $(PKG_ROOT)/usr/share/doc/$(APP_NAME)/README.md
	printf '%s\n' \
		'Package: $(APP_NAME)' \
		'Version: $(VERSION)-$(RELEASE)' \
		'Section: net' \
		'Priority: optional' \
		'Architecture: $(DEB_ARCH)' \
		'Maintainer: $(MAINTAINER)' \
		'Depends: ca-certificates' \
		'Homepage: $(HOMEPAGE)' \
		'Description: $(DESCRIPTION)' \
		' Local HTTPS interception proxy for controlled blue-team analysis.' \
		' It generates a local CA, presents dynamic leaf certificates,' \
		' and uses uTLS to mimic a Firefox ClientHello upstream.' \
		> $(PKG_ROOT)/DEBIAN/control
	printf '%s\n' \
		'[Unit]' \
		'Description=LucidGate HTTPS interception proxy' \
		'After=network-online.target' \
		'Wants=network-online.target' \
		'' \
		'[Service]' \
		'Type=simple' \
		'User=$(APP_NAME)' \
		'Group=$(APP_NAME)' \
		'WorkingDirectory=/var/lib/$(APP_NAME)' \
		'ExecStart=/usr/bin/$(APP_NAME) --listen=127.0.0.1:8080 --cert-dir=/var/lib/$(APP_NAME)/certs --max-capture-bytes=1048576' \
		'Restart=on-failure' \
		'RestartSec=2s' \
		'NoNewPrivileges=true' \
		'PrivateTmp=true' \
		'ProtectSystem=full' \
		'ProtectHome=true' \
		'ReadWritePaths=/var/lib/$(APP_NAME)' \
		'' \
		'[Install]' \
		'WantedBy=multi-user.target' \
		> $(PKG_ROOT)/lib/systemd/system/$(APP_NAME).service
	printf '%s\n' \
		'#!/bin/sh' \
		'set -e' \
		'if ! getent group $(APP_NAME) >/dev/null 2>&1; then groupadd --system $(APP_NAME) >/dev/null 2>&1 || true; fi' \
		'if ! getent passwd $(APP_NAME) >/dev/null 2>&1; then useradd --system --gid $(APP_NAME) --home-dir /var/lib/$(APP_NAME) --shell /usr/sbin/nologin $(APP_NAME) >/dev/null 2>&1 || true; fi' \
		'chown $(APP_NAME):$(APP_NAME) /var/lib/$(APP_NAME) >/dev/null 2>&1 || true' \
		'if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi' \
		'exit 0' \
		> $(PKG_ROOT)/DEBIAN/postinst
	printf '%s\n' \
		'#!/bin/sh' \
		'set -e' \
		'if [ "$$1" = "remove" ] || [ "$$1" = "deconfigure" ]; then' \
		'  if command -v systemctl >/dev/null 2>&1; then systemctl stop $(APP_NAME).service >/dev/null 2>&1 || true; fi' \
		'fi' \
		'exit 0' \
		> $(PKG_ROOT)/DEBIAN/prerm
	printf '%s\n' \
		'#!/bin/sh' \
		'set -e' \
		'if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi' \
		'exit 0' \
		> $(PKG_ROOT)/DEBIAN/postrm
	chmod 0755 $(PKG_ROOT)/DEBIAN/postinst $(PKG_ROOT)/DEBIAN/prerm $(PKG_ROOT)/DEBIAN/postrm
	chmod 0644 $(PKG_ROOT)/DEBIAN/control $(PKG_ROOT)/lib/systemd/system/$(APP_NAME).service $(PKG_ROOT)/usr/share/doc/$(APP_NAME)/README.md
	find $(PKG_ROOT) -type d -exec chmod 0755 {} +

.PHONY: deb
deb: package-tree ## Build a Debian .deb package in dist/.
	@command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required to build .deb packages"; exit 1; }
	mkdir -p $(DIST_DIR)
	dpkg-deb --build --root-owner-group $(PKG_ROOT) $(DEB_FILE)
	@echo "Built $(DEB_FILE)"

.PHONY: deb-clean
deb-clean: ## Remove Debian package staging files.
	rm -rf $(DIST_DIR)/deb

.PHONY: clean
clean: ## Remove build, dist and coverage artifacts.
	rm -rf $(BUILD_DIR) $(DIST_DIR) $(COVER_DIR)

.PHONY: release
release: clean verify build-all deb ## Run verification and produce release artifacts.

.PHONY: bench-load
bench-load: build ## Run the high-performance load and leak benchmark suite.
	$(GO) run bench/load_bench.go -mode=all

.PHONY: bench-attacks
bench-attacks: ## Run the Slowloris, Slow-POST, and HTTP/2 Rapid Reset attacks.
	$(GO) run bench/attacks.go -type=all

.PHONY: bench-degradation
bench-degradation: build ## Run the elegant degradation suite at 200% capacity.
	$(GO) run bench/degradation.go

.PHONY: bench-profile
bench-profile: ## Collect CPU and heap pprof profiles.
	$(GO) run bench/profile.go -seconds=5

.PHONY: bench-all
bench-all: bench-load bench-attacks bench-degradation ## Run all benchmarks and resilience test suites.

