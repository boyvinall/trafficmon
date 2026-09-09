MODULE  := github.com/boyvinall/trafficmon
BINARY  := trafficmon
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
MODULE_DIRS := . cmd/trafficmon receiver cmd/otel-collector

OCB_VERSION := v0.119.0

# goreleaser refuses to build at all without a reachable tag. CI's checkout
# has no tags (default shallow, non-tag checkout); release.yml's does (tags
# fetched, checked out at the release tag), so this expands to empty there.
GORELEASER_SNAPSHOT_FLAG := $(shell git describe --tags >/dev/null 2>&1 || echo --snapshot)

.PHONY: help all build lint test clean run bpf-generate generate-otel-collector build-otel-collector release-build release-build-linux

define PROMPT
	@echo
	@echo "**********************************************************"
	@echo "*"
	@echo "*   $(1)"
	@echo "*"
	@echo "**********************************************************"
	@echo
endef

#: build, lint, and test (default)
all: build build-otel-collector lint test

#: compile for the current platform
build:
	$(call PROMPT, $@)
	cd cmd/trafficmon && go build -ldflags "$(LDFLAGS)" -o ../../bin/$(BINARY) .

#: build then run under sudo (packet capture needs root)
run: build
	$(call PROMPT, $@)
	sudo ./bin/$(BINARY)

#: regenerate the ocb collector distribution sources (go.mod/go.sum, components.go, main*.go) from cmd/otel-collector/builder-config.yaml -- these are gitignored, not committed, so lint/test/build-otel-collector need this first on a fresh checkout
generate-otel-collector:
	$(call PROMPT, $@)
	cd cmd/otel-collector && go run go.opentelemetry.io/collector/cmd/builder@$(OCB_VERSION) --config builder-config.yaml --skip-compilation && go mod tidy

#: regenerate and compile the custom OpenTelemetry Collector distribution
build-otel-collector: generate-otel-collector
	$(call PROMPT, $@)
	cd cmd/otel-collector && go build -o ../../bin/trafficmon-otelcol .

#: run all linters, across all modules
lint: generate-otel-collector
	$(call PROMPT, $@)
	for d in $(MODULE_DIRS); do (cd $$d && golangci-lint run ./...) || exit 1; done

#: run all tests, across all modules
test: generate-otel-collector
	$(call PROMPT, $@)
	for d in $(MODULE_DIRS); do (cd $$d && go test ./...) || exit 1; done

#: cross-build the current platform's release variant via goreleaser (the darwin/windows builds in .goreleaser.yaml); needs goreleaser on PATH
release-build:
	$(call PROMPT, $@)
	goreleaser build --single-target --clean $(GORELEASER_SNAPSHOT_FLAG)

#: statically-linked linux release variant (netgo + static libpcap) via goreleaser; run inside an Alpine/musl container so the binary carries no glibc symbol-versioning floor -- regenerates eBPF bindings first
release-build-linux: bpf-generate
	$(call PROMPT, $@)
	goreleaser build --single-target --clean --id trafficmon-linux $(GORELEASER_SNAPSHOT_FLAG)

#: remove build artifacts
clean:
	$(call PROMPT, $@)
	rm -rf bin/ dist/

#: regenerate procinfo/bpf's bpf2go bindings + compiled BPF objects (Linux + BTF + clang/llvm/libbpf-dev/bpftool only; not part of `build`/`all` since the toolchain isn't available on a normal macOS dev machine -- CI runs this explicitly before building on the Linux leg)
bpf-generate:
	$(call PROMPT, $@)
	go generate ./procinfo/bpf/...

#: print Makefile targets and short descriptions
help:
	@echo "make targets:\n"
	@awk '/^#:[[:space:]]/ { sub(/^#:[[:space:]]*/, ""); desc=$$0; next } \
		/^[[:space:]]*$$/ { next } \
		/^#/ { next } \
		/^[a-zA-Z][a-zA-Z0-9_.-]*:/ { \
			if (desc != "") { \
				split($$0, a, ":"); \
				tgt=a[1]; \
				gsub(/^[[:space:]]+|[[:space:]]+$$/, "", tgt); \
				printf "  %-18s %s\n", tgt, desc; \
				desc="" \
			} \
		}' $(firstword $(MAKEFILE_LIST))
