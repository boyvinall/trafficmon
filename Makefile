MODULE  := github.com/boyvinall/trafficmon
BINARY  := trafficmon
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
MODULE_DIRS := . cmd/trafficmon receiver cmd/otel-collector

OCB_VERSION := v0.119.0

.PHONY: help all build lint test clean run bpf-generate generate-otel-collector build-otel-collector

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
