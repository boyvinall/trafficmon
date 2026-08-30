MODULE  := github.com/boyvinall/mac-nethogs
BINARY  := mac-nethogs
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help all build lint test clean run

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
all: build lint test

#: compile for the current platform
build:
	$(call PROMPT, $@)
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

#: build then run under sudo (packet capture needs root)
run: build
	$(call PROMPT, $@)
	sudo ./bin/$(BINARY)

#: run all linters
lint:
	$(call PROMPT, $@)
	golangci-lint run ./...

#: run all tests
test:
	$(call PROMPT, $@)
	go test ./...

#: remove build artifacts
clean:
	$(call PROMPT, $@)
	rm -rf bin/ dist/

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
