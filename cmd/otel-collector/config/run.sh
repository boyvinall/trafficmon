#!/usr/bin/env bash
# Builds the trafficmon-otelcol distribution and runs it against
# config/example.yaml. Packet capture needs root, same as `make run` for the
# TUI, so this re-execs itself under sudo.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)

make -C "$repo_root" build-otel-collector

exec sudo "$repo_root/bin/trafficmon-otelcol" --config "$script_dir/example.yaml"
