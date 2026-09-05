// Package fentry holds the compiled BTF fentry/fexit BPF object attributing
// outbound TCP connects, and its bpf2go-generated Go bindings. See
// connect_fentry.c for the program source and why it's a separate compiled
// object from ../kprobe and ../sockstate.
package fentry

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event -target amd64,arm64 -cc clang Fentry connect_fentry.c -- -I../headers -Wall
