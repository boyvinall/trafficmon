// Package sockstate holds the compiled inet_sock_set_state tracepoint BPF
// object, attached the same way regardless of which connect-hook mode
// (../fentry or ../kprobe) is active, and its bpf2go-generated Go bindings.
// See sockstate_tracepoint.c for the program source and why it's a separate
// compiled object from ../fentry and ../kprobe.
package sockstate

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event -target amd64,arm64 -cc clang Sockstate sockstate_tracepoint.c -- -I../headers -Wall
