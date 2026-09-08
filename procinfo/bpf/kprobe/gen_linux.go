// Package kprobe holds the compiled kprobe/kretprobe fallback BPF object
// attributing outbound TCP connects on kernels without usable BTF, and its
// bpf2go-generated Go bindings. See connect_kprobe.c for the program source
// and why it's a separate compiled object from ../fentry and ../sockstate.
package kprobe

// Unlike ../fentry and ../sockstate, connect_kprobe.c can't share one
// vmlinux.h across -target arches: BPF_KPROBE/BPF_KRETPROBE read struct
// pt_regs directly (no CO-RE relocation), so the header must supply the
// real per-architecture pt_regs layout -- see connect_kprobe.c's #include
// and ../headers/vmlinux_amd64.h's file comment for how each arch's header
// was produced.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event -target amd64,arm64 -cc clang Kprobe connect_kprobe.c -- -I../headers -Wall
