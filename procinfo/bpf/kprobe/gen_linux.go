// Package kprobe holds the compiled kprobe/kretprobe fallback BPF object
// attributing outbound TCP connects on kernels without usable BTF, and its
// bpf2go-generated Go bindings. See connect_kprobe.c for the program source
// and why it's a separate compiled object from ../fentry and ../sockstate.
package kprobe

// amd64 is deliberately not in -target: BPF_KPROBE/BPF_KRETPROBE read
// struct pt_regs, whose field layout is architecture-specific (x86_64's
// `di`/`ax` vs. arm64's `regs[N]`), and that struct comes from
// ../headers/vmlinux.h, which was dumped from this dev environment's own
// (aarch64) kernel BTF -- it has no x86_64 pt_regs to offer. Compiling for
// amd64 here fails with "no member named 'di' in 'struct pt_regs'", not a
// verifier or logic bug. Producing an amd64 object needs a vmlinux.h
// generated from an actual (or BTF-capable emulated) x86_64 kernel; add
// that target back once one is available.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event -target arm64 -cc clang Kprobe connect_kprobe.c -- -I../headers -Wall
