//go:build linux && !arm64

package procinfo

import "errors"

// attachKprobeConnect is a stub on every architecture except arm64:
// procinfo/bpf/kprobe's generated bindings are currently arm64-only (bpf2go
// couldn't produce an amd64 struct pt_regs layout from this dev
// environment's aarch64-sourced vmlinux.h -- see
// procinfo/bpf/kprobe/gen_linux.go), so the kprobe/kretprobe fallback is
// best-effort/arm64-only for now, not a bug to fix here. On a kernel
// without BTF fentry/fexit support, this leaves eBPF attach entirely
// unavailable on this architecture and NewEBPFSource returns an error, so
// the caller falls back to *procinfo.Poller as usual.
func (s *EBPFSource) attachKprobeConnect() error {
	return errors.New("kprobe/kretprobe fallback is not available on this architecture (arm64-only for now)")
}
