//go:build linux && !amd64 && !arm64

package procinfo

import "errors"

// attachKprobeConnect is a stub on every architecture except amd64/arm64:
// procinfo/bpf/kprobe only has a real per-arch vmlinux.h (needed for
// BPF_KPROBE/BPF_KRETPROBE's direct struct pt_regs reads -- see
// procinfo/bpf/kprobe/gen_linux.go) for those two, so the kprobe/kretprobe
// fallback is best-effort there for now, not a bug to fix here. On a kernel
// without BTF fentry/fexit support, this leaves eBPF attach entirely
// unavailable on this architecture and NewEBPFSource returns an error, so
// the caller falls back to *procinfo.Poller as usual.
func (s *EBPFSource) attachKprobeConnect() error {
	return errors.New("kprobe/kretprobe fallback is not available on this architecture (amd64/arm64 only for now)")
}
