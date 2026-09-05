//go:build linux && arm64

package procinfo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/boyvinall/trafficmon/procinfo/bpf/kprobe"
)

func decodeKprobeEvent(raw []byte) (ebpfEvent, error) {
	var e kprobe.KprobeEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return ebpfEvent{}, err
	}
	return ebpfEvent{
		SKAddr: e.Skaddr,
		Pid:    e.Pid, IPVer: e.IpVer,
		LocalPort: e.LocalPort, RemotePort: e.RemotePort,
		LocalAddr: e.LocalAddr, RemoteAddr: e.RemoteAddr,
		NewState: e.NewState,
	}, nil
}

// attachKprobeConnect attaches the kprobe/kretprobe fallback for outbound
// TCP connects, used when fentry/fexit isn't available (no BTF, or its
// attach failed). arm64-only: procinfo/bpf/kprobe's generated bindings are
// currently arm64-only -- see procinfo/bpf/kprobe/gen_linux.go's comment on
// why an amd64 object can't be produced from this dev environment's
// aarch64-sourced vmlinux.h -- see ebpf_kprobe_other_linux.go for the stub
// every other architecture builds instead.
func (s *EBPFSource) attachKprobeConnect() error {
	var objs kprobe.KprobeObjects
	if err := kprobe.LoadKprobeObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading kprobe/kretprobe objects: %w", describeVerifierError(err))
	}

	type probe struct {
		name string
		sym  string
		prog *ebpf.Program
		ret  bool
	}
	probes := []probe{
		{"kprobe_tcp_v4_connect", "tcp_v4_connect", objs.KprobeTcpV4Connect, false},
		{"kprobe_tcp_v6_connect", "tcp_v6_connect", objs.KprobeTcpV6Connect, false},
		{"kretprobe_tcp_v4_connect", "tcp_v4_connect", objs.KretprobeTcpV4Connect, true},
		{"kretprobe_tcp_v6_connect", "tcp_v6_connect", objs.KretprobeTcpV6Connect, true},
	}

	var links []io.Closer
	closeLinks := func() {
		for _, l := range links {
			_ = l.Close()
		}
	}
	for _, p := range probes {
		var l link.Link
		var err error
		if p.ret {
			l, err = link.Kretprobe(p.sym, p.prog, nil)
		} else {
			l, err = link.Kprobe(p.sym, p.prog, nil)
		}
		if err != nil {
			closeLinks()
			_ = objs.Close()
			return fmt.Errorf("attaching %q to %s: %w", p.name, p.sym, err)
		}
		links = append(links, l)
	}

	r, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		closeLinks()
		_ = objs.Close()
		return fmt.Errorf("opening kprobe ring buffer: %w", err)
	}

	s.closers = append(s.closers, links...)
	s.closers = append(s.closers, &objs)
	s.rings = append(s.rings, ringSource{reader: r, decode: decodeKprobeEvent})
	return nil
}
