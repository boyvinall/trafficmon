//go:build linux

package pcapdrv

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func init() {
	OpenLive = openLive
	FindAllDevs = findAllDevs
}

// linuxHandle adapts *pcap.Handle to Handle — a thin pass-through to the
// link-time binding, matching pcapdrv_darwin.go's shape. libpcap is linked
// in at build time (statically, for release builds — see .goreleaser.yaml),
// so it's already part of the binary rather than a runtime dependency.
type linuxHandle struct {
	h *pcap.Handle
}

func openLive(iface string, snaplen int32, promisc bool, timeout time.Duration) (Handle, error) {
	h, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		return nil, err
	}
	return linuxHandle{h: h}, nil
}

func findAllDevs() ([]string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(devs))
	for _, d := range devs {
		names = append(names, d.Name)
	}
	return names, nil
}

func (l linuxHandle) SetBPFFilter(expr string) error { return l.h.SetBPFFilter(expr) }
func (l linuxHandle) LinkType() layers.LinkType      { return l.h.LinkType() }
func (l linuxHandle) Stats() (Stats, error) {
	s, err := l.h.Stats()
	if err != nil {
		return Stats{}, err
	}
	return Stats{
		PacketsReceived:  s.PacketsReceived,
		PacketsDropped:   s.PacketsDropped,
		PacketsIfDropped: s.PacketsIfDropped,
	}, nil
}

func (l linuxHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := l.h.ZeroCopyReadPacketData()
	if err == pcap.NextErrorTimeoutExpired { //nolint:errorlint // pcap returns this as a sentinel value, never wrapped
		return data, ci, ErrTimeoutExpired
	}
	return data, ci, err
}

func (l linuxHandle) Close() { l.h.Close() }
