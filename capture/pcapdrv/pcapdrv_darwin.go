//go:build darwin

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

// darwinHandle adapts *pcap.Handle to Handle — macOS ships libpcap as part
// of the base OS, so this stays a thin pass-through to the link-time
// binding, unlike the Linux driver.
type darwinHandle struct {
	h *pcap.Handle
}

func openLive(iface string, snaplen int32, promisc bool, timeout time.Duration) (Handle, error) {
	h, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		return nil, err
	}
	return darwinHandle{h: h}, nil
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

func (d darwinHandle) SetBPFFilter(expr string) error { return d.h.SetBPFFilter(expr) }
func (d darwinHandle) LinkType() layers.LinkType      { return d.h.LinkType() }
func (d darwinHandle) Stats() (Stats, error) {
	s, err := d.h.Stats()
	if err != nil {
		return Stats{}, err
	}
	return Stats{
		PacketsReceived:  s.PacketsReceived,
		PacketsDropped:   s.PacketsDropped,
		PacketsIfDropped: s.PacketsIfDropped,
	}, nil
}

func (d darwinHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := d.h.ZeroCopyReadPacketData()
	if err == pcap.NextErrorTimeoutExpired { //nolint:errorlint // pcap returns this as a sentinel value, never wrapped
		return data, ci, ErrTimeoutExpired
	}
	return data, ci, err
}

func (d darwinHandle) Close() { d.h.Close() }
