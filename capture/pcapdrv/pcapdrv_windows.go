//go:build windows

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

// windowsHandle adapts *pcap.Handle to Handle — gopacket's own pcap_windows.go
// dynamically loads wpcap.dll at runtime, so this stays a thin pass-through
// with no dlopen code of our own, unlike the Linux driver.
type windowsHandle struct {
	h *pcap.Handle
}

func openLive(iface string, snaplen int32, promisc bool, timeout time.Duration) (Handle, error) {
	h, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		return nil, err
	}
	return windowsHandle{h: h}, nil
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

func (d windowsHandle) SetBPFFilter(expr string) error { return d.h.SetBPFFilter(expr) }
func (d windowsHandle) LinkType() layers.LinkType      { return d.h.LinkType() }
func (d windowsHandle) Stats() (Stats, error) {
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

func (d windowsHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := d.h.ZeroCopyReadPacketData()
	if err == pcap.NextErrorTimeoutExpired { //nolint:errorlint // pcap returns this as a sentinel value, never wrapped
		return data, ci, ErrTimeoutExpired
	}
	return data, ci, err
}

func (d windowsHandle) Close() { d.h.Close() }
