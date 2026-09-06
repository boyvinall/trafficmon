// Package pcapdrv is the OS-agnostic seam capture/pcap.go uses to open a
// live pcap handle: a shared Handle interface with one implementation per
// OS, mirroring the procinfo/route_*.go split so callers never branch on
// GOOS themselves. On Linux, the implementation loads libpcap via dlopen at
// runtime instead of linking against it, so a missing libpcap.so produces a
// clean Go error instead of the dynamic linker refusing to exec the binary
// at all — see pcapdrv_linux.go.
package pcapdrv

import (
	"errors"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Handle is the subset of a live pcap capture handle capture/pcap.go uses.
type Handle interface {
	SetBPFFilter(expr string) error
	LinkType() layers.LinkType
	Stats() (Stats, error)
	// ZeroCopyReadPacketData returns the next packet. The returned data is
	// only valid until the handle's next read — see capture/pcap.go's own
	// doc comment on ZeroCopyReadPacketData for why that's safe here.
	ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	Close()
}

// Stats is one handle's cumulative packet counters, in the same units as
// capture.PacketStats.
type Stats struct {
	PacketsReceived  int
	PacketsDropped   int
	PacketsIfDropped int
}

// ErrTimeoutExpired is returned from ZeroCopyReadPacketData when the read
// timeout passed to OpenLive elapses with no packet — not a real error,
// captureOn's read loop just comes up for air and checks ctx.
var ErrTimeoutExpired = errors.New("pcapdrv: read timeout expired")

// OpenLive and FindAllDevs are package-level vars (not plain funcs) purely
// so existing tests that stub library access can keep doing so the same way
// capture/route_*.go's runRoute already does; each is set per-OS in
// pcapdrv_{darwin,linux}.go's init.
var (
	OpenLive    func(iface string, snaplen int32, promisc bool, timeout time.Duration) (Handle, error)
	FindAllDevs func() ([]string, error)
)
