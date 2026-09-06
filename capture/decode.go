package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ipv6HeaderLen is the size of the fixed IPv6 header. The IPv6 Length field
// counts only what follows that header, unlike IPv4's, so it has to be added
// back to get a datagram size comparable with IPv4's.
const ipv6HeaderLen = 40

// errShortTransport reports a transport header cut short by the snap length,
// leaving no ports to read.
var errShortTransport = errors.New("transport header too short for ports")

// packetInfo is the slice of a packet the flow table cares about.
type packetInfo struct {
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   Proto

	// SYN, ACK and RST are the TCP flags of the same name, meaningful only
	// when Proto is ProtoTCP — UDP/ICMP/ARP have no TCP flags to read.
	SYN bool
	ACK bool
	RST bool

	// Bytes is the size of the whole IP datagram — IP header, transport
	// header and payload — taken from the IP header's own length field.
	//
	// It deliberately is not the captured length: that excludes link-layer
	// framing, so the same connection totals the same whether it was seen
	// over Ethernet or over the loopback pseudo-header. It also still holds
	// even for the rare packet SnapLen truncates (a jumbo frame, or a
	// ClientHello with enough extensions to run past it) — len(data) alone
	// would undercount those.
	//
	// ARP has no length field of its own to read here, so it uses
	// arpFrameBytes instead — see the ARP case in decode.
	Bytes uint64
}

// arpFrameBytes is the fixed size of a standard Ethernet/IPv4 ARP packet: an
// 8-byte header plus two (6-byte MAC + 4-byte IP) address pairs. It stands in
// for packetInfo.Bytes, which ARP has no length field to supply, and is safe
// at any realistic SnapLen since the whole frame is smaller than the default.
const arpFrameBytes = 28

// tcpFlagSYN, tcpFlagACK and tcpFlagRST are the bit positions of the SYN,
// ACK and RST flags within a TCP header's flags byte (offset 13).
const (
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
	tcpFlagRST = 0x04
)

// transportPorts is a minimal DecodingLayer for TCP and UDP that reads the
// source and destination ports, plus (for TCP) the flags byte, and stops.
//
// gopacket's own layers.TCP decoder fails a packet whose options run past the
// captured bytes, which would silently drop long-header packets from the flow
// table whenever SnapLen is tight. Only the first four bytes of either header
// matter for the ports, and those two layouts agree on them, so one decoder
// serves both and truncation stops mattering. flags is read from offset 13,
// which exists in any packet not truncated inside the TCP header itself —
// UDP's own bytes at that offset are unrelated (its length/checksum fields)
// and are simply never consulted for a UDP packet; see decode's TCP case.
type transportPorts struct {
	src   uint16
	dst   uint16
	flags byte
}

// DecodeFromBytes implements gopacket.DecodingLayer.
func (t *transportPorts) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		df.SetTruncated()
		return errShortTransport
	}
	t.src = binary.BigEndian.Uint16(data[0:2])
	t.dst = binary.BigEndian.Uint16(data[2:4])
	if len(data) >= 14 {
		t.flags = data[13]
	}
	return nil
}

// CanDecode implements gopacket.DecodingLayer.
func (t *transportPorts) CanDecode() gopacket.LayerClass {
	return gopacket.NewLayerClass([]gopacket.LayerType{layers.LayerTypeTCP, layers.LayerTypeUDP})
}

// NextLayerType implements gopacket.DecodingLayer. There is nothing below the
// ports worth decoding.
func (t *transportPorts) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// LayerPayload implements gopacket.DecodingLayer. Returning nothing ends the
// parser's decode loop.
func (t *transportPorts) LayerPayload() []byte { return nil }

// flowDecoder turns raw capture bytes into a packetInfo. It reuses one set of
// layer structs across every packet, so it must not be shared between the
// per-interface capture goroutines.
type flowDecoder struct {
	eth   layers.Ethernet
	loop  layers.Loopback
	dot1q layers.Dot1Q
	ip4   layers.IPv4
	ip6   layers.IPv6
	ports transportPorts
	icmp4 layers.ICMPv4
	icmp6 layers.ICMPv6
	arp   layers.ARP

	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	// linkType is the pcap handle's link type, kept alongside the decoder so
	// DPI inspectors can build a gopacket.Packet from raw capture bytes
	// without re-deriving it per packet.
	linkType layers.LinkType
}

// newFlowDecoder builds a decoder for the link type of one pcap handle.
func newFlowDecoder(linkType layers.LinkType) (*flowDecoder, error) {
	var first gopacket.LayerType
	switch linkType {
	case layers.LinkTypeEthernet:
		first = layers.LayerTypeEthernet
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		// lo0 and the utun tunnels carry a 4-byte address-family header
		// instead of an Ethernet one.
		first = layers.LayerTypeLoopback
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		first = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		first = layers.LayerTypeIPv6
	default:
		return nil, fmt.Errorf("unsupported link type %s", linkType)
	}

	d := &flowDecoder{decoded: make([]gopacket.LayerType, 0, 4), linkType: linkType}
	d.parser = gopacket.NewDecodingLayerParser(first,
		&d.eth, &d.loop, &d.dot1q, &d.ip4, &d.ip6, &d.ports, &d.icmp4, &d.icmp6, &d.arp)
	// Anything with no decoder here — ESP, an exotic IPv6 extension header —
	// is not a flow we count, so stopping quietly beats erroring.
	d.parser.IgnoreUnsupported = true

	return d, nil
}

// decode extracts the 5-tuple and datagram size from one captured packet. It
// reports false for anything that is not a complete-enough TCP, UDP, ICMP or
// ARP packet, which the caller should simply skip.
func (d *flowDecoder) decode(data []byte) (packetInfo, bool) {
	if err := d.parser.DecodeLayers(data, &d.decoded); err != nil {
		return packetInfo{}, false
	}

	var (
		info          packetInfo
		haveNet       bool
		haveTransport bool
	)
	for _, typ := range d.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			src, okSrc := netip.AddrFromSlice(d.ip4.SrcIP)
			dst, okDst := netip.AddrFromSlice(d.ip4.DstIP)
			if !okSrc || !okDst {
				return packetInfo{}, false
			}
			info.Src, info.Dst = src.Unmap(), dst.Unmap()
			info.Bytes = uint64(d.ip4.Length)
			haveNet = true

		case layers.LayerTypeIPv6:
			src, okSrc := netip.AddrFromSlice(d.ip6.SrcIP)
			dst, okDst := netip.AddrFromSlice(d.ip6.DstIP)
			if !okSrc || !okDst {
				return packetInfo{}, false
			}
			info.Src, info.Dst = src.Unmap(), dst.Unmap()
			info.Bytes = uint64(d.ip6.Length) + ipv6HeaderLen
			haveNet = true

		case layers.LayerTypeTCP:
			info.Proto = ProtoTCP
			info.SYN = d.ports.flags&tcpFlagSYN != 0
			info.ACK = d.ports.flags&tcpFlagACK != 0
			info.RST = d.ports.flags&tcpFlagRST != 0
			haveTransport = true

		case layers.LayerTypeUDP:
			info.Proto = ProtoUDP
			haveTransport = true

		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			// Ports stay zero: ICMP has none. haveNet is already set by the
			// IPv4/IPv6 case that necessarily preceded this one.
			info.Proto = ProtoICMP
			haveTransport = true

		case layers.LayerTypeARP:
			// ARP has no IP layer to supply Src/Dst/Bytes, so this case
			// stands in for both halves at once.
			src, okSrc := netip.AddrFromSlice(d.arp.SourceProtAddress)
			dst, okDst := netip.AddrFromSlice(d.arp.DstProtAddress)
			if !okSrc || !okDst {
				return packetInfo{}, false
			}
			info.Src, info.Dst = src.Unmap(), dst.Unmap()
			info.Proto = ProtoARP
			info.Bytes = arpFrameBytes
			haveNet = true
			haveTransport = true
		}
	}

	// A packet missing either half is unattributable: an IP-only packet has
	// no ports to join a process on, and ports without addresses cannot be
	// pointed at a peer.
	if !haveNet || !haveTransport {
		return packetInfo{}, false
	}

	info.SrcPort, info.DstPort = d.ports.src, d.ports.dst
	return info, true
}
