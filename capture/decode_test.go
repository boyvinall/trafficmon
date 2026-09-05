package capture

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// serialize builds a wire-format packet out of the given layers.
func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

func ethernet(next layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: next,
	}
}

func ipv4(proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: proto,
		SrcIP:    net.IP{192, 168, 1, 10},
		DstIP:    net.IP{140, 82, 112, 3},
	}
}

func ipv6(proto layers.IPProtocol) *layers.IPv6 {
	return &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: proto,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2606:4700::1111"),
	}
}

func TestFlowDecoderDecode(t *testing.T) {
	payload := gopacket.Payload(bytes.Repeat([]byte{0xAB}, 100))
	tcp := &layers.TCP{SrcPort: 51000, DstPort: 443}
	udp := &layers.UDP{SrcPort: 5353, DstPort: 53}

	tests := []struct {
		name     string
		linkType layers.LinkType
		data     []byte
		want     packetInfo
	}{
		{
			name:     "ethernet ipv4 tcp",
			linkType: layers.LinkTypeEthernet,
			data:     serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP), tcp, payload),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "140.82.112.3"),
				SrcPort: 51000, DstPort: 443, Proto: ProtoTCP,
				// 20 byte IPv4 header + 20 byte TCP header + payload.
				Bytes: 20 + 20 + 100,
			},
		},
		{
			name:     "ethernet ipv4 udp",
			linkType: layers.LinkTypeEthernet,
			data:     serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolUDP), udp, payload),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "140.82.112.3"),
				SrcPort: 5353, DstPort: 53, Proto: ProtoUDP,
				// 20 byte IPv4 header + 8 byte UDP header + payload.
				Bytes: 20 + 8 + 100,
			},
		},
		{
			name:     "ethernet ipv6 tcp",
			linkType: layers.LinkTypeEthernet,
			data:     serialize(t, ethernet(layers.EthernetTypeIPv6), ipv6(layers.IPProtocolTCP), tcp, payload),
			want: packetInfo{
				Src: mustAddr(t, "2001:db8::1"), Dst: mustAddr(t, "2606:4700::1111"),
				SrcPort: 51000, DstPort: 443, Proto: ProtoTCP,
				// The IPv6 Length field excludes the fixed header, so the
				// decoder has to add it back to match the IPv4 accounting.
				Bytes: 40 + 20 + 100,
			},
		},
		{
			name:     "loopback ipv4 tcp",
			linkType: layers.LinkTypeNull,
			data: serialize(t,
				&layers.Loopback{Family: layers.ProtocolFamilyIPv4},
				ipv4(layers.IPProtocolTCP), tcp, payload),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "140.82.112.3"),
				SrcPort: 51000, DstPort: 443, Proto: ProtoTCP,
				Bytes: 20 + 20 + 100,
			},
		},
		{
			name:     "raw ipv4 tcp",
			linkType: layers.LinkTypeRaw,
			data:     serialize(t, ipv4(layers.IPProtocolTCP), tcp, payload),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "140.82.112.3"),
				SrcPort: 51000, DstPort: 443, Proto: ProtoTCP,
				Bytes: 20 + 20 + 100,
			},
		},
		{
			name:     "ipv4 link type is treated the same as raw",
			linkType: layers.LinkTypeIPv4,
			data:     serialize(t, ipv4(layers.IPProtocolUDP), udp, payload),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "140.82.112.3"),
				SrcPort: 5353, DstPort: 53, Proto: ProtoUDP,
				Bytes: 20 + 8 + 100,
			},
		},
		{
			name:     "native ipv6 link type tcp",
			linkType: layers.LinkTypeIPv6,
			data:     serialize(t, ipv6(layers.IPProtocolTCP), tcp, payload),
			want: packetInfo{
				Src: mustAddr(t, "2001:db8::1"), Dst: mustAddr(t, "2606:4700::1111"),
				SrcPort: 51000, DstPort: 443, Proto: ProtoTCP,
				Bytes: 40 + 20 + 100,
			},
		},
		{
			name:     "vlan tagged ipv4 tcp",
			linkType: layers.LinkTypeEthernet,
			data: serialize(t,
				ethernet(layers.EthernetTypeDot1Q),
				&layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv4},
				ipv4(layers.IPProtocolTCP), tcp, payload),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "140.82.112.3"),
				SrcPort: 51000, DstPort: 443, Proto: ProtoTCP,
				Bytes: 20 + 20 + 100,
			},
		},
		{
			name:     "ethernet ipv4 icmp",
			linkType: layers.LinkTypeEthernet,
			data: serialize(t,
				ethernet(layers.EthernetTypeIPv4),
				ipv4(layers.IPProtocolICMPv4),
				&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}, payload),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "140.82.112.3"),
				Proto: ProtoICMP,
				// 20 byte IPv4 header + 8 byte ICMPv4 header + payload.
				Bytes: 20 + 8 + 100,
			},
		},
		{
			name:     "ethernet ipv6 icmp",
			linkType: layers.LinkTypeEthernet,
			data: serialize(t,
				ethernet(layers.EthernetTypeIPv6),
				ipv6(layers.IPProtocolICMPv6),
				&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}, payload),
			want: packetInfo{
				Src: mustAddr(t, "2001:db8::1"), Dst: mustAddr(t, "2606:4700::1111"),
				Proto: ProtoICMP,
				Bytes: 40 + 4 + 100,
			},
		},
		{
			name:     "ethernet arp",
			linkType: layers.LinkTypeEthernet,
			data: serialize(t,
				ethernet(layers.EthernetTypeARP),
				&layers.ARP{
					AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
					HwAddressSize: 6, ProtAddressSize: 4, Operation: 1,
					SourceHwAddress: []byte{2, 0, 0, 0, 0, 1}, SourceProtAddress: []byte{192, 168, 1, 10},
					DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{192, 168, 1, 1},
				}),
			want: packetInfo{
				Src: mustAddr(t, "192.168.1.10"), Dst: mustAddr(t, "192.168.1.1"),
				Proto: ProtoARP,
				Bytes: arpFrameBytes,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec, err := newFlowDecoder(tt.linkType)
			if err != nil {
				t.Fatalf("newFlowDecoder: %v", err)
			}

			got, ok := dec.decode(tt.data)
			if !ok {
				t.Fatal("decode() reported the packet as unusable")
			}
			if got != tt.want {
				t.Fatalf("decode() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFlowDecoderSkipsUnattributablePackets(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "truncated before the ports",
			data: serialize(t,
				ethernet(layers.EthernetTypeIPv4),
				ipv4(layers.IPProtocolTCP),
				&layers.TCP{SrcPort: 51000, DstPort: 443})[:36],
		},
		{
			name: "garbage",
			data: []byte{0x00, 0x01, 0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec, err := newFlowDecoder(layers.LinkTypeEthernet)
			if err != nil {
				t.Fatalf("newFlowDecoder: %v", err)
			}
			if got, ok := dec.decode(tt.data); ok {
				t.Fatalf("decode() = %+v, want it to be skipped", got)
			}
		})
	}
}

// TestFlowDecoderCountsFullDatagramWhenTruncated pins down the reason the byte
// count comes from the IP header rather than the captured length: a packet
// big enough to run past SnapLen — a jumbo frame, or a TLS record with enough
// extensions — would otherwise undercount, and the default snap length case
// below is built large enough to still be one of those.
func TestFlowDecoderCountsFullDatagramWhenTruncated(t *testing.T) {
	full := serialize(t,
		ethernet(layers.EthernetTypeIPv4),
		ipv4(layers.IPProtocolTCP),
		// A long option list plus a big payload, so both the transport header
		// and the data run past every snap length below, the default included.
		&layers.TCP{SrcPort: 51000, DstPort: 443, DataOffset: 15, Options: []layers.TCPOption{{
			OptionType: layers.TCPOptionKindTimestamps, OptionLength: 34,
			OptionData: bytes.Repeat([]byte{1}, 32),
		}}},
		gopacket.Payload(bytes.Repeat([]byte{0xAB}, 1600)))

	// The whole Ethernet frame minus its 14 byte header is the IP datagram.
	wantBytes := uint64(len(full) - 14)

	snapLens := map[string]int{
		"default snap length": DefaultConfig().SnapLen,
		// Eight bytes short of the TCP options, which is where gopacket's own
		// TCP decoder would give up and lose the flow entirely.
		"snap length cutting into the tcp header": 14 + 20 + 12,
		// The bare minimum: enough for the two ports and nothing else.
		"snap length holding only the ports": 14 + 20 + 4,
	}

	for name, snapLen := range snapLens {
		t.Run(name, func(t *testing.T) {
			dec, err := newFlowDecoder(layers.LinkTypeEthernet)
			if err != nil {
				t.Fatalf("newFlowDecoder: %v", err)
			}

			got, ok := dec.decode(full[:min(snapLen, len(full))])
			if !ok {
				t.Fatal("decode() dropped a truncated packet; the ports should still be readable")
			}
			if got.SrcPort != 51000 || got.DstPort != 443 {
				t.Errorf("decode() ports = %d/%d, want 51000/443", got.SrcPort, got.DstPort)
			}
			if got.Bytes != wantBytes {
				t.Errorf("decode() bytes = %d, want %d (the full datagram, not the %d captured)",
					got.Bytes, wantBytes, snapLen)
			}
		})
	}
}

// TestFlowDecoderDecodeSetsTCPFlags pins down that the SYN and ACK bits
// decode reads out of the TCP header's flags byte are only meaningful for
// TCP: a UDP packet's want packetInfo below leaves both zero even though it
// carries a payload at the same offset.
func TestFlowDecoderDecodeSetsTCPFlags(t *testing.T) {
	tests := []struct {
		name    string
		tcp     *layers.TCP
		wantSYN bool
		wantACK bool
	}{
		{name: "syn only", tcp: &layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true}, wantSYN: true, wantACK: false},
		{name: "syn+ack", tcp: &layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true, ACK: true}, wantSYN: true, wantACK: true},
		{name: "ack only", tcp: &layers.TCP{SrcPort: 51000, DstPort: 443, ACK: true}, wantSYN: false, wantACK: true},
		{name: "no flags", tcp: &layers.TCP{SrcPort: 51000, DstPort: 443}, wantSYN: false, wantACK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP), tt.tcp)

			dec, err := newFlowDecoder(layers.LinkTypeEthernet)
			if err != nil {
				t.Fatalf("newFlowDecoder: %v", err)
			}
			got, ok := dec.decode(data)
			if !ok {
				t.Fatal("decode() reported the packet as unusable")
			}
			if got.SYN != tt.wantSYN || got.ACK != tt.wantACK {
				t.Errorf("decode() SYN/ACK = %v/%v, want %v/%v", got.SYN, got.ACK, tt.wantSYN, tt.wantACK)
			}
		})
	}
}

func TestNewFlowDecoderRejectsUnknownLinkType(t *testing.T) {
	if _, err := newFlowDecoder(layers.LinkTypePPP); err == nil {
		t.Fatal("newFlowDecoder(LinkTypePPP) = nil error, want an unsupported link type error")
	}
}
