package capture

import (
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/boyvinall/trafficmon/dpi"
)

// inspectInput bundles one packet's inspect-relevant fields: the zero-copy
// buffer it was read into, the flow-table info decode already extracted from
// it, which direction it travelled, its link type (extractPayload needs this
// to build a second gopacket.Packet over the same buffer), and its capture
// timestamp.
type inspectInput struct {
	data     []byte
	info     packetInfo
	inbound  bool
	linkType layers.LinkType
	ts       time.Time
}

// inspect runs the configured Inspectors against one packet already
// attributed to ctr's flow, stopping at the first one willing to look. It is
// a no-op once ctr no longer needs inspection (see
// ByteCounter.NeedsHostnameInspection). A flow whose ClientHello spans more
// than one segment stays under inspection across several calls — see
// ByteCounter.AddHelloSegment — but is still bounded to one overall attempt:
// once that reassembly finishes or gives up, later packets on the same flow
// are never re-parsed.
//
// A fresh (non-continuation) candidate's payload is extracted up front,
// before any Inspector's Candidate runs, so Candidate can recognise a
// protocol from its own leading bytes instead of assuming a well-known
// port — but only once DatagramLen alone (no extraction needed) has ruled
// out a header-only TCP segment. If no Inspector accepts that first
// extracted payload, the flow's one-shot budget is spent right there rather
// than re-extracting every later packet: a genuine ClientHello (or QUIC
// Initial) is always the first payload-bearing packet a fresh connection
// carries, so this is what keeps a long-lived flow that is never TLS or
// QUIC at all (a plain HTTP download, an SSH session) from paying an
// extraction cost for its whole life instead of just once.
//
// A UDP candidate (QUIC's Initial packet) skips reassembly entirely: one
// datagram is already a complete unit, so it is inspected directly and the
// flow is marked attempted either way, hit or miss, with no continuation
// state to track.
//
// Only the first Inspector in c.cfg.Inspectors whose Candidate accepts a
// given packet is asked: a later one that would also have accepted the same
// packet never gets a look, hit or miss. This holds today because no two
// configured Inspectors' Candidate implementations overlap (see
// DefaultInspectors), but it means combining Inspectors whose candidates do
// overlap is not supported without changing this function.
//
// in.data is the same zero-copy buffer the capture loop just read; it is
// used here and only here, before the loop's next ZeroCopyReadPacketData
// call invalidates it. extractPayload builds its gopacket.Packet directly
// over in.data with gopacket.NoCopy, so nothing here copies it — the one
// copy that does happen is each segment's payload going into the flow's
// dpi.HelloAssembler, which has to outlive the next read.
func (c *Capturer) inspect(in inspectInput, remote netip.Addr, ctr *ByteCounter) {
	if len(c.cfg.Inspectors) == 0 || !ctr.NeedsHostnameInspection() {
		return
	}

	cand := dpi.CandidatePacket{
		IsTCP:       in.info.Proto == ProtoTCP,
		SrcPort:     in.info.SrcPort,
		DstPort:     in.info.DstPort,
		Outbound:    !in.inbound,
		DatagramLen: int(in.info.Bytes),
	}

	inProgress := cand.IsTCP && ctr.HelloInProgress()
	// A continuation must go back to the same inspector that started the
	// reassembly — not just any inspector willing to look — so a second
	// TCP-capable Inspector in the list can never hijack another one's
	// in-progress hello.
	wantInspector := ""
	if inProgress {
		wantInspector = ctr.HelloInspector()
	}

	if !inProgress && cand.IsTCP && cand.DatagramLen <= minPayloadDatagramLen {
		return // header-only TCP segment (SYN, bare ACK, FIN): nothing to extract
	}

	seq, payload, ok := extractPayload(in.data, in.linkType, cand.IsTCP)
	if !ok {
		if inProgress {
			ctr.MarkHostnameAttempted()
		}
		return
	}
	cand.Payload = payload

	for _, insp := range c.cfg.Inspectors {
		switch {
		case inProgress:
			if !cand.Outbound || insp.Name() != wantInspector {
				continue // a continuation only cares about this flow's own outbound bytes, on its own inspector
			}
		case !insp.Candidate(cand):
			continue
		}

		if !cand.IsTCP {
			// A single datagram, already complete: no reassembly, no
			// continuation across further calls.
			ctr.MarkHostnameAttempted()
			if host, ok := insp.Inspect(payload); ok {
				ctr.SetHostname(host)
				c.hostnameCache.Put(remote.String(), host, in.ts)
			}
			return
		}

		ready, done := ctr.AddHelloSegment(insp.Name(), seq, payload)
		if ready != nil {
			if host, ok := insp.Inspect(ready); ok {
				ctr.SetHostname(host)
				c.hostnameCache.Put(remote.String(), host, in.ts)
			}
		}
		// A candidate packet was examined either way: don't keep retrying
		// this flow once reassembly is done, found a hostname or not.
		if done {
			ctr.MarkHostnameAttempted()
		}
		return
	}

	// A fresh candidate's payload was examined (via Candidate, above) and no
	// Inspector wanted it: this flow's opening payload-bearing packet is
	// never coming back, so there is nothing left to gain by asking again on
	// its next packet.
	if !inProgress {
		ctr.MarkHostnameAttempted()
	}
}

// inspectPassive runs the configured PassiveInspectors against every
// packet, independent of any flow's own hostname state — a DNS resolver
// flow keeps carrying new, unrelated query/response pairs for its whole
// life, unlike a single ClientHello. Candidate keeps this cheap for every
// packet that isn't DNS.
func (c *Capturer) inspectPassive(data []byte, info packetInfo, linkType layers.LinkType, ts time.Time) {
	if len(c.cfg.PassiveInspectors) == 0 {
		return
	}

	cand := dpi.CandidatePacket{
		IsTCP:       info.Proto == ProtoTCP,
		SrcPort:     info.SrcPort,
		DstPort:     info.DstPort,
		DatagramLen: int(info.Bytes),
	}

	for _, insp := range c.cfg.PassiveInspectors {
		if !insp.Candidate(cand) {
			continue
		}

		_, payload, ok := extractPayload(data, linkType, cand.IsTCP)
		if !ok {
			continue
		}
		if cand.IsTCP {
			// DNS-over-TCP prefixes each message with its own 2-byte length;
			// strip it so Inspect always sees one bare message, the same as
			// the UDP case.
			if len(payload) < 2 {
				continue
			}
			payload = payload[2:]
		}

		for _, f := range insp.Inspect(payload) {
			c.hostnameCache.Put(f.IP, f.Hostname, ts)
		}
		if qi, ok := insp.(dpi.QueryPassiveInspector); ok {
			for _, f := range qi.InspectQuery(payload, info.Src.String(), info.Dst.String(), ts) {
				c.dnsQueries.push(f)
				if c.logFeed != nil {
					c.logFeed.sendDNSQuery(f)
				}
			}
		}
		if ei, ok := insp.(dpi.ErrorPassiveInspector); ok {
			for _, f := range ei.InspectError(payload, info.Src.String(), ts) {
				c.dnsErrors.push(f)
			}
		}
		if ai, ok := insp.(dpi.AnswerPassiveInspector); ok {
			for _, f := range ai.InspectAnswer(payload, info.Src.String(), ts) {
				c.dnsAnswers.push(f)
			}
		}
	}
}

// extractPayload decodes data with the stock gopacket TCP/UDP decoder — not
// the fast transportPorts path flowDecoder uses for every packet, see
// decode.go — to recover the application-layer payload (and, for TCP, the
// sequence number hello reassembly needs). It is only called for packets
// that already passed Candidate or belong to a flow already mid reassembly,
// so this second decode's cost stays bounded to a handful of packets per new
// connection.
func extractPayload(data []byte, linkType layers.LinkType, isTCP bool) (seq uint32, payload []byte, ok bool) {
	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	if isTCP {
		tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !isTCP {
			return 0, nil, false
		}
		return tcp.Seq, tcp.LayerPayload(), true
	}
	udp, isUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !isUDP {
		return 0, nil, false
	}
	return 0, udp.LayerPayload(), true
}
