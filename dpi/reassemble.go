package dpi

const (
	// maxHelloBufferBytes bounds how much a flow's ClientHello reassembly will
	// buffer before giving up: generous margin over a real-world post-quantum
	// hybrid ClientHello (an X25519MLKEM768 key share alone is ~1100 bytes),
	// while still capping memory for a flow that turns out not to be one.
	maxHelloBufferBytes = 8192
	// maxHelloSegments bounds segment count the same way, for a flow sending
	// its ClientHello in many small writes rather than a few full-MTU ones.
	maxHelloSegments = 8

	tlsHandshakeRecordType = 0x16
	tlsRecordHeaderLen     = 5
)

// HelloAssembler joins a TLS ClientHello across however many TCP segments its
// SNI extension is split over, by strict TCP sequence order. It is not a
// general reassembler: a sequence gap (reordering, a retransmit, or an
// unrelated packet on the same flow) gives up rather than trying to recover,
// since a live capture of this host's own outbound connection only exhibits
// the plain contiguous-forward case in practice.
type HelloAssembler struct {
	buf     []byte
	nextSeq uint32
	haveSeq bool
	segs    int
}

// NewHelloAssembler creates an empty HelloAssembler.
func NewHelloAssembler() *HelloAssembler { return &HelloAssembler{} }

// Add feeds one more segment's payload in, in capture order. ready is the
// joined record bytes once a complete TLS record has arrived; done reports
// whether the caller should stop calling Add for this flow, whether or not
// ready came back non-nil.
func (h *HelloAssembler) Add(seq uint32, payload []byte) (ready []byte, done bool) {
	if len(payload) == 0 {
		return nil, false
	}

	if !h.haveSeq {
		h.nextSeq, h.haveSeq = seq, true
	}
	if seq != h.nextSeq {
		return nil, true
	}

	h.buf = append(h.buf, payload...)
	h.nextSeq += uint32(len(payload))
	h.segs++

	if h.buf[0] != tlsHandshakeRecordType {
		return nil, true
	}
	if len(h.buf) > maxHelloBufferBytes || h.segs > maxHelloSegments {
		return nil, true
	}
	if len(h.buf) < tlsRecordHeaderLen {
		return nil, false
	}

	total := tlsRecordHeaderLen + (int(h.buf[3])<<8 | int(h.buf[4]))
	if len(h.buf) < total {
		return nil, false
	}
	return h.buf[:total], true
}
