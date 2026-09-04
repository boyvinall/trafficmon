package dpi

import "testing"

func TestHelloAssemblerAdd(t *testing.T) {
	t.Run("single segment already complete", func(t *testing.T) {
		h := NewHelloAssembler()
		full := buildClientHello("example.com")
		ready, done := h.Add(1000, full)
		if !done || string(ready) != string(full) {
			t.Fatalf("Add() = ready %d bytes, done=%v; want the full record, done=true", len(ready), done)
		}
	})

	t.Run("two-segment split", func(t *testing.T) {
		h := NewHelloAssembler()
		full := buildClientHello("www.example.com")
		mid := len(full) / 2

		ready, done := h.Add(1000, full[:mid])
		if ready != nil || done {
			t.Fatalf("Add(first half) = ready %v, done=%v; want nil, false", ready, done)
		}

		ready, done = h.Add(1000+uint32(mid), full[mid:])
		if !done || string(ready) != string(full) {
			t.Fatalf("Add(second half) = ready %d bytes, done=%v; want the full record, done=true", len(ready), done)
		}
	})

	t.Run("sequence gap gives up", func(t *testing.T) {
		h := NewHelloAssembler()
		full := buildClientHello("example.com")
		mid := len(full) / 2

		if _, done := h.Add(1000, full[:mid]); done {
			t.Fatalf("Add(first half) done=true, want false")
		}
		// Skip ahead: this is not the next contiguous byte of the stream.
		ready, done := h.Add(1000+uint32(mid)+50, full[mid:])
		if ready != nil || !done {
			t.Fatalf("Add(gap) = ready %v, done=%v; want nil, true", ready, done)
		}
	})

	t.Run("not a handshake record gives up immediately", func(t *testing.T) {
		h := NewHelloAssembler()
		ready, done := h.Add(1000, []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00})
		if ready != nil || !done {
			t.Fatalf("Add(non-handshake) = ready %v, done=%v; want nil, true", ready, done)
		}
	})

	t.Run("gives up past the byte cap", func(t *testing.T) {
		h := NewHelloAssembler()
		first := make([]byte, maxHelloBufferBytes+1)
		first[0] = tlsHandshakeRecordType
		ready, done := h.Add(1000, first)
		if ready != nil || !done {
			t.Fatalf("Add(oversized) = ready %v, done=%v; want nil, true", ready, done)
		}
	})

	t.Run("gives up past the segment cap", func(t *testing.T) {
		h := NewHelloAssembler()
		seq := uint32(1000)
		var done bool
		for i := 0; i <= maxHelloSegments; i++ {
			payload := []byte{tlsHandshakeRecordType, 0x03, 0x01, 0xff, 0xff} // declares a huge record, never completes
			_, done = h.Add(seq, payload)
			seq += uint32(len(payload))
			if done {
				break
			}
		}
		if !done {
			t.Fatal("Add() never gave up after exceeding maxHelloSegments")
		}
	})

	t.Run("empty payload is a no-op", func(t *testing.T) {
		h := NewHelloAssembler()
		ready, done := h.Add(1000, nil)
		if ready != nil || done {
			t.Fatalf("Add(empty) = ready %v, done=%v; want nil, false", ready, done)
		}
	})
}
