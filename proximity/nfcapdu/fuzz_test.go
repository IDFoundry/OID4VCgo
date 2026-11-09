package nfcapdu

import (
	"bytes"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testbounds"
	"github.com/idfoundry/oid4vcgo/proximity"
)

// splitAPDUs cuts b into APDUs, each prefixed by a one-byte length.
func splitAPDUs(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		n := min(int(b[0]), len(b)-1)
		// Each APDU has no spare capacity, as one read off the radio
		// doesn't: the next APDU's bytes would hide a read past its end.
		out = append(out, testbounds.Exact(b[1:1+n]))
		b = b[1+n:]
	}
	return out
}

func FuzzParseCommand(f *testing.F) {
	f.Add([]byte{0, insGetResponse, 0, 0, 0})
	f.Add([]byte{0, insEnvelope, 0, 0, 0, 0, 2, 4, 5, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		b = testbounds.Exact(b)
		c, ok := ParseCommand(b)
		if ok && (len(c.Data) > len(b) || c.Le < 0 || c.Le > 65536) {
			t.Fatalf("ParseCommand(%X) = %+v", b, c)
		}
		Classify(b)
	})
}

func FuzzUnwrapDO53(f *testing.F) {
	encoded, _ := WrapDO53(bytes.Repeat([]byte{1}, 300))
	f.Add(encoded)
	f.Add([]byte{0x53, 0x81, 1, 7})
	f.Fuzz(func(t *testing.T, b []byte) {
		b = testbounds.Exact(b)
		m, err := UnwrapDO53(b)
		if err != nil {
			return
		}
		again, err := WrapDO53(m)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("UnwrapDO53(%X) didn't round-trip", b)
		}
	})
}

func FuzzTNEPRecords(f *testing.F) {
	f.Add(tnepParameters)
	f.Add(concat(shortRecord("Tp", []byte{0x10, 1, 'x', 0, 16, 15, 1, 0}), tnepParameters))
	f.Fuzz(func(t *testing.T, b []byte) {
		b = testbounds.Exact(b)
		_, _, _ = tnepServiceParameters(b)
		_, _ = tnepPayload(b, "Ts")
	})
}

// FuzzHolder feeds a holder offering every path a sequence of commands.
func FuzzHolder(f *testing.F) {
	s, err := proximity.NewNFCNegotiatedDataDeviceSession(nil, proximity.NFCDataParameters{MaxCommand: 255, MaxResponse: 256})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{byte(len(selectNDEF))}, false)
	f.Add(concat([]byte{byte(len(selectNDEF))}, selectNDEF, []byte{byte(len(selectNDEFFile))}, selectNDEFFile, []byte{5, 0, insReadBinary, 0, 0, 2}), true)
	f.Fuzz(func(t *testing.T, b []byte, respond bool) {
		h, err := NewHolder(HolderOptions{Negotiate: s.HandleHandoverRequest, Data: true})
		if err != nil {
			t.Fatal(err)
		}
		for i, apdu := range splitAPDUs(b) {
			step := h.Process(apdu)
			if step.Message != nil {
				if respond {
					if _, err := h.Respond(step.Message); err != nil {
						t.Fatal(err)
					}
				} else {
					h.RefuseMessage()
				}
			} else if len(step.Response) < 2 {
				t.Fatalf("Process(%X) = %X", apdu, step.Response)
			}
			if i%7 == 6 {
				h.Deactivate(i%2 == 0, false)
			}
		}
	})
}

// FuzzReadHandover answers a reader's commands with fuzzed responses.
func FuzzReadHandover(f *testing.F) {
	f.Add([]byte{2, 0x90, 0}, uint16(261), true)
	f.Fuzz(func(t *testing.T, b []byte, maxTransceive uint16, negotiate bool) {
		var hr []byte
		if negotiate {
			hr = fixture(10)
		}
		replay(t, ReadHandover(int(maxTransceive), hr).Exchange, splitAPDUs(b))
	})
}

// FuzzTransact answers a data reader's commands with fuzzed responses.
func FuzzTransact(f *testing.F) {
	f.Add([]byte{2, 0x90, 0, 5, 0x53, 1, 1, 0x90, 0}, uint16(261))
	f.Fuzz(func(t *testing.T, b []byte, maxTransceive uint16) {
		p := proximity.NFCDataParameters{MaxCommand: 255, MaxResponse: 256}
		replay(t, Transact(int(maxTransceive), p, []byte("request")), splitAPDUs(b))
	})
}

// replay answers e's commands with responses in turn, closing it when
// they run out.
func replay(t *testing.T, e *Exchange, responses [][]byte) {
	defer e.Close()
	for _, resp := range responses {
		if e.Command() == nil {
			_, _ = e.Result()
			return
		}
		if err := e.Next(resp); err != nil {
			t.Fatal(err)
		}
	}
}
