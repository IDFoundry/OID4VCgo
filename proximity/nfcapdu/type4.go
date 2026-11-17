package nfcapdu

import (
	"bytes"
	"errors"
)

// maxNDEF is the largest NDEF message the emulated tag's NDEF file
// holds: its 0x7FFF maximum size, less the two-byte NLEN.
const maxNDEF = 32765

// Type 4 Tag file identifiers.
const (
	fileCC   = 0xe103
	fileNDEF = 0xe104
)

// capabilityContainer is the emulated tag's: mapping version 2.0, MLe
// and MLc 255, and an NDEF file 0xE104 of up to 0x7FFF bytes that reads
// freely and refuses writes (byte 14, which a writable tag sets to 0).
var capabilityContainer = []byte{0, 15, 0x20, 0, 0xff, 0, 0xff, 4, 6, 0xe1, 4, 0x7f, 0xff, 0, 0xff}

// bitset marks byte ranges of the NDEF file, up to maxNDEF bytes.
type bitset [(maxNDEF + 63) / 64]uint64

func (s *bitset) set(from, to int) {
	for i := from; i < to; i++ {
		s[i/64] |= 1 << (i % 64)
	}
}

// covers reports whether bits [0, n) are all set.
func (s *bitset) covers(n int) bool {
	for i := 0; i < n; i++ {
		if s[i/64]&(1<<(i%64)) == 0 {
			return false
		}
	}
	return true
}

func (s *bitset) clear() { *s = bitset{} }

// type4Tag is the NFC Forum Type 4 Tag NDEF application the mdoc
// emulates, serving one NDEF message. With update set, the reader may
// also write a message to its NDEF file, which update answers with the
// message the file then holds (TNEP).
type type4Tag struct {
	update func([]byte) ([]byte, error)

	ndef, committed []byte // NLEN and message
	coverage        bitset // the message bytes the reader has read
	notified        bool
	selected        bool
	file            int
	staged          []byte // a message being written in pieces
	written         bitset // the staged bytes written so far
}

func newType4Tag(message []byte, update func([]byte) ([]byte, error)) (*type4Tag, error) {
	if len(message) == 0 || len(message) > maxNDEF {
		return nil, errors.New("nfcapdu: NDEF message empty or too large")
	}
	t := &type4Tag{update: update, ndef: withNLEN(message)}
	t.committed = t.ndef
	return t, nil
}

func withNLEN(message []byte) []byte {
	out := make([]byte, 0, len(message)+2)
	out = append(out, hi(len(message)), lo(len(message)))
	return append(out, message...)
}

// deactivate forgets the selection after the field is lost, and any
// partial write. With reset set, the tag serves reset from then on.
func (t *type4Tag) deactivate(reset []byte) {
	t.selected = false
	t.file = 0
	if reset != nil {
		t.committed = withNLEN(reset)
		t.notified = false
	}
	t.ndef = t.committed
	t.coverage.clear()
	t.staged = nil
	t.written.clear()
}

// process answers one command APDU. read reports the reader has just
// read the whole NDEF message for the first time.
func (t *type4Tag) process(apdu []byte) (resp []byte, read bool) {
	c, ok := ParseCommand(apdu)
	if !ok {
		return response(swWrongLength, nil), false
	}
	if c.CLA != 0 {
		return response(swCLANotSupported, nil), false
	}
	if c.INS == insSelect && c.P1 == 4 {
		if c.P2 != 0 && c.P2 != 0x0c {
			return response(swWrongP1P2, nil), false
		}
		// A failed application selection undoes any file selection.
		t.selected = bytes.Equal(c.Data, NDEFApplication)
		t.file = 0
		if !t.selected {
			return response(swFileNotFound, nil), false
		}
		return response(swOK, nil), false
	}
	if !t.selected {
		return response(swConditionsNotMet, nil), false
	}
	switch c.INS {
	case insSelect:
		if c.P1 != 0 || c.P2 != 0x0c || len(c.Data) != 2 {
			return response(swWrongP1P2, nil), false
		}
		t.file = int(c.Data[0])<<8 | int(c.Data[1])
		if t.file != fileCC && t.file != fileNDEF {
			t.file = 0
			return response(swFileNotFound, nil), false
		}
		return response(swOK, nil), false
	case insReadBinary:
		return t.readBinary(c)
	case insUpdate:
		return t.write(c), false
	}
	return response(swINSNotSupported, nil), false
}

func (t *type4Tag) readBinary(c Command) ([]byte, bool) {
	if c.P1&0x80 != 0 || len(c.Data) != 0 || c.Le == 0 {
		return response(swWrongP1P2, nil), false
	}
	var source []byte
	switch t.file {
	case fileCC:
		source = bytes.Clone(capabilityContainer)
		if t.update != nil {
			source[14] = 0 // writable
		}
	case fileNDEF:
		source = t.ndef
	default:
		return response(swConditionsNotMet, nil), false
	}
	offset := int(c.P1)<<8 | int(c.P2)
	if offset >= len(source) {
		return response(swWrongOffset, nil), false
	}
	if c.Le > 255 {
		return response(swWrongLe, nil), false
	}
	end := min(offset+c.Le, len(source))
	read := false
	if t.file == fileNDEF {
		from, to := max(offset, 2)-2, max(end, 2)-2
		if to > from {
			t.coverage.set(from, to)
		}
		// Only a committed message counts as read: a staged write's
		// NLEN 0 serves no message, and covering it reads nothing.
		if !t.notified && len(t.ndef) > 2 && t.coverage.covers(len(t.ndef)-2) {
			t.notified = true
			read = true
		}
	}
	sw := swOK
	if end-offset != c.Le {
		sw = swEndOfFile
	}
	return response(sw, source[offset:end]), read
}

func (t *type4Tag) write(c Command) []byte {
	if t.update == nil {
		return response(swCommandNotAllowedEF, nil)
	}
	if t.file != fileNDEF {
		return response(swConditionsNotMet, nil)
	}
	if c.P1&0x80 != 0 || len(c.Data) == 0 || len(c.Data) > 255 || c.Le != 0 {
		return response(swWrongP1P2, nil)
	}
	offset := int(c.P1)<<8 | int(c.P2)
	if offset != 0 {
		if t.staged == nil {
			return response(swConditionsNotMet, nil)
		}
		if offset < 2 || offset-2+len(c.Data) > len(t.staged) {
			return response(swNotEnoughMemory, nil)
		}
		copy(t.staged[offset-2:], c.Data)
		t.written.set(offset-2, offset-2+len(c.Data))
		return response(swOK, nil)
	}
	if len(c.Data) < 2 {
		return response(swWrongLength, nil)
	}
	length := int(c.Data[0])<<8 | int(c.Data[1])
	if length == 0 && len(c.Data) == 2 {
		// NLEN 0 starts a message written in pieces.
		t.staged = make([]byte, maxNDEF)
		t.written.clear()
		t.ndef = []byte{0, 0}
		return response(swOK, nil)
	}
	if length < 1 || length > maxNDEF {
		return response(swNotEnoughMemory, nil)
	}
	var incoming []byte
	switch {
	case len(c.Data) == length+2:
		incoming = bytes.Clone(c.Data[2:])
	case len(c.Data) == 2 && t.staged != nil && t.written.covers(length):
		incoming = bytes.Clone(t.staged[:length])
	default:
		return response(swConditionsNotMet, nil)
	}
	t.staged = nil
	t.written.clear()
	answer, err := t.update(incoming)
	if err != nil {
		return response(swWrongData, nil)
	}
	if len(answer) < 1 || len(answer) > maxNDEF {
		return response(swNotEnoughMemory, nil)
	}
	t.ndef = withNLEN(answer)
	t.committed = t.ndef
	t.coverage.clear()
	t.notified = false
	return response(swOK, nil)
}
