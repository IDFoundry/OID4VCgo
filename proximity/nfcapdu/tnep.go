package nfcapdu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// handoverService is the TNEP service ISO/IEC 18013-5 negotiated
// handover uses (§8.2.2.1).
var handoverService = []byte("urn:nfc:sn:handover")

// Single-record TNEP messages (NFC Forum TNEP 1.0 §4).
var (
	// tnepParameters advertises the handover service: TNEP version 1.0,
	// single response communication, WT 16, N_wait 15, and the largest
	// NDEF message the emulated tag holds.
	tnepParameters    = shortRecord("Tp", concat([]byte{0x10, byte(len(handoverService))}, handoverService, []byte{0, 16, 15, maxNDEF >> 8, maxNDEF & 0xff}))
	tnepSelectPayload = concat([]byte{byte(len(handoverService))}, handoverService)
	tnepSelect        = shortRecord("Ts", tnepSelectPayload)
	tnepSuccess       = shortRecord("Te", []byte{0})
)

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// shortRecord is a one-record NDEF message: a well-known type with a
// payload of at most 255 bytes.
func shortRecord(typ string, payload []byte) []byte {
	return concat([]byte{0xd1, lo(len(typ)), lo(len(payload))}, []byte(typ), payload)
}

// maxTNEPRecords bounds the records parsed from one TNEP message.
const maxTNEPRecords = 128

type tnepRecord struct {
	typ     string // the type of a well-known record, empty otherwise
	payload []byte
}

// tnepRecords parses an NDEF message of TNEP records: one message, no
// chunked records, no reserved TNF.
func tnepRecords(message []byte) ([]tnepRecord, error) {
	if len(message) < 1 || len(message) > maxNDEF {
		return nil, errors.New("nfcapdu: invalid TNEP NDEF size")
	}
	c := &ndefCursor{b: message}
	var records []tnepRecord
	for c.pos < len(message) && len(records) < maxTNEPRecords {
		r, last, err := c.record(len(records) == 0)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
		if last {
			if c.pos != len(message) {
				return nil, errors.New("nfcapdu: bytes after NDEF message end")
			}
			return records, nil
		}
	}
	return nil, errors.New("nfcapdu: missing NDEF message end or too many records")
}

// ndefCursor reads NDEF records from b.
type ndefCursor struct {
	b   []byte
	pos int
}

// take returns the next n bytes.
func (c *ndefCursor) take(n int) ([]byte, error) {
	if n > len(c.b)-c.pos {
		return nil, errors.New("nfcapdu: truncated NDEF record")
	}
	c.pos += n
	return c.b[c.pos-n : c.pos], nil
}

// length reads a one-byte length, or a four-byte one when short is false.
func (c *ndefCursor) length(short bool) (uint32, error) {
	if short {
		b, err := c.take(1)
		if err != nil {
			return 0, err
		}
		return uint32(b[0]), nil
	}
	b, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// record reads one record; first reports it must begin the message, and
// last that it ends it.
func (c *ndefCursor) record(first bool) (r tnepRecord, last bool, err error) {
	header, err := c.take(2)
	if err != nil {
		return r, false, err
	}
	flags, typeLength := header[0], int(header[1])
	tnf := flags & 7
	if flags&0x80 != 0 != first || flags&0x20 != 0 || tnf > 5 {
		return r, false, errors.New("nfcapdu: unsupported NDEF framing")
	}
	size, err := c.length(flags&0x10 != 0)
	if err != nil {
		return r, false, err
	}
	idLength := uint32(0)
	if flags&8 != 0 {
		if idLength, err = c.length(true); err != nil {
			return r, false, err
		}
	}
	empty := typeLength == 0 && idLength == 0 && size == 0
	if tnf == 0 && !empty || tnf >= 1 && tnf <= 4 && typeLength == 0 || tnf == 5 && typeLength != 0 {
		return r, false, errors.New("nfcapdu: invalid NDEF type")
	}
	if size > maxNDEF || typeLength+int(idLength)+int(size) > len(c.b)-c.pos {
		return r, false, errors.New("nfcapdu: truncated NDEF payload")
	}
	typ, _ := c.take(typeLength)
	_, _ = c.take(int(idLength))
	r.payload, _ = c.take(int(size))
	if tnf == 1 {
		r.typ = string(typ)
	}
	return r, flags&0x40 != 0, nil
}

// tnepPayload returns the payload of message's only record when it has
// type typ, or nil.
func tnepPayload(message []byte, typ string) ([]byte, error) {
	records, err := tnepRecords(message)
	if err != nil {
		return nil, err
	}
	if len(records) != 1 || records[0].typ != typ {
		return nil, nil
	}
	return records[0].payload, nil
}

// tnepTiming is a TNEP service's: the minimum waiting time exponent WT,
// the waiting time extensions allowed, and the largest NDEF message it
// takes.
type tnepTiming struct {
	wt, waits, maxMessage int
}

// wait is the minimum waiting time, T_wait = 2^(WT/4 − 1) ms, rounded up
// to whole milliseconds.
func (t tnepTiming) wait() time.Duration {
	ms := math.Ceil(math.Pow(2, float64(t.wt)/4-1))
	return max(time.Duration(ms), 1) * time.Millisecond
}

// tnepServiceParameters finds the handover service in message's
// Service Parameter records. found is false when it isn't advertised.
func tnepServiceParameters(message []byte) (timing tnepTiming, found bool, err error) {
	records, err := tnepRecords(message)
	if err != nil {
		return tnepTiming{}, false, err
	}
	n := len(handoverService)
	var matching [][]byte
	for _, r := range records {
		p := r.payload
		if r.typ == "Tp" && len(p) >= n+2 && int(p[1]) == n && bytes.Equal(p[2:2+n], handoverService) {
			matching = append(matching, p)
		}
	}
	switch len(matching) {
	case 0:
		return tnepTiming{}, false, nil
	case 1:
	default:
		return tnepTiming{}, false, errors.New("nfcapdu: duplicate TNEP handover service")
	}
	p := matching[0]
	if len(p) != n+7 || p[0] != 0x10 || p[2+n] != 0 {
		return tnepTiming{}, false, errors.New("nfcapdu: unsupported TNEP service")
	}
	timing = tnepTiming{wt: int(p[3+n]), waits: int(p[4+n]), maxMessage: int(p[5+n])<<8 | int(p[6+n])}
	if timing.wt > 63 || timing.waits > 15 {
		return tnepTiming{}, false, errors.New("nfcapdu: invalid TNEP timing")
	}
	if timing.maxMessage == 0 {
		return tnepTiming{}, false, errors.New("nfcapdu: invalid TNEP message limit")
	}
	return timing, true, nil
}

// tnepHolder answers TNEP over the emulated tag: service selection and
// deselection, then the reader's Handover Request, which negotiate
// answers with the Handover Select.
type tnepHolder struct {
	negotiate      func(hr []byte) ([]byte, error)
	selected       bool
	handoverReady  bool   // negotiate has answered
	handoverSelect []byte // what negotiate answered
}

// isHandoverSelect reports whether ndef, an NDEF file with its NLEN, is
// the Handover Select negotiate answered, rather than another TNEP
// answer served after it.
func (h *tnepHolder) isHandoverSelect(ndef []byte) bool {
	return h.handoverReady && len(ndef) > 2 && bytes.Equal(ndef[2:], h.handoverSelect)
}

func (h *tnepHolder) transact(message []byte) ([]byte, error) {
	service, err := tnepPayload(message, "Ts")
	if err != nil {
		return nil, err
	}
	if bytes.Equal(service, []byte{0}) {
		h.selected = false
		return tnepParameters, nil
	}
	if service != nil && bytes.Equal(service, tnepSelectPayload) {
		h.selected = true
		return tnepSuccess, nil
	}
	if !h.selected {
		return nil, errors.New("nfcapdu: TNEP service not selected")
	}
	if status, err := tnepPayload(message, "Te"); err == nil && bytes.Equal(status, []byte{0}) && h.handoverReady {
		return tnepSuccess, nil
	}
	hs, err := h.negotiate(message)
	if err != nil {
		return nil, err
	}
	h.handoverReady, h.handoverSelect = true, bytes.Clone(hs)
	return hs, nil
}
