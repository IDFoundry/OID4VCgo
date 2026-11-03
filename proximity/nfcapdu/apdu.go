package nfcapdu

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Status words this package answers with (ISO/IEC 7816-4 §5.6).
const (
	swOK                  = 0x9000
	swEndOfFile           = 0x6282
	swWrongLength         = 0x6700
	swConditionsNotMet    = 0x6985
	swCommandNotAllowedEF = 0x6986
	swWrongData           = 0x6a80
	swFileNotFound        = 0x6a82
	swNotEnoughMemory     = 0x6a84
	swWrongP1P2           = 0x6a86
	swWrongOffset         = 0x6b00
	swWrongLe             = 0x6cff
	swINSNotSupported     = 0x6d00
	swCLANotSupported     = 0x6e00
	swUnknown             = 0x6f00
	swMoreData            = 0x6100
)

// Instructions this package sends or answers.
const (
	insSelect      = 0xa4
	insReadBinary  = 0xb0
	insUpdate      = 0xd6
	insEnvelope    = 0xc3
	insGetResponse = 0xc0
)

// maxCommandAPDU is the longest command APDU: a 7-byte extended header,
// 65535 data bytes and a 2-byte Le.
const maxCommandAPDU = 4 + 3 + 65535 + 2

// NDEFApplication is the NFC Forum Type 4 Tag NDEF application's AID.
var NDEFApplication = []byte{0xd2, 0x76, 0, 0, 0x85, 1, 1}

// DataApplication is the AID of ISO/IEC 18013-5's NFC data retrieval
// application (§8.3.3.1.2).
var DataApplication = []byte{0xa0, 0, 0, 2, 0x48, 4, 0}

// Command is an ISO/IEC 7816-4 command APDU.
type Command struct {
	CLA, INS, P1, P2 byte
	Data             []byte
	// Le is the expected response length, 1–65536, or 0 when absent.
	Le int
}

// ParseCommand parses a command APDU in any of the four ISO/IEC 7816-4
// cases, with short or extended lengths. It reports false for a
// malformed one.
func ParseCommand(b []byte) (Command, bool) {
	if len(b) < 4 || len(b) > maxCommandAPDU {
		return Command{}, false
	}
	c := Command{CLA: b[0], INS: b[1], P1: b[2], P2: b[3]}
	switch {
	case len(b) == 4:
		return c, true
	case len(b) == 5:
		c.Le = shortLe(b[4])
		return c, true
	}
	extended := b[4] == 0
	start := 5
	if extended {
		start = 7
	}
	if len(b) < start {
		return Command{}, false
	}
	length := int(b[4])
	if extended {
		length = int(b[5])<<8 | int(b[6])
	}
	if extended && len(b) == 7 {
		c.Le = extendedLe(length)
		return c, true
	}
	if length == 0 || start+length > len(b) {
		return Command{}, false
	}
	remaining := len(b) - start - length
	leBytes := 1
	if extended {
		leBytes = 2
	}
	if remaining != 0 && remaining != leBytes {
		return Command{}, false
	}
	c.Data = bytes.Clone(b[start : start+length])
	switch {
	case remaining == 0:
	case extended:
		c.Le = extendedLe(int(b[len(b)-2])<<8 | int(b[len(b)-1]))
	default:
		c.Le = shortLe(b[len(b)-1])
	}
	return c, true
}

func shortLe(b byte) int {
	if b == 0 {
		return 256
	}
	return int(b)
}

func extendedLe(n int) int {
	if n == 0 {
		return 65536
	}
	return n
}

// isSelectByName reports whether c selects an application by its AID,
// returning its FCI (P2 0) or nothing (P2 0x0C).
func (c Command) isSelectByName() bool {
	return c.CLA == 0 && c.INS == insSelect && c.P1 == 4 && (c.P2 == 0 || c.P2 == 0x0c)
}

// lo and hi are the low and high bytes of a 16-bit length or offset.
func lo(n int) byte { return byte(n & 0xff) }
func hi(n int) byte { return byte(n >> 8 & 0xff) }

// response is a response APDU: data followed by the status word.
func response(status int, data []byte) []byte {
	out := make([]byte, 0, len(data)+2)
	out = append(out, data...)
	return binary.BigEndian.AppendUint16(out, uint16(status&0xffff))
}

// status splits a response APDU into its data and status word.
func status(resp []byte) ([]byte, int, error) {
	if len(resp) < 2 {
		return nil, 0, errors.New("nfcapdu: response APDU shorter than its status word")
	}
	n := len(resp) - 2
	return resp[:n], int(resp[n])<<8 | int(resp[n+1]), nil
}

// CommandKind classifies a command APDU for engagement arbitration: which
// application, if any, it selects.
type CommandKind int

const (
	// CommandOther is any command that isn't a SELECT by AID, or a
	// malformed one.
	CommandOther CommandKind = iota
	// CommandSelectNDEF selects the Type 4 Tag NDEF application: a reader
	// discovering the handover, which doesn't yet commit to NFC.
	CommandSelectNDEF
	// CommandSelectData selects the NFC data application: with P2 0x0C
	// and no Le, as ISO/IEC 18013-5 (second edition) §11.2 Table 8 has
	// it, or with P2 0.
	CommandSelectData
	// CommandSelectDataNoFCI is no longer reported: Classify reports
	// either SELECT of the NFC data application as CommandSelectData.
	//
	// Deprecated: a reader's SELECT with P2 0x0C is the standard one,
	// which NFC data retrieval accepts.
	CommandSelectDataNoFCI
	// CommandSelectOther selects some other application.
	CommandSelectOther
)

// Classify reports what apdu selects.
func Classify(apdu []byte) CommandKind {
	c, ok := ParseCommand(apdu)
	if !ok || !c.isSelectByName() {
		return CommandOther
	}
	switch {
	case bytes.Equal(c.Data, NDEFApplication):
		return CommandSelectNDEF
	case bytes.Equal(c.Data, DataApplication):
		return CommandSelectData
	}
	return CommandSelectOther
}
