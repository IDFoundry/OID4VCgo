package nfcapdu

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testbounds"
)

// validCC is a capability container naming one writable NDEF file:
// CCLEN 15, mapping version 2.0, MLe 255, MLc 255, and the NDEF File
// Control TLV for file E104 of up to 32767 bytes.
var validCC = []byte{0, 15, 0x20, 0, 0xff, 0, 0xff, 4, 6, 0xe1, 0x04, 0x7f, 0xff, 0, 0}

// The TNEP and capability container parsers refuse, without panicking,
// a truncated message and survive any one-byte change, on input with no
// spare capacity: the tag, or the reader, chooses every byte.
func TestNFCAPDUParsers_Bounds(t *testing.T) {
	testbounds.Check(t, "TNEP Service Parameter", tnepParameters, true, func(b []byte) error {
		_, found, err := tnepServiceParameters(b)
		if err == nil && !found {
			return fmt.Errorf("no handover service")
		}
		return err
	})
	// A well-framed Service Parameter record whose payload is a byte
	// short or long names the handover service but isn't its parameters.
	params := tnepParameters[3+len("Tp"):]
	for n := len(handoverService) + 2; n <= len(params)+1; n++ {
		if n == len(params) {
			continue
		}
		payload := concat(params, []byte{0})[:n]
		err := testbounds.NoPanic(t, fmt.Sprintf("Service Parameter of %d bytes", n), shortRecord("Tp", payload), func(b []byte) error {
			_, _, err := tnepServiceParameters(b)
			return err
		})
		if err == nil {
			t.Errorf("a Service Parameter payload of %d bytes, not %d, accepted", n, len(params))
		}
	}
	testbounds.Check(t, "TNEP Service Select", tnepSelect, true, func(b []byte) error {
		_, err := tnepRecords(b)
		return err
	})
	twoRecords := concat([]byte{0x91, 2, 1}, []byte("Ts"), []byte{0}, []byte{0x51, 2, 1}, []byte("Te"), []byte{0})
	testbounds.Check(t, "two TNEP records", twoRecords, true, func(b []byte) error {
		records, err := tnepRecords(b)
		if err == nil && len(records) != 2 {
			return fmt.Errorf("%d records", len(records))
		}
		return err
	})
	testbounds.Check(t, "capability container", validCC, true, func(b []byte) error {
		_, err := (&type4Reader{}).ndefFile(b)
		return err
	})
}

// A reader refuses, without panicking, a tag's capability container in
// any one-byte change or length.
func TestReadHandover_CapabilityContainerBounds(t *testing.T) {
	read := func(cc []byte) error {
		_, _, err := drive(t, ReadHandover(261, nil).Exchange, func(c []byte) []byte {
			if c[1] != insReadBinary {
				return response(swOK, nil)
			}
			offset, n := int(c[2])<<8|int(c[3]), int(c[4])
			if offset >= len(cc) {
				return response(swWrongOffset, nil)
			}
			return response(swOK, cc[offset:min(offset+n, len(cc))])
		})
		return err
	}
	for i := range validCC {
		for _, v := range []byte{0x00, 0xff, validCC[i] + 1, validCC[i] - 1} {
			changed := testbounds.Exact(validCC)
			changed[i] = v
			_ = testbounds.NoPanic(t, fmt.Sprintf("capability container with byte %d set to %#x", i, v), changed, read)
		}
	}
	for n := range len(validCC) {
		_ = testbounds.NoPanic(t, fmt.Sprintf("capability container cut to %d bytes", n), validCC[:n], read)
	}
}

// UPDATE BINARY writes a message to the NDEF file in one command or in
// pieces, and refuses each malformed or out-of-range write with the
// status Type 4 Tag 2.0 gives it, without committing anything.
func TestType4Tag_UpdateBinary(t *testing.T) {
	newTag := func(t *testing.T) (*type4Tag, *[][]byte) {
		t.Helper()
		var commits [][]byte
		tag, err := newType4Tag(fixture(1), func(m []byte) ([]byte, error) {
			commits = append(commits, m)
			return m, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		tag.process(selectNDEF)
		tag.process(selectNDEFFile)
		return tag, &commits
	}
	status := func(resp []byte) int { return int(resp[len(resp)-2])<<8 | int(resp[len(resp)-1]) }
	update := func(p1, p2 byte, data []byte, le ...byte) []byte {
		return concat([]byte{0, insUpdate, p1, p2, byte(len(data))}, data, le)
	}

	for name, tc := range map[string]struct {
		before []byte // a command to send first, if any
		cmd    []byte
		want   int
	}{
		"a whole message":                {nil, writeAt(0, []byte{0, 2, 0xd0, 0}), swOK},
		"an offset with nothing staged":  {nil, writeAt(2, []byte{1}), swConditionsNotMet},
		"P1's high bit":                  {nil, update(0x80, 0, []byte{0, 1, 0}), swWrongP1P2},
		"no data":                        {nil, update(0, 0, nil), swWrongP1P2},
		"an Le":                          {nil, update(0, 0, []byte{0, 1, 0}, 0), swWrongP1P2},
		"one byte at offset 0":           {nil, writeAt(0, []byte{0}), swWrongLength},
		"NLEN over the file":             {nil, writeAt(0, []byte{0x7f, 0xff, 0}), swNotEnoughMemory},
		"NLEN and data disagree":         {nil, writeAt(0, []byte{0, 5, 0xd0, 0}), swConditionsNotMet},
		"a piece into the NLEN":          {writeAt(0, []byte{0, 0}), writeAt(1, []byte{1}), swNotEnoughMemory},
		"the last byte the file holds":   {writeAt(0, []byte{0, 0}), writeAt(maxNDEF+1, []byte{1}), swOK},
		"a piece past the file":          {writeAt(0, []byte{0, 0}), writeAt(maxNDEF+2, []byte{1}), swNotEnoughMemory},
		"a piece ending past the file":   {writeAt(0, []byte{0, 0}), writeAt(maxNDEF, []byte{1, 2, 3}), swNotEnoughMemory},
		"commit before the bytes arrive": {writeAt(0, []byte{0, 0}), writeAt(0, []byte{0, 4}), swConditionsNotMet},
	} {
		t.Run(name, func(t *testing.T) {
			tag, commits := newTag(t)
			if tc.before != nil {
				if got := status(mustProcess(t, tag, tc.before)); got != swOK {
					t.Fatalf("first command: %04X", got)
				}
			}
			if got := status(mustProcess(t, tag, tc.cmd)); got != tc.want {
				t.Errorf("status %04X, want %04X", got, tc.want)
			}
			if wantCommits := btoi(tc.want == swOK && tc.before == nil); len(*commits) != wantCommits {
				t.Errorf("%d commits, want %d", len(*commits), wantCommits)
			}
		})
	}

	// In pieces: NLEN 0, the message's bytes in any order, then its NLEN.
	tag, commits := newTag(t)
	message := []byte{0xd1, 1, 3, 'T', 'a', 'b', 'c'}
	for _, cmd := range [][]byte{writeAt(0, []byte{0, 0}), writeAt(2+4, message[4:]), writeAt(2, message[:4]), writeAt(0, []byte{0, byte(len(message))})} {
		if got := status(mustProcess(t, tag, cmd)); got != swOK {
			t.Fatalf("%X: status %04X", cmd, got)
		}
	}
	if len(*commits) != 1 || !bytes.Equal((*commits)[0], message) {
		t.Errorf("commits %X, want the message once", *commits)
	}
}

func mustProcess(t *testing.T, tag *type4Tag, cmd []byte) []byte {
	t.Helper()
	resp, _ := tag.process(testbounds.Exact(cmd))
	if len(resp) < 2 {
		t.Fatalf("%X: response %X", cmd, resp)
	}
	return resp
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
