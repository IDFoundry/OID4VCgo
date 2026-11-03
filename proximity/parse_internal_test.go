package proximity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func mustCBOR(t *testing.T, v any) cbor.RawMessage {
	t.Helper()
	b, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A DeviceEngagement's Security is refused unless it's a two-member
// array of cipher suite 1 and a tagged EDeviceKey, as a reader parsing a
// QR code a hostile holder shows must.
func TestDecodeEngagementSecurity_Refuses(t *testing.T) {
	notTagged := mustCBOR(t, []byte{1, 2, 3})
	tagged := func(content []byte) cbor.RawMessage {
		return mustCBOR(t, cbor.Tag{Number: 24, Content: content})
	}
	for name, security := range map[string]cbor.RawMessage{
		"not an array":       mustCBOR(t, "security"),
		"one member":         mustCBOR(t, []any{cipherSuite1}),
		"suite not a number": mustCBOR(t, []any{"one", notTagged}),
		"another suite":      mustCBOR(t, []any{2, notTagged}),
		"key not tagged":     mustCBOR(t, []any{cipherSuite1, "key"}),
		"key not a COSE_Key": mustCBOR(t, []any{cipherSuite1, tagged(mustCBOR(t, "not a key"))}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeEngagementSecurity(security); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// A malformed retrieval method is refused as ErrCBORDecoding; methods
// that aren't BLE, or offer no mode with a 16-byte UUID, are skipped.
func TestSelectBLEMethod(t *testing.T) {
	uuid := bytes.Repeat([]byte{7}, 16)
	ble := func(opts bleOptions) cbor.RawMessage {
		return mustCBOR(t, []any{retrievalTypeBLE, retrievalVersionBLE, opts})
	}
	for name, methods := range map[string][]cbor.RawMessage{
		"not an array":      {mustCBOR(t, "method")},
		"too short":         {mustCBOR(t, []any{retrievalTypeBLE, 1})},
		"type not a number": {mustCBOR(t, []any{"ble", 1, map[string]any{}})},
		"options not a map": {mustCBOR(t, []any{retrievalTypeBLE, 1, "options"})},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := selectBLEMethod(methods); !errors.Is(err, ErrCBORDecoding) {
				t.Errorf("err = %v, want ErrCBORDecoding", err)
			}
		})
	}

	nfc := mustCBOR(t, []any{1, 1, map[string]any{}})
	short := ble(bleOptions{PeripheralServer: true, PeripheralUUID: []byte{1}})
	ok, mode, got, err := selectBLEMethod([]cbor.RawMessage{nfc, short, ble(bleOptions{PeripheralServer: true, PeripheralUUID: uuid})})
	if err != nil || !ok || mode != PeripheralServer || !bytes.Equal(got, uuid) {
		t.Errorf("selectBLEMethod = %v, %v, %x, %v; want the peripheral server method", ok, mode, got, err)
	}
	if ok, _, _, err := selectBLEMethod([]cbor.RawMessage{nfc}); ok || err != nil {
		t.Errorf("no BLE method: %v, %v; want none", ok, err)
	}
}

// cborMapHeader reads every header length a CBOR map can have, and
// refuses what isn't one.
func TestCBORMapHeader(t *testing.T) {
	for name, tc := range map[string]struct {
		raw        []byte
		n          uint64
		indefinite bool
		rest       []byte
	}{
		"small":      {raw: []byte{0xa2, 9}, n: 2, rest: []byte{9}},
		"one byte":   {raw: []byte{0xb8, 30, 9}, n: 30, rest: []byte{9}},
		"two bytes":  {raw: []byte{0xb9, 0x01, 0x00}, n: 256, rest: []byte{}},
		"four bytes": {raw: []byte{0xba, 0, 1, 0, 0}, n: 65536, rest: []byte{}},
		"indefinite": {raw: []byte{0xbf, 0xff}, indefinite: true, rest: []byte{0xff}},
	} {
		t.Run(name, func(t *testing.T) {
			n, indefinite, rest, err := cborMapHeader(tc.raw)
			if err != nil || n != tc.n || indefinite != tc.indefinite || !bytes.Equal(rest, tc.rest) {
				t.Errorf("cborMapHeader(%x) = %d, %v, %x, %v", tc.raw, n, indefinite, rest, err)
			}
		})
	}
	for name, raw := range map[string][]byte{
		"empty":         {},
		"not a map":     {0x82, 1, 2},
		"truncated":     {0xb9, 0x01},
		"reserved info": {0xbc},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := cborMapHeader(raw); !errors.Is(err, ErrCBORDecoding) {
				t.Errorf("cborMapHeader(%x) = %v, want ErrCBORDecoding", raw, err)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

// A random source that fails fails the session, for either mode's UUID.
func TestModeUUIDs_RandomFails(t *testing.T) {
	for _, modes := range [][2]bool{{true, false}, {false, true}} {
		if _, _, err := modeUUIDs(failingReader{}, modes[0], modes[1]); err == nil {
			t.Errorf("modeUUIDs(peripheral=%v, central=%v) accepted a failing random source", modes[0], modes[1])
		}
	}
}

// A SessionData-shaped {"x": [[{} × inner] × outer]} under
// MaxMessageBytes is refused before it's decoded: past the container
// bound with 65 535 maps per array, past the message's item bound with
// 4096.
func TestDecodeSessionDataRefusesItemFlood(t *testing.T) {
	for _, inner := range []int{65535, 4096} {
		array := append([]byte{0x99, byte(inner >> 8), byte(inner)}, bytes.Repeat([]byte{0xa0}, inner)...)
		outer := (MaxMessageBytes - 16) / len(array)
		msg := []byte{0xa1, 0x61, 'x', 0x99, byte(outer >> 8), byte(outer)}
		for range outer {
			msg = append(msg, array...)
		}
		if _, err := decodeSessionData(msg); !errors.Is(err, ErrCBORDecoding) {
			t.Fatalf("inner %d: decodeSessionData = %v, want ErrCBORDecoding", inner, err)
		}
		allocs := testing.AllocsPerRun(1, func() { _, _ = decodeSessionData(msg) })
		if allocs > 100 {
			t.Errorf("inner %d: decodeSessionData made %v allocations, want it refused before decoding", inner, allocs)
		}
	}
}

// TestCompressedEDeviceKey: an mdoc may send EDeviceKey as a compressed
// point, y its sign bit (ISO/IEC 18013-5 second edition §12.7.2); EReaderKey, and
// a point off the curve, stay refused.
func TestCompressedEDeviceKey(t *testing.T) {
	for range 4 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		b, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		compressed := mustCBOR(t, map[int]any{1: 2, -1: 1, -2: b[1:33], -3: b[64]&1 == 1})
		edkb, err := wrapTag24(compressed)
		if err != nil {
			t.Fatal(err)
		}
		de, err := encodeQREngagement(mustCBOR(t, []any{1, cbor.RawMessage(edkb)}), make([]byte, 16), nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseDeviceEngagement(de)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.eDeviceKey.Equal(&key.PublicKey) {
			t.Error("the decompressed EDeviceKey isn't the mdoc's key")
		}
		if _, err := decodeCoseKey(compressed); err == nil {
			t.Error("a compressed EReaderKey was accepted")
		}
	}
	offCurve := mustCBOR(t, map[int]any{1: 2, -1: 1, -2: bytes.Repeat([]byte{0xff}, 32), -3: true})
	if _, err := decodeEDeviceKey(offCurve); err == nil {
		t.Error("a compressed point off P-256 was accepted")
	}
}
