package proximity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Every engagement a holder writes, QR or NFC, is version 1.1 with
// originInfos 5: [] and capabilities 6: {4: true}, and parses back to
// extended request support.
func TestDeviceEngagement_AdvertisesExtendedRequestSupport(t *testing.T) {
	data := NFCDataParameters{MaxCommand: 255, MaxResponse: 256}
	for name, start := range map[string]func() (*DeviceSession, error){
		"QR": func() (*DeviceSession, error) { return NewDeviceSession(nil) },
		"QR, both BLE modes": func() (*DeviceSession, error) {
			return NewDeviceSession(nil, WithBLEModes(PeripheralServer, CentralClient))
		},
		"NFC static handover":     func() (*DeviceSession, error) { return NewNFCDeviceSession(nil) },
		"NFC negotiated handover": func() (*DeviceSession, error) { return NewNFCNegotiatedDeviceSession(nil) },
		"NFC data":                func() (*DeviceSession, error) { return NewNFCDataDeviceSession(nil, data) },
		"NFC negotiated data":     func() (*DeviceSession, error) { return NewNFCNegotiatedDataDeviceSession(nil, data) },
	} {
		t.Run(name, func(t *testing.T) {
			s, err := start()
			if err != nil {
				t.Fatal(err)
			}
			de := s.DeviceEngagementBytes()
			var members map[int]cbor.RawMessage
			if err := cbor.Unmarshal(de, &members); err != nil {
				t.Fatal(err)
			}
			var version string
			if err := cbor.Unmarshal(members[0], &version); err != nil || version != "1.1" {
				t.Errorf("version %q (%v), want 1.1", version, err)
			}
			if got := members[5]; !bytes.Equal(got, []byte{0x80}) {
				t.Errorf("originInfos %x, want 80 (an empty array)", got)
			}
			var capabilities map[int]any
			if err := cbor.Unmarshal(members[6], &capabilities); err != nil || len(capabilities) != 1 || capabilities[4] != true {
				t.Errorf("capabilities %v (%v), want {4: true}", capabilities, err)
			}
			pe, err := parseDeviceEngagement(de)
			if err != nil {
				t.Fatal(err)
			}
			if !pe.extendedRequestSupport {
				t.Error("parsed back without extended request support")
			}
		})
	}
}

// The capabilities member's ExtendedRequestSupport is read as true only
// when key 4 holds true; an engagement without capabilities, as version
// 1.0's, or with a capabilities member this package can't read, still
// parses, advertising nothing.
func TestParseDeviceEngagement_Capabilities(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	security, err := encodeEngagementSecurity(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	method := mustCBOR(t, []any{retrievalTypeBLE, retrievalVersionBLE, bleOptions{PeripheralServer: true, PeripheralUUID: make([]byte, 16)}})
	engagement := func(version string, extra map[int]any) []byte {
		m := map[int]any{0: version, 1: security, 2: []cbor.RawMessage{method}}
		for k, v := range extra {
			m[k] = v
		}
		return mustCBOR(t, m)
	}
	for name, tc := range map[string]struct {
		de   []byte
		want bool
	}{
		"1.0, no capabilities":          {engagement("1.0", nil), false},
		"1.1, no capabilities":          {engagement("1.1", map[int]any{5: []any{}}), false},
		"4: true":                       {engagement("1.1", map[int]any{5: []any{}, 6: map[int]any{4: true}}), true},
		"4: true, without originInfos":  {engagement("1.1", map[int]any{6: map[int]any{4: true}}), true},
		"4: true among others":          {engagement("1.1", map[int]any{6: map[int]any{2: false, 3: true, 4: true, -7: "ext"}}), true},
		"4: false":                      {engagement("1.1", map[int]any{6: map[int]any{4: false}}), false},
		"4: 1":                          {engagement("1.1", map[int]any{6: map[int]any{4: 1}}), false},
		"only 3: true":                  {engagement("1.1", map[int]any{6: map[int]any{3: true}}), false},
		"empty capabilities":            {engagement("1.1", map[int]any{6: map[int]any{}}), false},
		"capabilities not a map":        {engagement("1.1", map[int]any{6: []any{4, true}}), false},
		"capabilities with a text key":  {engagement("1.1", map[int]any{6: map[string]any{"4": true}}), false},
		"a later 1.x with capabilities": {engagement("1.2", map[int]any{6: map[int]any{4: true}, 7: "later"}), true},
	} {
		t.Run(name, func(t *testing.T) {
			pe, err := parseDeviceEngagement(tc.de)
			if err != nil {
				t.Fatalf("parseDeviceEngagement: %v", err)
			}
			if pe.extendedRequestSupport != tc.want {
				t.Errorf("extendedRequestSupport = %v, want %v", pe.extendedRequestSupport, tc.want)
			}
			if !pe.ble || pe.bleMode != PeripheralServer {
				t.Errorf("BLE = %v, mode %v; want peripheral server", pe.ble, pe.bleMode)
			}
		})
	}
	if _, err := parseDeviceEngagement(engagement("2.0", map[int]any{6: map[int]any{4: true}})); err == nil {
		t.Error("a version 2.0 engagement was accepted")
	}
}
