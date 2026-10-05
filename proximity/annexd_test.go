package proximity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// annexDKey is one of Annex D's P-256 private keys, checked against its
// published public coordinates.
func annexDKey(t testing.TB, d, x, y string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), mustHex(t, d))
	if err != nil {
		t.Fatalf("parse Annex D private key: %v", err)
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub[1:33], mustHex(t, x)) || !bytes.Equal(pub[33:], mustHex(t, y)) {
		t.Fatal("Annex D private key does not match its published public key")
	}
	return key
}

// annexDTranscriptParts splits Annex D's SessionTranscriptBytes into the
// exact DeviceEngagement bytes, EReaderKey bytes and Handover it was
// built from.
func annexDTranscriptParts(t testing.TB) (deviceEngagement, eReaderKey []byte, handover cbor.RawMessage) {
	t.Helper()
	transcript, err := unwrapTag24(mustHex(t, annexDSessionTranscriptBytes))
	if err != nil {
		t.Fatalf("unwrap SessionTranscriptBytes: %v", err)
	}
	var parts []cbor.RawMessage
	if err := decMode.Unmarshal(transcript, &parts); err != nil || len(parts) != 3 {
		t.Fatalf("decode SessionTranscript: %v (%d parts)", err, len(parts))
	}
	if deviceEngagement, err = unwrapTag24(parts[0]); err != nil {
		t.Fatalf("DeviceEngagementBytes: %v", err)
	}
	if eReaderKey, err = unwrapTag24(parts[1]); err != nil {
		t.Fatalf("EReaderKeyBytes: %v", err)
	}
	return deviceEngagement, eReaderKey, parts[2]
}

func annexDDeviceSession(t testing.TB) *DeviceSession {
	t.Helper()
	de, _, handover := annexDTranscriptParts(t)
	key := annexDKey(t, annexDEphemeralDeviceKeyD, annexDEphemeralDeviceKeyX, annexDEphemeralDeviceKeyY)
	return newDeviceSession(key, nil, de, handover)
}

// TestAnnexDDeviceEngagement: Annex D's QR DeviceEngagement parses to
// its published EDeviceKey and BLE central client mode UUID, and
// encoding those back gives the same bytes.
func TestAnnexDDeviceEngagement(t *testing.T) {
	raw := mustHex(t, annexDDeviceEngagement)
	pe, err := parseDeviceEngagement(raw)
	if err != nil {
		t.Fatalf("parseDeviceEngagement: %v", err)
	}
	key := annexDKey(t, annexDEphemeralDeviceKeyD, annexDEphemeralDeviceKeyX, annexDEphemeralDeviceKeyY)
	if !pe.eDeviceKey.Equal(&key.PublicKey) {
		t.Error("EDeviceKey does not match Annex D's ephemeral device key")
	}
	if !pe.ble || pe.bleMode != CentralClient {
		t.Errorf("BLE = %v, mode %v; want central client", pe.ble, pe.bleMode)
	}
	if got, want := formatUUID(pe.uuid), "45efef74-2b2c-4837-a9a3-b0e1d05a6917"; got != want {
		t.Errorf("UUID = %s, want %s", got, want)
	}

	encoded, err := encodeDeviceEngagement(pe.eDeviceKey, pe.bleMode, pe.uuid)
	if err != nil {
		t.Fatalf("encodeDeviceEngagement: %v", err)
	}
	if !bytes.Equal(encoded, raw) {
		t.Errorf("re-encoded DeviceEngagement differs:\n got %x\nwant %x", encoded, raw)
	}

	qr := encodeQR(raw)
	back, err := decodeQR(qr)
	if err != nil || !bytes.Equal(back, raw) {
		t.Errorf("QR round trip: %v", err)
	}
}

// TestAnnexDHolder drives a DeviceSession through Annex D's session:
// SessionEstablishment decrypts to the published DeviceRequest under
// the derived SKReader, the SessionTranscriptBytes match, the published
// DeviceResponse encrypts under SKDevice to the published SessionData
// byte for byte, and termination matches both ways.
func TestAnnexDHolder(t *testing.T) {
	s := annexDDeviceSession(t)

	req, err := s.HandleSessionEstablishment(mustHex(t, annexDSessionEstablishment))
	if err != nil {
		t.Fatalf("HandleSessionEstablishment: %v", err)
	}
	if !bytes.Equal(req, mustHex(t, annexDDeviceRequest)) {
		t.Error("decrypted DeviceRequest differs from Annex D's")
	}
	if !bytes.Equal(s.SessionTranscriptBytes(), mustHex(t, annexDSessionTranscriptBytes)) {
		t.Error("SessionTranscriptBytes differs from Annex D's")
	}

	msg, err := s.Encrypt(mustHex(t, annexDDeviceResponse), false)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(msg, mustHex(t, annexDSessionData)) {
		t.Error("encrypted SessionData differs from Annex D's")
	}

	data, status, err := s.HandleSessionData(mustHex(t, annexDSessionTermination))
	if err != nil || data != nil || status == nil || *status != StatusSessionTermination {
		t.Errorf("HandleSessionData(termination) = %x, %v, %v; want status 20", data, status, err)
	}
	if !bytes.Equal(s.Termination(), mustHex(t, annexDSessionTermination)) {
		t.Error("Termination differs from Annex D's")
	}
	if _, err := s.Encrypt([]byte{0}, false); err != ErrSessionClosed {
		t.Errorf("Encrypt after termination: %v, want ErrSessionClosed", err)
	}
}

// TestAnnexDSessionTranscript: rebuilding SessionTranscriptBytes from
// its parts gives Annex D's bytes.
func TestAnnexDSessionTranscript(t *testing.T) {
	de, eReaderKey, handover := annexDTranscriptParts(t)
	got, err := buildSessionTranscriptBytes(de, eReaderKey, handover)
	if err != nil {
		t.Fatalf("buildSessionTranscriptBytes: %v", err)
	}
	if !bytes.Equal(got, mustHex(t, annexDSessionTranscriptBytes)) {
		t.Errorf("SessionTranscriptBytes differs:\n got %x\nwant %s", got, annexDSessionTranscriptBytes)
	}
}
