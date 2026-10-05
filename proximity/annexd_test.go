package proximity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
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

// TestAnnexDReader drives a ReaderSession through Annex D's session
// from the other side: the published DeviceRequest encrypts under
// SKReader to the published SessionEstablishment byte for byte, and the
// published SessionData decrypts under SKDevice to the published
// DeviceResponse.
func TestAnnexDReader(t *testing.T) {
	de, _, handover := annexDTranscriptParts(t)
	key := annexDKey(t, annexDEphemeralReaderKeyD, annexDEphemeralReaderKeyX, annexDEphemeralReaderKeyY)
	r, err := newReaderSession(key, de, handover)
	if err != nil {
		t.Fatalf("newReaderSession: %v", err)
	}
	if !bytes.Equal(r.SessionTranscriptBytes(), mustHex(t, annexDSessionTranscriptBytes)) {
		t.Error("SessionTranscriptBytes differs from Annex D's")
	}
	msg, err := r.establishment(mustHex(t, annexDDeviceRequest))
	if err != nil {
		t.Fatalf("establishment: %v", err)
	}
	if !bytes.Equal(msg, mustHex(t, annexDSessionEstablishment)) {
		t.Errorf("SessionEstablishment differs:\n got %x\nwant %s", msg, annexDSessionEstablishment)
	}
	data, status, err := receive(r.cipher, mustHex(t, annexDSessionData))
	if err != nil || status != nil {
		t.Fatalf("receive SessionData: %v, status %v", err, status)
	}
	if !bytes.Equal(data, mustHex(t, annexDDeviceResponse)) {
		t.Error("decrypted DeviceResponse differs from Annex D's")
	}
}

// TestAnnexDParseDeviceRequest: Annex D's DeviceRequest parses to its
// six elements in request order, with portrait the one not retained,
// the exact ItemsRequestBytes and the readerAuth kept.
func TestAnnexDParseDeviceRequest(t *testing.T) {
	reqs, err := ParseDeviceRequest(mustHex(t, annexDDeviceRequest))
	if err != nil {
		t.Fatalf("ParseDeviceRequest: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("got %d DocRequests, want 1", len(reqs))
	}
	req := reqs[0]
	if req.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("DocType = %q", req.DocType)
	}
	const ns = "org.iso.18013.5.1"
	want := []string{"family_name", "document_number", "driving_privileges", "issue_date", "expiry_date", "portrait"}
	if len(req.Elements) != len(want) {
		t.Fatalf("Elements = %v, want %v", req.Elements, want)
	}
	for i, el := range want {
		if req.Elements[i] != [2]string{ns, el} {
			t.Errorf("Elements[%d] = %v, want %s", i, req.Elements[i], el)
		}
		if got := req.IntentToRetain[[2]string{ns, el}]; got != (el != "portrait") {
			t.Errorf("IntentToRetain[%s] = %v", el, got)
		}
	}
	items, err := unwrapTag24(req.ItemsRequestBytes)
	if err != nil || !bytes.Equal(items, mustHex(t, annexDItemsRequest)) {
		t.Errorf("ItemsRequestBytes does not wrap Annex D's ItemsRequest: %v", err)
	}
	if req.ReaderAuth == nil {
		t.Error("ReaderAuth not kept")
	}
}

// TestAnnexDDeviceResponse: Annex D's DeviceResponse parses, its issuer
// signature and digests verify under the published document signer
// certificate at a time inside its validity, and its DeviceMAC verifies
// with the static device key and the ephemeral reader key over the
// published transcript.
func TestAnnexDDeviceResponse(t *testing.T) {
	doc, err := parseDeviceResponse(mustHex(t, annexDDeviceResponse))
	if err != nil {
		t.Fatalf("parseDeviceResponse: %v", err)
	}
	if doc.deviceSigned.AuthType != mdoc.DeviceAuthMAC {
		t.Fatalf("AuthType = %v, want DeviceAuthMAC", doc.deviceSigned.AuthType)
	}
	cert, err := x509.ParseCertificate(mustHex(t, annexDDsCert))
	if err != nil {
		t.Fatalf("parse DS certificate: %v", err)
	}
	at := cert.NotBefore.Add(24 * time.Hour)
	verified, err := mdoc.Verify(doc.issuerSigned, doc.docType, cert.PublicKey, cose.ES256, mdoc.VerifyOptions{
		Now: func() time.Time { return at },
	})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["family_name"]; got != "Doe" {
		t.Errorf("family_name = %v, want Doe", got)
	}

	static := annexDKey(t, annexDStaticDeviceKeyD, annexDStaticDeviceKeyX, annexDStaticDeviceKeyY)
	if !static.PublicKey.Equal(verified.DeviceKey) {
		t.Error("MSO device key is not Annex D's static device key")
	}
	reader := annexDKey(t, annexDEphemeralReaderKeyD, annexDEphemeralReaderKeyX, annexDEphemeralReaderKeyY)
	transcript := mustHex(t, annexDSessionTranscriptBytes)
	if err := mdoc.VerifyDeviceMAC(doc.deviceSigned, &static.PublicKey, reader, transcript, doc.docType); err != nil {
		t.Errorf("VerifyDeviceMAC: %v", err)
	}
	transcript[len(transcript)-1] ^= 1
	if err := mdoc.VerifyDeviceMAC(doc.deviceSigned, &static.PublicKey, reader, transcript, doc.docType); err == nil {
		t.Error("VerifyDeviceMAC over a different transcript: verified")
	}
}
