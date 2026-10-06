package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

const (
	mDL   = "org.iso.18013.5.1.mDL"
	mDLNS = "org.iso.18013.5.1"
)

// fixture is a freshly issued mdoc under a test IACA → document signer
// chain, with the holder's device key.
type fixture struct {
	docType      string
	issuerSigned mdoc.IssuerSigned
	deviceKey    *ecdsa.PrivateKey
	roots        *x509.CertPool
}

func issueFixture(t testing.TB, docType string) fixture {
	t.Helper()
	ca, caKey := testIACA(t)
	ds, dsKey := testDocumentSigner(t, ca, caKey)
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := time.Now().Add(-time.Minute)
	issuerSigned, err := mdoc.Issue(dsKey, cose.ES256, mdoc.Claims{
		DocType: docType,
		NameSpaces: map[string]map[string]interface{}{
			mDLNS: {
				"given_name":      "Alice",
				"family_name":     "Doe",
				"document_number": "D1234567",
				"age_over_18":     true,
				"age_over_21":     false,
			},
		},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed,
		ValidFrom:  signed,
		ValidUntil: signed.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return fixture{docType: docType, issuerSigned: issuerSigned, deviceKey: deviceKey, roots: roots}
}

// flow is one engaged and established session, request decoded by the
// holder.
type flow struct {
	holder *DeviceSession
	reader *ReaderSession
	req    DocRequest
}

func establish(t testing.TB, docType string, elements map[string][]string, opts ...DeviceOption) flow {
	t.Helper()
	return establishWith(t, docType, elements, opts, nil)
}

// establishReader is establish with reader options.
func establishReader(t testing.TB, docType string, elements map[string][]string, opts ...ReaderOption) flow {
	t.Helper()
	return establishWith(t, docType, elements, nil, opts)
}

func establishWith(t testing.TB, docType string, elements map[string][]string, deviceOpts []DeviceOption, readerOpts []ReaderOption) flow {
	t.Helper()
	holder, err := NewDeviceSession(nil, deviceOpts...)
	if err != nil {
		t.Fatalf("NewDeviceSession: %v", err)
	}
	reader, err := NewReaderSession(holder.QRCode(), readerOpts...)
	if err != nil {
		t.Fatalf("NewReaderSession: %v", err)
	}
	if reader.ServiceUUID() != holder.ServiceUUID() {
		t.Fatalf("reader UUID %s, holder %s", reader.ServiceUUID(), holder.ServiceUUID())
	}
	est, err := reader.Establishment(docType, elements)
	if err != nil {
		t.Fatalf("Establishment: %v", err)
	}
	reqBytes, err := holder.HandleSessionEstablishment(est)
	if err != nil {
		t.Fatalf("HandleSessionEstablishment: %v", err)
	}
	reqs, err := ParseDeviceRequest(reqBytes)
	if err != nil {
		t.Fatalf("ParseDeviceRequest: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("got %d DocRequests", len(reqs))
	}
	return flow{holder: holder, reader: reader, req: reqs[0]}
}

// respond builds and encrypts the holder's DeviceResponse for elements.
func (f flow) respond(t *testing.T, fx fixture, elements [][2]string) []byte {
	t.Helper()
	resp, err := buildDeviceResponse(fx.issuerSigned, fx.docType, fx.deviceKey, f.holder.SessionTranscriptBytes(), elements)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}
	msg, err := f.holder.Encrypt(resp, false)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return msg
}

func TestRoundTripAgeOver18(t *testing.T) {
	fx := issueFixture(t, mDL)
	f := establish(t, mDL, map[string][]string{mDLNS: {"age_over_18"}})
	if want := [][2]string{{mDLNS, "age_over_18"}}; len(f.req.Elements) != 1 || f.req.Elements[0] != want[0] {
		t.Fatalf("holder saw %v, want %v", f.req.Elements, want)
	}

	v, err := f.reader.Verify(f.respond(t, fx, f.req.Elements), fx.roots, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := v.Claims[mDLNS]; len(got) != 1 || got["age_over_18"] != true {
		t.Errorf("Claims = %v, want only age_over_18 = true", v.Claims)
	}
	if v.DocType != mDL || v.IssuerCN != "Test Document Signer" || v.TrustAnchorCN != "Test IACA" {
		t.Errorf("Verified = %+v", v)
	}
	if v.DeviceAuth != mdoc.DeviceAuthSignature {
		t.Errorf("DeviceAuth = %v, want signature", v.DeviceAuth)
	}
	if v.ValidUntil.Before(time.Now()) || v.ValidFrom.After(time.Now()) {
		t.Errorf("validity %v – %v does not cover now", v.ValidFrom, v.ValidUntil)
	}
}

// TestRoundTripMultipleElements also covers central client mode, and a
// holder that discloses only a consented subset of the request.
func TestRoundTripMultipleElements(t *testing.T) {
	fx := issueFixture(t, mDL)
	requested := map[string][]string{mDLNS: {"given_name", "family_name", "document_number", "age_over_21"}}
	f := establish(t, mDL, requested, WithBLEMode(CentralClient))
	if f.reader.BLEMode() != CentralClient {
		t.Errorf("reader BLEMode = %v, want central client", f.reader.BLEMode())
	}
	if id := f.holder.BLEIdent(); len(id) != 16 || string(id) != string(f.reader.BLEIdent()) {
		t.Errorf("BLEIdent: holder %x, reader %x", id, f.reader.BLEIdent())
	}
	if other := establish(t, mDL, requested); string(other.holder.BLEIdent()) == string(f.holder.BLEIdent()) {
		t.Error("two sessions share a BLEIdent")
	}
	if len(f.req.Elements) != 4 {
		t.Fatalf("holder saw %v", f.req.Elements)
	}

	consented := [][2]string{{mDLNS, "given_name"}, {mDLNS, "family_name"}, {mDLNS, "age_over_21"}}
	v, err := f.reader.Verify(f.respond(t, fx, consented), fx.roots, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got := v.Claims[mDLNS]
	if len(got) != 3 || got["given_name"] != "Alice" || got["family_name"] != "Doe" || got["age_over_21"] != false {
		t.Errorf("Claims = %v", v.Claims)
	}
	if _, err := f.reader.Verify(nil, fx.roots, time.Now()); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("second Verify: %v, want ErrSessionClosed", err)
	}
}

func TestDeclined(t *testing.T) {
	fx := issueFixture(t, mDL)
	f := establish(t, mDL, map[string][]string{mDLNS: {"age_over_18"}})
	_, err := f.reader.Verify(f.holder.Termination(), fx.roots, time.Now())
	if !errors.Is(err, ErrDeclined) {
		t.Errorf("Verify(termination) = %v, want ErrDeclined", err)
	}
	if _, err := f.holder.Encrypt([]byte{0xa0}, false); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("holder Encrypt after Termination: %v, want ErrSessionClosed", err)
	}
}

func TestStatusReply(t *testing.T) {
	fx := issueFixture(t, mDL)
	f := establish(t, mDL, map[string][]string{mDLNS: {"age_over_18"}})
	_, err := f.reader.Verify(StatusMessage(StatusCBORDecodingError), fx.roots, time.Now())
	if err == nil || !strings.Contains(err.Error(), "status 11") {
		t.Errorf("Verify(status 11) = %v", err)
	}
}

// TestRejects covers each verification failure on the reader side.
func TestRejects(t *testing.T) {
	age := map[string][]string{mDLNS: {"age_over_18"}}
	ageOnly := [][2]string{{mDLNS, "age_over_18"}}

	tests := []struct {
		name string
		run  func(t *testing.T) error
		want string
	}{
		{"untrusted issuer root", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			other := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			_, err := f.reader.Verify(f.respond(t, fx, ageOnly), other.roots, time.Now())
			return err
		}, "does not verify against a trusted root"},
		{"expired MSO", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			_, err := f.reader.Verify(f.respond(t, fx, ageOnly), fx.roots, time.Now().Add(2*time.Hour))
			return err
		}, "MSO has expired"},
		{"element not requested", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			_, err := f.reader.Verify(f.respond(t, fx, [][2]string{{mDLNS, "age_over_18"}, {mDLNS, "family_name"}}), fx.roots, time.Now())
			return err
		}, "unrequested elements [org.iso.18013.5.1/family_name]"},
		{"docType mismatch", func(t *testing.T) error {
			fx := issueFixture(t, "org.example.other")
			f := establish(t, mDL, age)
			_, err := f.reader.Verify(f.respond(t, fx, ageOnly), fx.roots, time.Now())
			return err
		}, `docType "org.example.other", requested`},
		{"device signature over another session's transcript", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			other := establish(t, mDL, age)
			resp, err := buildDeviceResponse(fx.issuerSigned, mDL, fx.deviceKey, other.holder.SessionTranscriptBytes(), ageOnly)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := f.holder.Encrypt(resp, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.reader.Verify(msg, fx.roots, time.Now())
			return err
		}, "DeviceSignature"},
		{"device signature by a key not in the MSO", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			fx.deviceKey = issueFixture(t, mDL).deviceKey
			f := establish(t, mDL, age)
			_, err := f.reader.Verify(f.respond(t, fx, ageOnly), fx.roots, time.Now())
			return err
		}, "DeviceSignature"},
		{"tampered response ciphertext", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			msg := tamperData(t, f.respond(t, fx, ageOnly))
			_, err := f.reader.Verify(msg, fx.roots, time.Now())
			return wantStatus(t, err, StatusSessionEncryptionError)
		}, "decrypt"},
		{"reordered response", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			f.respond(t, fx, ageOnly) // message 1, never delivered
			_, err := f.reader.Verify(f.respond(t, fx, ageOnly), fx.roots, time.Now())
			return wantStatus(t, err, StatusSessionEncryptionError)
		}, "decrypt message 1"},
		{"encrypted non-CBOR response", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			msg, err := f.holder.Encrypt([]byte{0xff, 0x00}, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.reader.Verify(msg, fx.roots, time.Now())
			return wantStatus(t, err, StatusCBORDecodingError)
		}, "decode DeviceResponse"},
		{"malformed SessionData", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			_, err := f.reader.Verify([]byte{0x83, 0x01}, fx.roots, time.Now())
			return wantStatus(t, err, StatusCBORDecodingError)
		}, "decode SessionData"},
		{"oversize SessionData", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			_, err := f.reader.Verify(make([]byte, MaxMessageBytes+1), fx.roots, time.Now())
			return wantStatus(t, err, StatusCBORDecodingError)
		}, "over"},
		{"no document", func(t *testing.T) error {
			fx := issueFixture(t, mDL)
			f := establish(t, mDL, age)
			resp, err := encMode.Marshal(map[string]any{"version": "1.0", "documentErrors": []map[string]int{{mDL: 0}}, "status": 0})
			if err != nil {
				t.Fatal(err)
			}
			msg, err := f.holder.Encrypt(resp, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.reader.Verify(msg, fx.roots, time.Now())
			if !errors.Is(err, ErrNoDocument) {
				t.Errorf("err = %v, want ErrNoDocument", err)
			}
			return err
		}, "no document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(t)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// TestHolderRejects covers the holder side's message handling.
func TestHolderRejects(t *testing.T) {
	newEstablishment := func(t *testing.T) (*DeviceSession, []byte) {
		t.Helper()
		holder, err := NewDeviceSession(nil)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := NewReaderSession(holder.QRCode())
		if err != nil {
			t.Fatal(err)
		}
		est, err := reader.Establishment(mDL, map[string][]string{mDLNS: {"age_over_18"}})
		if err != nil {
			t.Fatal(err)
		}
		return holder, est
	}

	t.Run("tampered SessionEstablishment", func(t *testing.T) {
		holder, est := newEstablishment(t)
		var se sessionEstablishment
		if err := decMode.Unmarshal(est, &se); err != nil {
			t.Fatal(err)
		}
		se.Data[len(se.Data)-1] ^= 1
		tampered, _ := encMode.Marshal(se)
		_, err := holder.HandleSessionEstablishment(tampered)
		wantStatus(t, err, StatusSessionEncryptionError)
		if _, err := holder.HandleSessionEstablishment(est); !errors.Is(err, ErrSessionClosed) {
			t.Errorf("after a failure: %v, want ErrSessionClosed", err)
		}
	})
	t.Run("replayed request", func(t *testing.T) {
		holder, est := newEstablishment(t)
		if _, err := holder.HandleSessionEstablishment(est); err != nil {
			t.Fatal(err)
		}
		var se sessionEstablishment
		if err := decMode.Unmarshal(est, &se); err != nil {
			t.Fatal(err)
		}
		replay, _ := encodeSessionData(se.Data, nil)
		_, _, err := holder.HandleSessionData(replay)
		wantStatus(t, err, StatusSessionEncryptionError)
	})
	t.Run("establishment twice", func(t *testing.T) {
		holder, est := newEstablishment(t)
		if _, err := holder.HandleSessionEstablishment(est); err != nil {
			t.Fatal(err)
		}
		if _, err := holder.HandleSessionEstablishment(est); err == nil {
			t.Error("second SessionEstablishment accepted")
		}
	})
	t.Run("reader termination", func(t *testing.T) {
		holder, est := newEstablishment(t)
		if _, err := holder.HandleSessionEstablishment(est); err != nil {
			t.Fatal(err)
		}
		data, status, err := holder.HandleSessionData(StatusMessage(StatusSessionTermination))
		if err != nil || data != nil || status == nil || *status != StatusSessionTermination {
			t.Errorf("HandleSessionData(20) = %x, %v, %v", data, status, err)
		}
		if _, err := holder.Encrypt([]byte{0xa0}, false); !errors.Is(err, ErrSessionClosed) {
			t.Errorf("Encrypt after reader termination: %v", err)
		}
	})
	malformed := map[string][]byte{
		"not CBOR":           {0xff},
		"wrong type":         {0x83, 0x01, 0x02, 0x03},
		"no eReaderKey":      mustMarshal(t, map[string]any{"data": []byte{1}}),
		"untagged key":       mustMarshal(t, map[string]any{"eReaderKey": []byte{0xa0}, "data": []byte{1}}),
		"key not a COSE_Key": mustMarshal(t, map[string]any{"eReaderKey": cbor.Tag{Number: 24, Content: []byte{0x01}}, "data": []byte{1}}),
		"oversize":           make([]byte, MaxMessageBytes+1),
	}
	for name, msg := range malformed {
		t.Run("malformed SessionEstablishment: "+name, func(t *testing.T) {
			holder, _ := newEstablishment(t)
			_, err := holder.HandleSessionEstablishment(msg)
			wantStatus(t, err, StatusCBORDecodingError)
		})
	}
	t.Run("malformed SessionData", func(t *testing.T) {
		for _, msg := range [][]byte{{0xff}, {0xa0}, mustMarshal(t, map[string]any{"data": "text"}), make([]byte, MaxMessageBytes+1)} {
			holder, est := newEstablishment(t)
			if _, err := holder.HandleSessionEstablishment(est); err != nil {
				t.Fatal(err)
			}
			_, _, err := holder.HandleSessionData(msg)
			wantStatus(t, err, StatusCBORDecodingError)
		}
	})
}

func TestParseDeviceRequestRejects(t *testing.T) {
	items := func(t *testing.T, v any) cbor.Tag {
		return cbor.Tag{Number: 24, Content: mustMarshal(t, v)}
	}
	tests := map[string][]byte{
		"not CBOR":        {0xff},
		"oversize":        make([]byte, MaxMessageBytes+1),
		"version 2.0":     mustMarshal(t, map[string]any{"version": "2.0", "docRequests": []any{}}),
		"no docRequests":  mustMarshal(t, map[string]any{"version": "1.0", "docRequests": []any{}}),
		"untagged items":  mustMarshal(t, map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": []byte{0xa0}}}}),
		"no docType":      mustMarshal(t, map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(t, map[string]any{"nameSpaces": map[string]any{mDLNS: map[string]bool{"x": true}}})}}}),
		"no nameSpaces":   mustMarshal(t, map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(t, map[string]any{"docType": mDL, "nameSpaces": map[string]any{}})}}}),
		"empty namespace": mustMarshal(t, map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(t, map[string]any{"docType": mDL, "nameSpaces": map[string]any{mDLNS: map[string]bool{}}})}}}),
		"non-bool intent": mustMarshal(t, map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(t, map[string]any{"docType": mDL, "nameSpaces": map[string]any{mDLNS: map[string]int{"x": 1}}})}}}),
		"duplicate element": mustMarshal(t, map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(t, map[string]any{"docType": mDL, "nameSpaces": map[string]cbor.RawMessage{
			mDLNS: {0xa2, 0x61, 'x', 0xf5, 0x61, 'x', 0xf4}, // {"x": true, "x": false}
		}})}}}),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDeviceRequest(b); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestNewReaderSessionRejects(t *testing.T) {
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	pe, err := parseDeviceEngagement(holder.DeviceEngagementBytes())
	if err != nil {
		t.Fatal(err)
	}
	coseKey, _ := encodeCoseKey(pe.eDeviceKey)
	keyBytes := cbor.Tag{Number: 24, Content: coseKey}
	engagement := func(t *testing.T, suite int, methods any) string {
		return "mdoc:" + base64.RawURLEncoding.EncodeToString(mustMarshal(t, map[int]any{0: "1.0", 1: []any{suite, keyBytes}, 2: methods}))
	}
	ble := []any{[]any{2, 1, map[int]any{0: true, 1: false, 10: make([]byte, 16)}}}

	tests := map[string]struct {
		qr   string
		want string
	}{
		"cipher suite 2":   {engagement(t, 2, ble), "cipher suite 2"},
		"no BLE method":    {engagement(t, 1, []any{[]any{1, 1, map[int]any{}}}), "no BLE"},
		"BLE without UUID": {engagement(t, 1, []any{[]any{2, 1, map[int]any{0: true, 1: false}}}), "no BLE"},
		"wrong scheme":     {"https://example.com", "does not start"},
		"bad base64":       {"mdoc:!!!", "decode QR"},
		"not CBOR":         {"mdoc:" + base64.RawURLEncoding.EncodeToString([]byte{0xff}), "CBOR decoding"},
		"version 2.0":      {"mdoc:" + base64.RawURLEncoding.EncodeToString(mustMarshal(t, map[int]any{0: "2.0", 1: []any{1, keyBytes}})), "version"},
		"oversize":         {"mdoc:" + strings.Repeat("A", MaxMessageBytes*4/3+8), "over"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewReaderSession(tt.qr)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}
	t.Run("upper-case scheme", func(t *testing.T) {
		if _, err := NewReaderSession("MDOC:" + strings.TrimPrefix(holder.QRCode(), "mdoc:")); err != nil {
			t.Errorf("MDOC: scheme: %v", err)
		}
	})
}

func TestReaderAuthNotSupported(t *testing.T) {
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reader, err := NewReaderSession(holder.QRCode(), WithReaderAuth(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Establishment(mDL, map[string][]string{mDLNS: {"age_over_18"}}); err == nil {
		t.Error("Establishment with a readerAuth signer: sent an unsigned request")
	}
}

func TestBuildDeviceResponseRejects(t *testing.T) {
	fx := issueFixture(t, mDL)
	f := establish(t, mDL, map[string][]string{mDLNS: {"age_over_18", "portrait"}})
	st := f.holder.SessionTranscriptBytes()
	ageOnly := [][2]string{{mDLNS, "age_over_18"}}
	other := issueFixture(t, "org.example.other")
	for name, tc := range map[string]struct {
		req          DocRequest
		issuerSigned mdoc.IssuerSigned
		transcript   []byte
		elements     [][2]string
		want         string
	}{
		"an element not requested":  {f.req, fx.issuerSigned, st, [][2]string{{mDLNS, "age_over_18"}, {mDLNS, "family_name"}}, "family_name wasn't requested"},
		"nothing to disclose":       {f.req, fx.issuerSigned, st, nil, "no element"},
		"held none of the elements": {f.req, fx.issuerSigned, st, [][2]string{{mDLNS, "portrait"}}, "holds none"},
		"no session transcript":     {f.req, fx.issuerSigned, nil, ageOnly, "no session transcript"},
		"no request":                {DocRequest{}, fx.issuerSigned, st, ageOnly, "no document request"},
		"an mdoc of another type":   {f.req, other.issuerSigned, st, ageOnly, `the mdoc is a "org.example.other"`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := BuildDeviceResponse(tc.req, tc.issuerSigned, fx.deviceKey, tc.transcript, tc.elements)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("BuildDeviceResponse = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	if _, err := BuildDeviceResponse(f.req, fx.issuerSigned, fx.deviceKey, st, ageOnly); err != nil {
		t.Errorf("a requested element: %v", err)
	}
}

func TestStatusFor(t *testing.T) {
	if s, ok := StatusFor(ErrSessionClosed); ok {
		t.Errorf("StatusFor(ErrSessionClosed) = %d", s)
	}
	if got := StatusMessage(StatusSessionTermination); string(got) != string(mustHex(t, annexDSessionTermination)) {
		t.Errorf("StatusMessage(20) = %x", got)
	}
}

// tamperData flips one bit of a SessionData's ciphertext.
func tamperData(t *testing.T, msg []byte) []byte {
	t.Helper()
	sd, err := decodeSessionData(msg)
	if err != nil {
		t.Fatal(err)
	}
	sd.Data[0] ^= 1
	out, err := encodeSessionData(sd.Data, sd.Status)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// wantStatus checks err maps to status, and passes err through.
func wantStatus(t *testing.T, err error, status uint64) error {
	t.Helper()
	if got, ok := StatusFor(err); !ok || got != status {
		t.Errorf("StatusFor(%v) = %d, %v; want %d", err, got, ok, status)
	}
	return err
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testIACA is an IACA certificate with the countryName Annex B
// requires, and its key.
func testIACA(t testing.TB) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return testCert(t, pkix.Name{CommonName: "Test IACA", Country: []string{"SG"}}, nil, nil, true, nil)
}

// testDocumentSigner is a document signer certificate under ca, in the
// same country, with extended key usages ekus.
func testDocumentSigner(t testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ekus ...asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return testCert(t, pkix.Name{CommonName: "Test Document Signer", Country: []string{"SG"}}, ca, caKey, false, ekus)
}

func testCert(t testing.TB, subject pkix.Name, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, ekus []asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: ekus,
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
