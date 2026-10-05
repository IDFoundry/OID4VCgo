package mdocdcapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

const (
	testOrigin = "https://verifier.example"
	isoNS      = "org.iso.18013.5.1"
)

// fixedIssuerKey resolves every document to one issuer key, or refuses
// it with err.
type fixedIssuerKey struct {
	pub crypto.PublicKey
	err error
}

func (k fixedIssuerKey) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return k.pub, oid4vci.COSEES256, k.err
}

type harness struct {
	f       testmdoc.Fixture
	reader  ReaderKey
	request Request
}

func newHarness(t testing.TB, elements map[string]map[string]bool) harness {
	t.Helper()
	cert, key := testcert.SelfSignedLeaf(t, "mdocdcapi test reader")
	reader := ReaderKey{Signer: key, Chain: []*x509.Certificate{cert}}
	req, err := BuildRequest(RequestParams{Origin: testOrigin, DocType: testmdoc.DocType, Elements: elements, Readers: []ReaderKey{reader}})
	if err != nil {
		t.Fatal(err)
	}
	return harness{f: testmdoc.Issue(t), reader: reader, request: req}
}

func bothNames() map[string]map[string]bool {
	return map[string]map[string]bool{isoNS: {"given_name": false, "family_name": true}}
}

// respond answers data as a document provider would for origin, with
// f's mdoc: the device signs over the Annex C.5 session transcript,
// recomputed here from its definition, and the DeviceResponse is HPKE
// sealed to the request's key (Annex C.4).
func respond(t testing.TB, data RequestData, origin string, f testmdoc.Fixture) string {
	t.Helper()
	params := decodeEncryptionInfo(t, data.EncryptionInfo)
	transcript := annexCTranscript(t, data.EncryptionInfo, origin)
	stBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: transcript})
	if err != nil {
		t.Fatal(err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(f.DeviceKey, cose.ES256, stBytes, testmdoc.DocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	deviceResponse, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: deviceSigned})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := params.RecipientPublicKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ecdhPub, err := pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	pkR, err := hpke.NewDHKEMPublicKey(ecdhPub)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(pkR, hpke.HKDFSHA256(), hpke.AES128GCM(), transcript)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Seal(nil, deviceResponse)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cbor.Marshal([]any{"dcapi", map[string][]byte{"enc": enc, "cipherText": ct}})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeEncryptionInfo(t testing.TB, encryptionInfo string) encryptionParameters {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encryptionInfo)
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		_        struct{} `cbor:",toarray"`
		Protocol string
		Params   encryptionParameters
	}
	if err := cbor.Unmarshal(raw, &info); err != nil {
		t.Fatal(err)
	}
	if info.Protocol != "dcapi" || len(info.Params.Nonce) < 16 {
		t.Fatalf("EncryptionInfo = %+v, want [\"dcapi\", {nonce of 16+ bytes, ...}]", info)
	}
	return info.Params
}

// annexCTranscript is Annex C.5's SessionTranscript, built from its
// definition independently of sessionTranscript.
func annexCTranscript(t testing.TB, encryptionInfo, origin string) []byte {
	t.Helper()
	dcapiInfo, err := cbor.Marshal([]string{encryptionInfo, origin})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(dcapiInfo)
	transcript, err := cbor.Marshal([]any{nil, nil, []any{"dcapi", hash[:]}})
	if err != nil {
		t.Fatal(err)
	}
	return transcript
}

func verify(t *testing.T, h harness, response string, mutate func(*VerifyParams)) (Verified, error) {
	t.Helper()
	p := VerifyParams{Pending: h.request.Pending, Response: response, IssuerKeys: fixedIssuerKey{pub: h.f.IssuerKey.Public()}}
	if mutate != nil {
		mutate(&p)
	}
	return VerifyResponse(context.Background(), p)
}

func TestRoundTrip(t *testing.T) {
	h := newHarness(t, bothNames())
	got, err := verify(t, h, respond(t, h.request.Data, testOrigin, h.f), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.DocType != testmdoc.DocType || got.NameSpaces[isoNS]["given_name"] != "Alice" || got.NameSpaces[isoNS]["family_name"] != "Doe" {
		t.Errorf("Verified = %+v", got)
	}
}

// The response is bound to the origin the browser gave the mdoc and to
// this request's encryption key: answered for another origin, or for
// another request, it doesn't decrypt.
func TestResponseBoundToOriginAndRequest(t *testing.T) {
	h := newHarness(t, bothNames())
	if _, err := verify(t, h, respond(t, h.request.Data, "https://attacker.example", h.f), nil); err == nil {
		t.Error("a response for another origin: accepted")
	}
	other := newHarness(t, bothNames())
	if _, err := verify(t, h, respond(t, other.request.Data, testOrigin, h.f), nil); err == nil {
		t.Error("a response to another request: accepted")
	}
}

func TestVerifyResponseRefuses(t *testing.T) {
	h := newHarness(t, bothNames())
	good := respond(t, h.request.Data, testOrigin, h.f)
	tampered := tamperCipherText(t, good)

	only := newHarness(t, map[string]map[string]bool{isoNS: {"given_name": false}})
	overDisclosed := respond(t, only.request.Data, testOrigin, only.f)

	for name, tc := range map[string]struct {
		h        harness
		response string
		mutate   func(*VerifyParams)
		want     string
	}{
		"tampered ciphertext": {h, tampered, nil, "decrypt"},
		"not base64url":       {h, "!!", nil, "base64url"},
		"untrusted issuer": {h, good, func(p *VerifyParams) {
			p.IssuerKeys = fixedIssuerKey{err: errors.New("not a trusted issuer")}
		}, "not a trusted issuer"},
		"another doc type":    {h, good, func(p *VerifyParams) { p.Pending.DocType = "org.iso.23220.photoid.1" }, "not the requested"},
		"unrequested element": {only, overDisclosed, nil, "family_name, which wasn't requested"},
		"too large":           {h, strings.Repeat("A", MaxResponseBytes+1), nil, "more than"},
		"no issuer keys":      {h, good, func(p *VerifyParams) { p.IssuerKeys = nil }, "IssuerKeys"},
	} {
		if _, err := verify(t, tc.h, tc.response, tc.mutate); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error containing %q", name, err, tc.want)
		}
	}
}

// tamperCipherText flips a bit of response's cipherText.
func tamperCipherText(t *testing.T, response string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		_        struct{} `cbor:",toarray"`
		Protocol string
		Data     encryptedResponseData
	}
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Data.CipherText[0] ^= 1
	out, err := cbor.Marshal([]any{wire.Protocol, wire.Data})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(out)
}

// Each reader's ReaderAuthAll, and the first reader's ReaderAuth on the
// DocRequest, verify under the reader's certificate over ISO/IEC
// 18013-5 §12.5's structures with this request's session transcript —
// what a document provider checks before answering.
func TestReaderAuthentication(t *testing.T) {
	h := newHarness(t, bothNames())
	raw, err := base64.RawURLEncoding.DecodeString(h.request.Data.DeviceRequest)
	if err != nil {
		t.Fatal(err)
	}
	var dr struct {
		Version     string `cbor:"version"`
		DocRequests []struct {
			ItemsRequest cbor.RawMessage `cbor:"itemsRequest"`
			ReaderAuth   cbor.RawMessage `cbor:"readerAuth"`
		} `cbor:"docRequests"`
		ReaderAuthAll []cbor.RawMessage `cbor:"readerAuthAll"`
	}
	if err := cbor.Unmarshal(raw, &dr); err != nil {
		t.Fatal(err)
	}
	if dr.Version != "1.1" || len(dr.DocRequests) != 1 || len(dr.ReaderAuthAll) != 1 {
		t.Fatalf("DeviceRequest = %+v, want version 1.1, one DocRequest and one ReaderAuthAll", dr)
	}
	var items struct {
		DocType    string                     `cbor:"docType"`
		NameSpaces map[string]map[string]bool `cbor:"nameSpaces"`
	}
	var itemsBytes []byte
	var tag cbor.Tag
	if err := cbor.Unmarshal(dr.DocRequests[0].ItemsRequest, &tag); err != nil || tag.Number != 24 {
		t.Fatalf("itemsRequest isn't tag 24: %v", err)
	}
	itemsBytes = tag.Content.([]byte)
	if err := cbor.Unmarshal(itemsBytes, &items); err != nil || items.DocType != testmdoc.DocType || !items.NameSpaces[isoNS]["family_name"] {
		t.Fatalf("ItemsRequest = %+v, %v", items, err)
	}

	transcript := cbor.RawMessage(annexCTranscript(t, h.request.Data.EncryptionInfo, testOrigin))
	detached := func(v any) []byte {
		inner, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out, err := cbor.Marshal(cbor.Tag{Number: 24, Content: inner})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	pub := h.reader.Chain[0].PublicKey
	all := detached([]any{"ReaderAuthenticationAll", transcript, []any{dr.DocRequests[0].ItemsRequest}, nil})
	if _, unprotected, err := cose.VerifyDetached(cose.ES256, pub, dr.ReaderAuthAll[0], all, nil); err != nil || len(unprotected.X5Chain) != 1 {
		t.Errorf("ReaderAuthAll: %v (x5chain %d certificates)", err, len(unprotected.X5Chain))
	}
	single := detached([]any{"ReaderAuthentication", transcript, dr.DocRequests[0].ItemsRequest})
	if _, _, err := cose.VerifyDetached(cose.ES256, pub, dr.DocRequests[0].ReaderAuth, single, nil); err != nil {
		t.Errorf("ReaderAuth: %v", err)
	}
}

// Without readers the request is unsigned, version 1.0 (ISO/IEC 18013-5
// §10.2.2), and still verifies end to end.
func TestUnsignedRequest(t *testing.T) {
	req, err := BuildRequest(RequestParams{Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames()})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(req.Data.DeviceRequest)
	var dr map[string]any
	if err := cbor.Unmarshal(raw, &dr); err != nil {
		t.Fatal(err)
	}
	if dr["version"] != "1.0" || dr["readerAuthAll"] != nil {
		t.Errorf("unsigned DeviceRequest = %v, want version 1.0 without readerAuthAll", dr)
	}
	f := testmdoc.Issue(t)
	h := harness{f: f, request: req}
	if _, err := verify(t, h, respond(t, req.Data, testOrigin, f), nil); err != nil {
		t.Error(err)
	}
}

func TestBuildRequestRefuses(t *testing.T) {
	cert, key := testcert.SelfSignedLeaf(t, "reader")
	_, otherKey := testcert.SelfSignedLeaf(t, "other")
	for name, p := range map[string]RequestParams{
		"origin with a path":      {Origin: testOrigin + "/", DocType: testmdoc.DocType, Elements: bothNames()},
		"origin without scheme":   {Origin: "verifier.example", DocType: testmdoc.DocType, Elements: bothNames()},
		"no doc type":             {Origin: testOrigin, Elements: bothNames()},
		"no elements":             {Origin: testOrigin, DocType: testmdoc.DocType},
		"empty namespace":         {Origin: testOrigin, DocType: testmdoc.DocType, Elements: map[string]map[string]bool{isoNS: {}}},
		"reader key isn't leaf's": {Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Readers: []ReaderKey{{Signer: otherKey, Chain: []*x509.Certificate{cert}}}},
		"reader without chain":    {Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Readers: []ReaderKey{{Signer: key}}},
	} {
		if _, err := BuildRequest(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
