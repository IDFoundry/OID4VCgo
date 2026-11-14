package mdocdcapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
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
	transcript := annexCTranscript(t, data.EncryptionInfo, origin)
	return respondSignedOver(t, data, transcript, transcript, f)
}

// respondSignedOver is respond with the DeviceResponse HPKE sealed under
// sealTranscript and the device signing over signTranscript, where a
// document provider uses one session transcript for both.
func respondSignedOver(t testing.TB, data RequestData, sealTranscript, signTranscript []byte, f testmdoc.Fixture) string {
	t.Helper()
	stBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: signTranscript})
	if err != nil {
		t.Fatal(err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(f.DeviceKey, cose.ES256, stBytes, testmdoc.DocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	return respondWith(t, data, sealTranscript, f, deviceSigned)
}

// respondWith seals a DeviceResponse of f's IssuerSigned and
// deviceSigned under transcript, as respond does.
func respondWith(t testing.TB, data RequestData, transcript []byte, f testmdoc.Fixture, deviceSigned mdoc.DeviceSigned) string {
	t.Helper()
	deviceResponse, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: deviceSigned})
	if err != nil {
		t.Fatal(err)
	}
	enc, ct := seal(t, data, transcript, deviceResponse)
	return encodeResponse(t, []any{"dcapi", map[string][]byte{"enc": enc, "cipherText": ct}})
}

// seal HPKE seals plaintext to data's recipient key with transcript as
// info (Annex C.4), returning the encapsulated key and the ciphertext.
func seal(t testing.TB, data RequestData, transcript, plaintext []byte) (enc, ct []byte) {
	t.Helper()
	params := decodeEncryptionInfo(t, data.EncryptionInfo)
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
	ct, err = sender.Seal(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return enc, ct
}

// encodeResponse is v, CBOR encoded and base64url, as data.response is.
func encodeResponse(t testing.TB, v any) string {
	t.Helper()
	raw, err := cbor.Marshal(v)
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
	p := VerifyParams{Pending: h.request.Pending, Response: response, IssuerKeys: fixedIssuerKey{pub: h.f.IssuerKey.Public()}, Assurance: verifier.AssuranceDevelopment}
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

// A request is answerable until its Pending's ExpiresAt, DefaultLifetime
// after it's built, and a Pending without one is refused.
func TestVerifyResponseRefusesAnExpiredRequest(t *testing.T) {
	h := newHarness(t, bothNames())
	if want := time.Now().Add(DefaultLifetime); h.request.Pending.ExpiresAt.After(want) || h.request.Pending.ExpiresAt.Before(want.Add(-time.Minute)) {
		t.Errorf("ExpiresAt = %v, want about %v", h.request.Pending.ExpiresAt, want)
	}
	response := respond(t, h.request.Data, testOrigin, h.f)
	_, err := verify(t, h, response, func(p *VerifyParams) {
		p.Now = func() time.Time { return h.request.Pending.ExpiresAt }
	})
	if !errors.Is(err, ErrRequestExpired) {
		t.Errorf("at ExpiresAt: %v, want ErrRequestExpired", err)
	}
	if _, err := verify(t, h, response, func(p *VerifyParams) { p.Pending.ExpiresAt = time.Time{} }); err == nil {
		t.Error("a Pending without ExpiresAt: verified")
	}
}

// A requested element the document doesn't disclose is reported as
// Missing, so a caller doesn't take its absence for an answer.
func TestRoundTrip_Missing(t *testing.T) {
	h := newHarness(t, bothNames())
	if got, err := verify(t, h, respond(t, h.request.Data, testOrigin, h.f), nil); err != nil || got.Missing != nil {
		t.Fatalf("all disclosed: Missing = %v, %v; want none", got.Missing, err)
	}
	got, err := verify(t, h, respond(t, h.request.Data, testOrigin, h.f), func(p *VerifyParams) {
		elements := map[string]map[string]bool{}
		for ns, els := range p.Pending.Elements {
			elements[ns] = map[string]bool{"age_over_18": false}
			for el, retain := range els {
				elements[ns][el] = retain
			}
		}
		p.Pending.Elements = elements
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"age_over_18"}; len(got.Missing) != 1 || !slices.Equal(got.Missing[isoNS], want) {
		t.Errorf("Missing = %v, want %s: %v", got.Missing, isoNS, want)
	}
	// Credential carries it as Withheld.
	if withheld := got.Credential().Withheld; len(withheld) != 1 || !slices.Equal(withheld[isoNS], got.Missing[isoNS]) {
		t.Errorf("Credential().Withheld = %v, want %v", withheld, got.Missing)
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
		"issuer not authorized for the doctype": {h, good, func(p *VerifyParams) {
			p.IssuerAuthorized = func(_ context.Context, a verifier.IssuerAuthorization) error {
				if a.Format != "mso_mdoc" || a.Type != testmdoc.DocType || !slices.Equal(a.RequestedTypes, []string{testmdoc.DocType}) {
					t.Errorf("IssuerAuthorization = %+v", a)
				}
				return errors.New("not authorized for " + a.Type)
			}
		}, "issuer authorization: not authorized for"},
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
		"origin with a path":      {Origin: testOrigin + "/app", DocType: testmdoc.DocType, Elements: bothNames()},
		"a non-loopback http":     {Origin: "http://verifier.example", DocType: testmdoc.DocType, Elements: bothNames()},
		"an unencodable origin":   {Origin: "https://bücher.example", DocType: testmdoc.DocType, Elements: bothNames()},
		"a malformed Origins":     {Origin: testOrigin, Origins: []string{"verifier.example"}, DocType: testmdoc.DocType, Elements: bothNames()},
		"origin without scheme":   {Origin: "verifier.example", DocType: testmdoc.DocType, Elements: bothNames()},
		"no doc type":             {Origin: testOrigin, Elements: bothNames()},
		"no elements":             {Origin: testOrigin, DocType: testmdoc.DocType},
		"empty namespace":         {Origin: testOrigin, DocType: testmdoc.DocType, Elements: map[string]map[string]bool{isoNS: {}}},
		"reader key isn't leaf's": {Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Readers: []ReaderKey{{Signer: otherKey, Chain: []*x509.Certificate{cert}}}},
		"reader without chain":    {Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Readers: []ReaderKey{{Signer: key}}},
		"a negative lifetime":     {Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Lifetime: -time.Second},
		"too long a lifetime":     {Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Lifetime: MaxLifetime + time.Second},
	} {
		if _, err := BuildRequest(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// verifyBoth is verify's error, and VerifyResponseDocuments' for the
// same parameters: the two share their decryption and document checks.
func verifyBoth(t *testing.T, h harness, response string) (single, documents error) {
	t.Helper()
	_, single = verify(t, h, response, nil)
	_, documents = VerifyResponseDocuments(context.Background(), VerifyParams{
		Pending: h.request.Pending, Response: response, IssuerKeys: fixedIssuerKey{pub: h.f.IssuerKey.Public()},
		Assurance: verifier.AssuranceDevelopment,
	})
	return single, documents
}

// A response sealed under this request's session transcript decrypts,
// but a device signature over another one, for another origin or for
// another request's EncryptionInfo, doesn't bind the document to this
// request: it's refused.
func TestDeviceSignatureBoundToSessionTranscript(t *testing.T) {
	h := newHarness(t, bothNames())
	other := newHarness(t, bothNames())
	sealed := annexCTranscript(t, h.request.Data.EncryptionInfo, testOrigin)
	for name, signed := range map[string][]byte{
		"another origin":  annexCTranscript(t, h.request.Data.EncryptionInfo, "https://attacker.example"),
		"another request": annexCTranscript(t, other.request.Data.EncryptionInfo, testOrigin),
	} {
		single, documents := verifyBoth(t, h, respondSignedOver(t, h.request.Data, sealed, signed, h.f))
		for fn, err := range map[string]error{"VerifyResponse": single, "VerifyResponseDocuments": documents} {
			if err == nil || !strings.Contains(err.Error(), "verify DeviceSignature") {
				t.Errorf("%s: %s: %v, want a DeviceSignature error", name, fn, err)
			}
		}
	}
}

// No reader key is exchanged over the Digital Credentials API, so a
// document authenticated by a deviceMac (ISO/IEC 18013-5 §12.4.5) isn't
// bound to the request, and is refused.
func TestVerifyResponseRefusesDeviceMac(t *testing.T) {
	h := newHarness(t, bothNames())
	transcript := annexCTranscript(t, h.request.Data.EncryptionInfo, testOrigin)
	stBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: transcript})
	if err != nil {
		t.Fatal(err)
	}
	deviceSigned, err := mdoc.ComputeDeviceMACFromSharedSecret(make([]byte, 32), stBytes, testmdoc.DocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	single, documents := verifyBoth(t, h, respondWith(t, h.request.Data, transcript, h.f, deviceSigned))
	for fn, err := range map[string]error{"VerifyResponse": single, "VerifyResponseDocuments": documents} {
		if err == nil || !strings.Contains(err.Error(), "must be authenticated by a device signature") {
			t.Errorf("%s: %v, want a refusal of the deviceMac", fn, err)
		}
	}
}

// An EncryptedResponse (Annex C.3) that isn't ["dcapi", {"enc": bstr,
// "cipherText": bstr}], with a whole encapsulated key and a ciphertext,
// is refused.
func TestVerifyResponseRefusesMalformedEncryptedResponse(t *testing.T) {
	h := newHarness(t, bothNames())
	enc, ct := seal(t, h.request.Data, annexCTranscript(t, h.request.Data.EncryptionInfo, testOrigin), []byte("not reached"))
	for name, tc := range map[string]struct {
		wire any
		want string
	}{
		"another protocol":       {[]any{"openid4vp", map[string][]byte{"enc": enc, "cipherText": ct}}, `protocol "openid4vp"`},
		"an empty protocol":      {[]any{"", map[string][]byte{"enc": enc, "cipherText": ct}}, `protocol ""`},
		"no enc":                 {[]any{"dcapi", map[string][]byte{"cipherText": ct}}, "HPKE"},
		"no cipherText":          {[]any{"dcapi", map[string][]byte{"enc": enc}}, "decrypt the response"},
		"an empty cipherText":    {[]any{"dcapi", map[string][]byte{"enc": enc, "cipherText": {}}}, "decrypt the response"},
		"a short enc":            {[]any{"dcapi", map[string][]byte{"enc": enc[:len(enc)-1], "cipherText": ct}}, "HPKE"},
		"a long enc":             {[]any{"dcapi", map[string][]byte{"enc": append(slices.Clone(enc), 0), "cipherText": ct}}, "HPKE"},
		"a compressed enc":       {[]any{"dcapi", map[string][]byte{"enc": append([]byte{2 + enc[64]&1}, enc[1:33]...), "cipherText": ct}}, "HPKE"},
		"a protocol number":      {[]any{1, map[string][]byte{"enc": enc, "cipherText": ct}}, "decode EncryptedResponse"},
		"enc as text":            {[]any{"dcapi", map[string]any{"enc": string(enc), "cipherText": ct}}, "decode EncryptedResponse"},
		"cipherText as an array": {[]any{"dcapi", map[string]any{"enc": enc, "cipherText": []any{ct}}}, "decode EncryptedResponse"},
		"data as an array":       {[]any{"dcapi", []any{enc, ct}}, "decode EncryptedResponse"},
		"a map":                  {map[string]any{"dcapi": map[string][]byte{"enc": enc, "cipherText": ct}}, "decode EncryptedResponse"},
		"a third element":        {[]any{"dcapi", map[string][]byte{"enc": enc, "cipherText": ct}, nil}, "decode EncryptedResponse"},
		"no data":                {[]any{"dcapi"}, "decode EncryptedResponse"},
	} {
		if _, err := verify(t, h, encodeResponse(t, tc.wire), nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error containing %q", name, err, tc.want)
		}
	}
}

// legacyReaderAuthentication(All)Bytes are the detached reader
// authentication payloads as this package built them before the
// construction moved to internal/readerauth: each structure encoded with
// encMode and wrapped with wrapTag24. The shared builder must keep them.
func legacyReaderAuthenticationBytes(t *testing.T, transcript, itemsRequestBytes []byte) []byte {
	t.Helper()
	b, err := wrapTag24([]any{"ReaderAuthentication", cbor.RawMessage(transcript), cbor.RawMessage(itemsRequestBytes)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func legacyReaderAuthenticationAllBytes(t *testing.T, transcript []byte, itemsRequestBytes [][]byte, info []byte) []byte {
	t.Helper()
	items := make([]any, len(itemsRequestBytes))
	for i, b := range itemsRequestBytes {
		items[i] = cbor.RawMessage(b)
	}
	var infoItem any
	if info != nil {
		infoItem = cbor.RawMessage(info)
	}
	b, err := wrapTag24([]any{"ReaderAuthenticationAll", cbor.RawMessage(transcript), items, infoItem})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// BuildRequest's signatures are over the same bytes as before the
// shared builders: every reader's ReaderAuthAll over the whole request,
// and each DocRequest's ReaderAuth by the first reader only.
func TestBuildRequestSignsUnchangedAuthenticationBytes(t *testing.T) {
	ca, caKey := testcert.CA(t, "mdocdcapi test reader CA")
	certA, keyA := testcert.Leaf(t, "mdocdcapi test reader A", ca, caKey)
	certB, keyB := testcert.Leaf(t, "mdocdcapi test reader B", ca, caKey)
	req, err := BuildRequest(RequestParams{
		Origin: testOrigin,
		Documents: []DocumentRequest{
			{DocType: testmdoc.DocType, Elements: bothNames()},
			{DocType: "org.example.second", Elements: map[string]map[string]bool{"org.example": {"x": false}}},
		},
		Readers: []ReaderKey{{Signer: keyA, Chain: []*x509.Certificate{certA, ca}}, {Signer: keyB, Chain: []*x509.Certificate{certB, ca}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	transcript := annexCTranscript(t, req.Data.EncryptionInfo, testOrigin)
	raw, err := base64.RawURLEncoding.DecodeString(req.Data.DeviceRequest)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		DocRequests []struct {
			ItemsRequest cbor.RawMessage `cbor:"itemsRequest"`
			ReaderAuth   cbor.RawMessage `cbor:"readerAuth"`
		} `cbor:"docRequests"`
		ReaderAuthAll []cbor.RawMessage `cbor:"readerAuthAll"`
	}
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.DocRequests) != 2 || len(wire.ReaderAuthAll) != 2 {
		t.Fatalf("got %d DocRequests and %d ReaderAuthAll, want 2 and 2", len(wire.DocRequests), len(wire.ReaderAuthAll))
	}
	items := [][]byte{wire.DocRequests[0].ItemsRequest, wire.DocRequests[1].ItemsRequest}

	all := legacyReaderAuthenticationAllBytes(t, transcript, items, nil)
	if shared, err := readerauth.AuthenticationAllBytes(transcript, items, nil); err != nil || !bytes.Equal(shared, all) {
		t.Errorf("AuthenticationAllBytes = %x, %v; want the legacy %x", shared, err, all)
	}
	for i, leaf := range []*x509.Certificate{certA, certB} {
		if err := readerauth.VerifySignature(wire.ReaderAuthAll[i], all, leaf); err != nil {
			t.Errorf("ReaderAuthAll[%d] over the legacy bytes: %v", i, err)
		}
	}
	for i, d := range wire.DocRequests {
		one := legacyReaderAuthenticationBytes(t, transcript, d.ItemsRequest)
		if shared, err := readerauth.AuthenticationBytes(transcript, d.ItemsRequest); err != nil || !bytes.Equal(shared, one) {
			t.Errorf("AuthenticationBytes[%d] = %x, %v; want the legacy %x", i, shared, err, one)
		}
		if err := readerauth.VerifySignature(d.ReaderAuth, one, certA); err != nil {
			t.Errorf("DocRequest %d ReaderAuth by the first reader: %v", i, err)
		}
		if err := readerauth.VerifySignature(d.ReaderAuth, one, certB); err == nil {
			t.Errorf("DocRequest %d ReaderAuth verifies by the second reader too", i)
		}
	}
	// A present DeviceRequestInfo is inserted as received, as before.
	info := []byte{0xd8, 0x18, 0x41, 0xa0}
	if shared, err := readerauth.AuthenticationAllBytes(transcript, items, info); err != nil || !bytes.Equal(shared, legacyReaderAuthenticationAllBytes(t, transcript, items, info)) {
		t.Errorf("AuthenticationAllBytes with information differs from the legacy construction: %v", err)
	}
}
