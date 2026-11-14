package proximity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/readerauth"
)

// testSigner is a reader key, its chain, and the pool of its CA.
type testSigner struct {
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
	roots *x509.CertPool
}

func newTestSigner(t testing.TB) testSigner {
	t.Helper()
	key, chain, roots := testReader(t, ReaderAuthenticationEKU)
	return testSigner{key, chain, roots}
}

// testTranscriptBytes is an arbitrary SessionTranscriptBytes for
// building and verifying test requests outside a session.
func testTranscriptBytes(t testing.TB, label string) []byte {
	t.Helper()
	transcript := mustCBOR(t, []any{nil, nil, []any{label, []byte{1}}})
	return mustCBOR(t, cbor.Tag{Number: tag24, Content: []byte(transcript)})
}

// tagged is #6.24(bstr .cbor raw).
func tagged(t testing.TB, raw []byte) cbor.RawMessage {
	t.Helper()
	return mustCBOR(t, cbor.Tag{Number: tag24, Content: raw})
}

// testDoc is one DocRequest of a test request: its docType, and the
// reader signing it on its own, if any.
type testDoc struct {
	docType string
	signer  *testSigner
}

// testRequest describes a DeviceRequest to build: its documents, the
// readers signing it as a whole, in order, and its deviceRequestInfo
// as encoded (#6.24(bstr)), or nil for none.
type testRequest struct {
	docs    []testDoc
	all     []testSigner
	info    cbor.RawMessage
	version string
}

// build encodes r for the session whose SessionTranscriptBytes is
// transcriptBytes. The signed structures are encoded here with the
// generic CBOR encoder, not with internal/readerauth's builders.
func (r testRequest) build(t testing.TB, transcriptBytes []byte) []byte {
	t.Helper()
	transcript, err := unwrapTag24(transcriptBytes)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(s testSigner, authentication []any) cbor.RawMessage {
		detached := tagged(t, mustCBOR(t, authentication))
		sig, err := readerauth.Sign(s.key, s.chain, detached)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	var docRequests []any
	var items []any
	for _, d := range r.docs {
		itemsBytes := tagged(t, mustCBOR(t, map[string]any{
			"docType": d.docType, "nameSpaces": map[string]map[string]bool{mDLNS: {"age_over_18": false}},
		}))
		doc := map[string]any{"itemsRequest": itemsBytes}
		if d.signer != nil {
			doc["readerAuth"] = sign(*d.signer, []any{"ReaderAuthentication", cbor.RawMessage(transcript), itemsBytes})
		}
		docRequests = append(docRequests, doc)
		items = append(items, itemsBytes)
	}
	version := r.version
	if version == "" {
		version = "1.1"
	}
	req := map[string]any{"version": version, "docRequests": docRequests}
	var info any
	if r.info != nil {
		req["deviceRequestInfo"] = r.info
		info = r.info
	}
	if len(r.all) > 0 {
		var all []any
		for _, s := range r.all {
			all = append(all, sign(s, []any{"ReaderAuthenticationAll", cbor.RawMessage(transcript), items, info}))
		}
		req["readerAuthAll"] = all
	}
	return mustCBOR(t, req)
}

// testDocs is n documents of distinct types, signed by signer if not nil.
func testDocs(n int, signer *testSigner) []testDoc {
	out := make([]testDoc, n)
	for i := range out {
		out[i] = testDoc{docType: "org.example.doc" + string(rune('a'+i)), signer: signer}
	}
	return out
}

// sampleInfo is a deviceRequestInfo with two use cases, purpose hints
// and an unknown extension, keys in a noncanonical order.
func sampleInfo(t testing.TB) cbor.RawMessage {
	t.Helper()
	// {"useCases": [{"mandatory": true, "documentSets": [[0], [1, 0]],
	//   "purposeHints": {"org.example": 3, "org.example.neg": -2}},
	//   {"mandatory": false, "documentSets": []}], "zzExtension": "x"}
	raw := []byte{0xa2}
	raw = append(raw, mustCBOR(t, "zzExtension")...)
	raw = append(raw, mustCBOR(t, "x")...)
	raw = append(raw, mustCBOR(t, "useCases")...)
	raw = append(raw, 0x82, 0xa3)
	raw = append(raw, mustCBOR(t, "mandatory")...)
	raw = append(raw, 0xf5)
	raw = append(raw, mustCBOR(t, "documentSets")...)
	raw = append(raw, mustCBOR(t, [][]int{{0}, {1, 0}})...)
	raw = append(raw, mustCBOR(t, "purposeHints")...)
	raw = append(raw, 0xa2)
	raw = append(raw, mustCBOR(t, "org.example")...)
	raw = append(raw, 0x03)
	raw = append(raw, mustCBOR(t, "org.example.neg")...)
	raw = append(raw, 0x21)
	raw = append(raw, 0xa2)
	raw = append(raw, mustCBOR(t, "mandatory")...)
	raw = append(raw, 0xf4)
	raw = append(raw, mustCBOR(t, "documentSets")...)
	raw = append(raw, 0x80)
	return tagged(t, raw)
}

func mustDecode(t *testing.T, b []byte) *DeviceRequest {
	t.Helper()
	req, err := DecodeDeviceRequest(b)
	if err != nil {
		t.Fatalf("DecodeDeviceRequest: %v", err)
	}
	return req
}

// DecodeDeviceRequest copies what it decodes: changing the input buffer,
// or anything an accessor returned, changes neither the accessors'
// next results nor what VerifyDeviceRequest checks.
func TestDeviceRequest_OwnsItsData(t *testing.T) {
	signer := newTestSigner(t)
	transcript := testTranscriptBytes(t, "owned")
	b := testRequest{docs: testDocs(2, &signer), all: []testSigner{signer}, info: sampleInfo(t)}.build(t, transcript)
	original := bytes.Clone(b)
	req := mustDecode(t, b)
	trust := ReaderTrust{Roots: signer.roots}
	if got := VerifyDeviceRequest(req, transcript, trust); got.Reader.Status != ReaderTrusted || !got.RequestInfoSigned {
		t.Fatalf("before mutation: %+v", got)
	}
	wantDocs, wantInfo := req.DocRequests(), req.RequestInfo()

	// Scribble over the input and everything returned.
	for i := range b {
		b[i] = 0
	}
	ds := req.DocRequests()
	for i := range ds {
		ds[i].DocType = "changed"
		ds[i].Elements[0] = [2]string{"x", "y"}
		for k := range ds[i].IntentToRetain {
			ds[i].IntentToRetain[k] = true
		}
		ds[i].ItemsRequestBytes[len(ds[i].ItemsRequestBytes)-1] ^= 1
		ds[i].ReaderAuth[len(ds[i].ReaderAuth)-1] ^= 1
	}
	info := req.RequestInfo()
	info.Signed = true
	info.UseCases[0].Mandatory = false
	info.UseCases[0].DocumentSets[1][0] = 7
	info.UseCases[0].PurposeHints["org.example"] = 99
	info.UseCases[0].PurposeHints["added"] = 1
	info.UseCases = append(info.UseCases, UseCase{})

	if got := req.DocRequests(); !equalDocRequests(got, wantDocs) {
		t.Errorf("DocRequests changed: %+v", got)
	}
	if got := req.RequestInfo(); !equalRequestInfo(got, wantInfo) || got.Signed {
		t.Errorf("RequestInfo changed: %+v", got)
	}
	if got := VerifyDeviceRequest(req, transcript, trust); got.Reader.Status != ReaderTrusted || !got.RequestInfoSigned {
		t.Errorf("after mutation: %+v, want the original request still trusted and signed", got)
	}
	if again := mustDecode(t, original); !equalDocRequests(again.DocRequests(), wantDocs) {
		t.Error("a fresh decode of the original bytes differs")
	}
}

// A nil or zero DeviceRequest has no data and never authenticates, even
// as an unsigned request.
func TestDeviceRequest_ZeroValue(t *testing.T) {
	transcript := testTranscriptBytes(t, "zero")
	for name, req := range map[string]*DeviceRequest{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if req.DocRequests() != nil || req.RequestInfo() != nil {
				t.Error("accessors return data")
			}
			got := VerifyDeviceRequest(req, transcript, ReaderTrust{})
			if got.Reader.Status != ReaderInvalid || got.Reader.Err == nil || got.RequestInfoSigned || got.Reader.Chain != nil {
				t.Errorf("VerifyDeviceRequest = %+v, want invalid", got)
			}
		})
	}
}

// Each verification is its own: roots and times from one call don't
// carry into the next, and the request isn't changed by any.
func TestVerifyDeviceRequest_Repeatable(t *testing.T) {
	signer := newTestSigner(t)
	other := newTestSigner(t)
	transcript := testTranscriptBytes(t, "repeat")
	req := mustDecode(t, testRequest{docs: testDocs(2, nil), all: []testSigner{signer}, info: sampleInfo(t)}.build(t, transcript))
	for i, tc := range []struct {
		trust ReaderTrust
		want  ReaderStatus
	}{
		{ReaderTrust{Roots: signer.roots}, ReaderTrusted},
		{ReaderTrust{Roots: other.roots}, ReaderUntrusted},
		{ReaderTrust{Roots: signer.roots}, ReaderTrusted},
		{ReaderTrust{Roots: signer.roots, Now: time.Now().Add(48 * time.Hour)}, ReaderUntrusted},
		{ReaderTrust{}, ReaderUntrusted},
		{ReaderTrust{Roots: signer.roots, Now: time.Now()}, ReaderTrusted},
	} {
		got := VerifyDeviceRequest(req, transcript, tc.trust)
		if got.Reader.Status != tc.want || !got.RequestInfoSigned {
			t.Errorf("call %d: %v (%v), signed %v; want %v, signed", i, got.Reader.Status, got.Reader.Err, got.RequestInfoSigned, tc.want)
		}
		if req.RequestInfo().Signed {
			t.Errorf("call %d: verification set the request's own Signed", i)
		}
	}
}

// The legacy parser keeps its acceptance: a request whose
// request-level fields DecodeDeviceRequest refuses still parses to its
// documents, and both agree on the documents of one both accept.
func TestParseDeviceRequest_LegacyAcceptanceKept(t *testing.T) {
	transcript := testTranscriptBytes(t, "legacy")
	good := testRequest{docs: testDocs(2, nil), info: sampleInfo(t)}.build(t, transcript)
	legacy, err := ParseDeviceRequest(good)
	if err != nil {
		t.Fatal(err)
	}
	if !equalDocRequests(legacy, mustDecode(t, good).DocRequests()) {
		t.Error("the parsers disagree on the documents")
	}
	for name, edit := range map[string]func(map[string]cbor.RawMessage){
		"null readerAuthAll":     func(m map[string]cbor.RawMessage) { m["readerAuthAll"] = cbor.RawMessage{0xf6} },
		"empty readerAuthAll":    func(m map[string]cbor.RawMessage) { m["readerAuthAll"] = cbor.RawMessage{0x80} },
		"null deviceRequestInfo": func(m map[string]cbor.RawMessage) { m["deviceRequestInfo"] = cbor.RawMessage{0xf6} },
		"untagged information":   func(m map[string]cbor.RawMessage) { m["deviceRequestInfo"] = cbor.RawMessage{0xa0} },
		"index past the documents": func(m map[string]cbor.RawMessage) {
			m["deviceRequestInfo"] = infoOf(t, map[string]any{"useCases": []any{map[string]any{"mandatory": true, "documentSets": [][]int{{2}}}}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := editRequest(t, good, edit)
			if _, err := ParseDeviceRequest(b); err != nil {
				t.Errorf("ParseDeviceRequest refuses what it accepted before: %v", err)
			}
			if _, err := DecodeDeviceRequest(b); !errors.Is(err, ErrCBORValidation) {
				t.Errorf("DecodeDeviceRequest = %v, want a validation error", err)
			}
		})
	}
}

// editRequest decodes b, a DeviceRequest, edits its top-level map, and
// encodes it again.
func editRequest(t *testing.T, b []byte, edit func(map[string]cbor.RawMessage)) []byte {
	t.Helper()
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	return mustCBOR(t, m)
}

func equalDocRequests(a, b []DocRequest) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.DocType != y.DocType || len(x.Elements) != len(y.Elements) || len(x.IntentToRetain) != len(y.IntentToRetain) ||
			!bytes.Equal(x.ItemsRequestBytes, y.ItemsRequestBytes) || !bytes.Equal(x.ReaderAuth, y.ReaderAuth) {
			return false
		}
		for j := range x.Elements {
			if x.Elements[j] != y.Elements[j] || x.IntentToRetain[x.Elements[j]] != y.IntentToRetain[x.Elements[j]] {
				return false
			}
		}
	}
	return true
}

func equalRequestInfo(a, b *RequestInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Signed != b.Signed || len(a.UseCases) != len(b.UseCases) {
		return false
	}
	for i := range a.UseCases {
		x, y := a.UseCases[i], b.UseCases[i]
		if x.Mandatory != y.Mandatory || len(x.DocumentSets) != len(y.DocumentSets) || len(x.PurposeHints) != len(y.PurposeHints) {
			return false
		}
		for j := range x.DocumentSets {
			if len(x.DocumentSets[j]) != len(y.DocumentSets[j]) {
				return false
			}
			for k := range x.DocumentSets[j] {
				if x.DocumentSets[j][k] != y.DocumentSets[j][k] {
					return false
				}
			}
		}
		for k, v := range x.PurposeHints {
			if w, ok := y.PurposeHints[k]; !ok || w != v {
				return false
			}
		}
	}
	return true
}

// infoOf is v encoded as a deviceRequestInfo, #6.24(bstr .cbor v).
func infoOf(t testing.TB, v any) cbor.RawMessage {
	t.Helper()
	return tagged(t, mustCBOR(t, v))
}
