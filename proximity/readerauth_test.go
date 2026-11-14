package proximity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// testReader is a reader key whose certificate, from its own CA, has
// the extended key usages ekus, and the pool of that CA.
func testReader(t testing.TB, ekus ...asn1.ObjectIdentifier) (*ecdsa.PrivateKey, []*x509.Certificate, *x509.CertPool) {
	t.Helper()
	return testReaderOn(t, elliptic.P256(), ekus...)
}

// testReaderOn is testReader with a reader key on curve.
func testReaderOn(t testing.TB, curve elliptic.Curve, ekus ...asn1.ObjectIdentifier) (*ecdsa.PrivateKey, []*x509.Certificate, *x509.CertPool) {
	t.Helper()
	ca, caKey := testcert.CA(t, "proximity test reader CA")
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "proximity test reader"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return key, []*x509.Certificate{cert, ca}, roots
}

var ageOver18 = map[string][]string{mDLNS: {"age_over_18"}}

// A signed request verifies at the holder by the reader's certificate:
// trusted under its CA with the reader authentication EKU required, and
// untrusted, though signed, otherwise.
func TestReaderAuth(t *testing.T) {
	key, chain, roots := testReader(t, ReaderAuthenticationEKU)
	_, _, otherRoots := testReader(t, ReaderAuthenticationEKU)
	noEKUKey, noEKUChain, noEKURoots := testReader(t)

	for name, tc := range map[string]struct {
		opts  []ReaderOption
		trust ReaderTrust
		want  ReaderStatus
	}{
		"trusted": {
			[]ReaderOption{WithReaderAuth(key, chain)},
			ReaderTrust{Roots: roots, LeafPolicy: RequireReaderAuthenticationEKU},
			ReaderTrusted,
		},
		"unsigned": {
			nil,
			ReaderTrust{Roots: roots},
			ReaderUnauthenticated,
		},
		"another CA": {
			[]ReaderOption{WithReaderAuth(key, chain)},
			ReaderTrust{Roots: otherRoots},
			ReaderUntrusted,
		},
		"no roots": {
			[]ReaderOption{WithReaderAuth(key, chain)},
			ReaderTrust{},
			ReaderUntrusted,
		},
		"no reader authentication EKU": {
			[]ReaderOption{WithReaderAuth(noEKUKey, noEKUChain)},
			ReaderTrust{Roots: noEKURoots, LeafPolicy: RequireReaderAuthenticationEKU},
			ReaderUntrusted,
		},
		"no EKU, no policy": {
			[]ReaderOption{WithReaderAuth(noEKUKey, noEKUChain)},
			ReaderTrust{Roots: noEKURoots},
			ReaderTrusted,
		},
		"expired": {
			[]ReaderOption{WithReaderAuth(key, chain)},
			ReaderTrust{Roots: roots, Now: time.Now().Add(48 * time.Hour)},
			ReaderUntrusted,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := establishReader(t, mDL, ageOver18, tc.opts...)
			got := f.holder.VerifyReaderAuth(f.req, tc.trust)
			if got.Status != tc.want {
				t.Fatalf("Status = %v (%v), want %v", got.Status, got.Err, tc.want)
			}
			if (got.Err == nil) != (tc.want == ReaderTrusted) {
				t.Errorf("Err = %v for %v", got.Err, got.Status)
			}
			signed := tc.opts != nil
			if signed != (len(got.Chain) > 0) {
				t.Fatalf("Chain = %d certificates, signed %v", len(got.Chain), signed)
			}
			if signed && got.Chain[0].Subject.CommonName != "proximity test reader" {
				t.Errorf("Chain[0] = %s", got.Chain[0].Subject)
			}
		})
	}
}

// A readerAuth proves nothing outside its own session: taken into
// another session, or over altered ItemsRequestBytes, its signature
// doesn't verify, and a malformed one is invalid too.
func TestReaderAuthInvalid(t *testing.T) {
	key, chain, roots := testReader(t, ReaderAuthenticationEKU)
	trust := ReaderTrust{Roots: roots}
	f := establishReader(t, mDL, ageOver18, WithReaderAuth(key, chain))
	other := establishReader(t, mDL, ageOver18, WithReaderAuth(key, chain))

	t.Run("another session", func(t *testing.T) {
		if got := other.holder.VerifyReaderAuth(f.req, trust); got.Status != ReaderInvalid {
			t.Errorf("Status = %v, want invalid", got.Status)
		}
	})
	t.Run("altered request", func(t *testing.T) {
		req := f.req
		items, err := unwrapTag24(f.req.ItemsRequestBytes)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := cbor.Unmarshal(items, &m); err != nil {
			t.Fatal(err)
		}
		m["docType"] = "org.example.other"
		altered, _ := encMode.Marshal(m)
		if req.ItemsRequestBytes, err = wrapTag24(altered); err != nil {
			t.Fatal(err)
		}
		if got := f.holder.VerifyReaderAuth(req, trust); got.Status != ReaderInvalid {
			t.Errorf("Status = %v, want invalid", got.Status)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		req := f.req
		req.ReaderAuth = []byte{0x84, 0x40}
		if got := f.holder.VerifyReaderAuth(req, trust); got.Status != ReaderInvalid || got.Chain != nil {
			t.Errorf("Status = %v, Chain %d", got.Status, len(got.Chain))
		}
	})
	t.Run("before establishment", func(t *testing.T) {
		if got := VerifyReaderAuth(f.req, nil, trust); got.Status != ReaderInvalid {
			t.Errorf("Status = %v, want invalid", got.Status)
		}
	})
}

// WithReaderAuth needs a chain whose leaf certifies its key.
func TestWithReaderAuthRejects(t *testing.T) {
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, chain, _ := testReader(t, ReaderAuthenticationEKU)
	otherKey, _, _ := testReader(t, ReaderAuthenticationEKU)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	for name, opt := range map[string]ReaderOption{
		"no chain":        WithReaderAuth(key, nil),
		"another key":     WithReaderAuth(otherKey, chain),
		"no signer":       WithReaderAuth(nil, chain),
		"unsupported key": WithReaderAuth(p224, []*x509.Certificate{testcert.SelfSigned(t, "p224", &p224.PublicKey, p224)}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReaderSession(holder.QRCode(), devReader(opt)...); err == nil {
				t.Error("NewReaderSession accepted it")
			}
		})
	}
}

// Annex D's readerAuth verifies over its own SessionTranscript and
// ItemsRequestBytes, by the certificate it carries, trusted when that
// certificate is a trust anchor and the time is inside its validity.
func TestAnnexDReaderAuth(t *testing.T) {
	reqs, err := ParseDeviceRequest(mustHex(t, annexDDeviceRequest))
	if err != nil {
		t.Fatal(err)
	}
	transcript := mustHex(t, annexDSessionTranscriptBytes)
	untrusted := VerifyReaderAuth(reqs[0], transcript, ReaderTrust{})
	if untrusted.Status != ReaderUntrusted {
		t.Fatalf("Status = %v (%v), want untrusted: the signature should verify", untrusted.Status, untrusted.Err)
	}
	leaf := untrusted.Chain[0]
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	now := leaf.NotBefore.Add(24 * time.Hour)
	if got := VerifyReaderAuth(reqs[0], transcript, ReaderTrust{Roots: roots, Now: now}); got.Status != ReaderTrusted {
		t.Errorf("Status = %v (%v), want trusted", got.Status, got.Err)
	}
	if got := VerifyReaderAuth(reqs[0], transcript[:len(transcript)-1], ReaderTrust{Roots: roots, Now: now}); got.Status != ReaderInvalid {
		t.Errorf("truncated transcript: Status = %v, want invalid", got.Status)
	}
}

// A DeviceRequest that is well-formed CBOR but not a DeviceRequest is a
// validation error, answered with an encrypted DeviceResponse of status
// 12; one that isn't CBOR is a decoding error, status 11.
func TestParseDeviceRequestErrors(t *testing.T) {
	enc := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	items := func(v any) cbor.RawMessage {
		b, err := wrapTag24(enc(v))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := map[string]any{"docType": mDL, "nameSpaces": map[string]any{mDLNS: map[string]bool{"age_over_18": false}}}
	for name, tc := range map[string]struct {
		b    []byte
		want error
	}{
		"not CBOR":         {[]byte{0xa2, 0x67}, ErrCBORDecoding},
		"items not CBOR":   {enc(map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": cbor.Tag{Number: 24, Content: []byte{0xa2, 0x67}}}}}), ErrCBORDecoding},
		"not a map":        {enc([]int{1}), ErrCBORValidation},
		"version 2":        {enc(map[string]any{"version": "2.0", "docRequests": []any{map[string]any{"itemsRequest": items(good)}}}), ErrCBORValidation},
		"no docRequests":   {enc(map[string]any{"version": "1.0"}), ErrCBORValidation},
		"DocRequests":      {enc(map[string]any{"version": "1.0", "DocRequests": []any{map[string]any{"itemsRequest": items(good)}}}), ErrCBORValidation},
		"DocType":          {enc(map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(map[string]any{"DocType": mDL, "nameSpaces": good["nameSpaces"]})}}}), ErrCBORValidation},
		"items not tagged": {enc(map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": enc(good)}}}), ErrCBORValidation},
		"no elements":      {enc(map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(map[string]any{"docType": mDL, "nameSpaces": map[string]any{mDLNS: map[string]bool{}}})}}}), ErrCBORValidation},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDeviceRequest(tc.b)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if status, ok := StatusFor(err); !ok || status != StatusCBORDecodingError {
				t.Errorf("StatusFor = %d, %v", status, ok)
			}
		})
	}
	if _, err := ParseDeviceRequest(enc(map[string]any{"version": "1.0", "docRequests": []any{map[string]any{"itemsRequest": items(good)}}})); err != nil {
		t.Errorf("the well-formed request: %v", err)
	}
}

// ErrorResponse sends the status for the holder's error, which the
// reader's Verify reports, and ends the session on both sides.
func TestErrorResponse(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want uint64
	}{
		{ErrCBORValidation, DeviceResponseStatusCBORValidation},
		{ErrCBORDecoding, DeviceResponseStatusCBORDecoding},
		{errors.New("the wallet failed"), DeviceResponseStatusGeneralError},
	} {
		f := establish(t, mDL, ageOver18)
		msg, err := f.holder.ErrorResponse(tc.err)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.holder.Encrypt([]byte{0xa0}, false); !errors.Is(err, ErrSessionClosed) {
			t.Errorf("the holder's session is still open: %v", err)
		}
		_, err = f.reader.Verify(context.Background(), msg, x509.NewCertPool(), time.Now())
		var se *DeviceResponseStatusError
		if !errors.As(err, &se) || se.Status != tc.want {
			t.Errorf("Verify = %v, want status %d", err, tc.want)
		}
	}
}

// VerifyDeviceRequest's outcomes for whole-request, per-document and
// mixed signatures: every signature must verify; with readerAuthAll its
// signers alone are the candidates for the reader, the first trusted
// one chosen; coverage of the information comes only from a verified
// readerAuthAll, trusted or not.
func TestVerifyDeviceRequest(t *testing.T) {
	a, b, c := newTestSigner(t), newTestSigner(t), newTestSigner(t)
	transcript := testTranscriptBytes(t, "verify")
	info := sampleInfo(t)
	trustA := ReaderTrust{Roots: a.roots, LeafPolicy: RequireReaderAuthenticationEKU}
	both := x509.NewCertPool()
	both.AddCert(a.chain[1])
	both.AddCert(b.chain[1])
	trustAB := ReaderTrust{Roots: both}
	for name, tc := range map[string]struct {
		req        testRequest
		trust      ReaderTrust
		want       ReaderStatus
		wantLeaf   *testSigner
		wantSigned bool
	}{
		"whole request only, trusted": {
			testRequest{docs: testDocs(2, nil), all: []testSigner{a}, info: info}, trustA, ReaderTrusted, &a, true,
		},
		"whole request only, no information": {
			testRequest{docs: testDocs(2, nil), all: []testSigner{a}}, trustA, ReaderTrusted, &a, false,
		},
		"whole request only, present empty information": {
			testRequest{docs: testDocs(2, nil), all: []testSigner{a}, info: infoOf(t, map[string]any{})}, trustA, ReaderTrusted, &a, true,
		},
		"whole request only, untrusted: still signed": {
			testRequest{docs: testDocs(2, nil), all: []testSigner{b}, info: info}, trustA, ReaderUntrusted, &b, true,
		},
		"one trusted signer after an untrusted one": {
			testRequest{docs: testDocs(2, nil), all: []testSigner{b, a}, info: info}, trustA, ReaderTrusted, &a, true,
		},
		"several trusted: the first": {
			testRequest{docs: testDocs(2, nil), all: []testSigner{b, a}, info: info}, trustAB, ReaderTrusted, &b, true,
		},
		"none trusted: the first signer's chain": {
			testRequest{docs: testDocs(2, nil), all: []testSigner{b, c}, info: info}, trustA, ReaderUntrusted, &b, true,
		},
		"trusted documents, untrusted whole request: no fallback": {
			testRequest{docs: testDocs(2, &a), all: []testSigner{b}, info: info}, trustA, ReaderUntrusted, &b, true,
		},
		"untrusted documents, trusted whole request": {
			testRequest{docs: testDocs(2, &b), all: []testSigner{a}, info: info}, trustA, ReaderTrusted, &a, true,
		},
		"some documents signed, whole request signed": {
			testRequest{docs: []testDoc{{"org.example.one", &a}, {"org.example.two", nil}}, all: []testSigner{a}, info: info}, trustA, ReaderTrusted, &a, true,
		},
		"documents only, one trusted reader": {
			testRequest{docs: testDocs(2, &a), info: info}, trustA, ReaderTrusted, &a, false,
		},
		"documents only, two trusted readers": {
			testRequest{docs: []testDoc{{"org.example.one", &a}, {"org.example.two", &b}}, info: info}, trustAB, ReaderUntrusted, &b, false,
		},
		"documents only, one unsigned": {
			testRequest{docs: []testDoc{{"org.example.one", &a}, {"org.example.two", nil}}, info: info}, trustA, ReaderUnauthenticated, nil, false,
		},
		"unsigned": {
			testRequest{docs: testDocs(2, nil), info: info}, trustA, ReaderUnauthenticated, nil, false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := mustDecode(t, tc.req.build(t, transcript))
			got := VerifyDeviceRequest(req, transcript, tc.trust)
			if got.Reader.Status != tc.want {
				t.Fatalf("Status = %v (%v), want %v", got.Reader.Status, got.Reader.Err, tc.want)
			}
			if got.RequestInfoSigned != tc.wantSigned {
				t.Errorf("RequestInfoSigned = %v, want %v", got.RequestInfoSigned, tc.wantSigned)
			}
			if (got.Reader.Err == nil) != (tc.want == ReaderTrusted) {
				t.Errorf("Err = %v for %v", got.Reader.Err, got.Reader.Status)
			}
			if tc.wantLeaf != nil && (len(got.Reader.Chain) == 0 || !got.Reader.Chain[0].Equal(tc.wantLeaf.chain[0])) {
				t.Errorf("the reader's chain isn't the expected signer's")
			}
		})
	}
}

// One bad signature anywhere makes the whole request invalid, with no
// chain and no coverage, though a complete trusted path would verify:
// a tampered, malformed or misplaced signature, another session,
// reordered documents, and changed information or extensions.
func TestVerifyDeviceRequest_Invalid(t *testing.T) {
	a, b := newTestSigner(t), newTestSigner(t)
	transcript := testTranscriptBytes(t, "invalid")
	trust := ReaderTrust{Roots: a.roots}
	signed := testRequest{docs: testDocs(2, &a), all: []testSigner{a, b}, info: sampleInfo(t)}.build(t, transcript)
	if got := VerifyDeviceRequest(mustDecode(t, signed), transcript, trust); got.Reader.Status != ReaderTrusted || !got.RequestInfoSigned {
		t.Fatalf("untampered: %+v", got)
	}
	edit := func(f func(m map[string]cbor.RawMessage)) []byte { return editRequest(t, signed, f) }
	editList := func(m map[string]cbor.RawMessage, key string, f func([]cbor.RawMessage) []cbor.RawMessage) {
		var list []cbor.RawMessage
		if err := cbor.Unmarshal(m[key], &list); err != nil {
			t.Fatal(err)
		}
		m[key] = mustCBOR(t, f(list))
	}
	editDoc := func(m map[string]cbor.RawMessage, i int, f func(map[string]cbor.RawMessage)) {
		editList(m, "docRequests", func(docs []cbor.RawMessage) []cbor.RawMessage {
			var d map[string]cbor.RawMessage
			if err := cbor.Unmarshal(docs[i], &d); err != nil {
				t.Fatal(err)
			}
			f(d)
			docs[i] = mustCBOR(t, d)
			return docs
		})
	}
	otherInfo := infoOf(t, map[string]any{"useCases": []any{useCase([][]int{{0}}, "purposeHints", map[string]int{"org.example": 4})}})
	changedExtension := append(append([]byte{0xa2}, mustCBOR(t, "zzExtension")...), mustCBOR(t, "y")...)
	changedExtension = append(changedExtension, sampleInfoUseCases(t)...)
	for name, tc := range map[string]struct {
		b       []byte
		session []byte
		reason  string
	}{
		"an extra whole-request signature tampered": {edit(func(m map[string]cbor.RawMessage) {
			editList(m, "readerAuthAll", func(all []cbor.RawMessage) []cbor.RawMessage { all[1] = tamperCOSE(t, all[1]); return all })
		}), transcript, "readerAuthAll[1]"},
		"a malformed whole-request signature": {edit(func(m map[string]cbor.RawMessage) {
			editList(m, "readerAuthAll", func(all []cbor.RawMessage) []cbor.RawMessage { return append(all, mustCBOR(t, "junk")) })
		}), transcript, "readerAuthAll[2]"},
		"a signature without a certificate": {edit(func(m map[string]cbor.RawMessage) {
			editList(m, "readerAuthAll", func(all []cbor.RawMessage) []cbor.RawMessage {
				return append(all, mustCBOR(t, []any{[]byte{0xa1, 0x01, 0x26}, map[int]any{}, nil, make([]byte, 64)}))
			})
		}), transcript, "readerAuthAll[2]"},
		"a document signature tampered": {edit(func(m map[string]cbor.RawMessage) {
			editDoc(m, 1, func(d map[string]cbor.RawMessage) { d["readerAuth"] = tamperCOSE(t, d["readerAuth"]) })
		}), transcript, "docRequests[1]"},
		"a document signature moved to the other document": {edit(func(m map[string]cbor.RawMessage) {
			var docs []map[string]cbor.RawMessage
			if err := cbor.Unmarshal(m["docRequests"], &docs); err != nil {
				t.Fatal(err)
			}
			docs[0]["readerAuth"], docs[1]["readerAuth"] = docs[1]["readerAuth"], docs[0]["readerAuth"]
			m["docRequests"] = mustCBOR(t, docs)
		}), transcript, "docRequests[0]"},
		"documents reordered": {edit(func(m map[string]cbor.RawMessage) {
			editList(m, "docRequests", func(docs []cbor.RawMessage) []cbor.RawMessage { return []cbor.RawMessage{docs[1], docs[0]} })
		}), transcript, "readerAuthAll[0]"},
		"information changed": {edit(func(m map[string]cbor.RawMessage) { m["deviceRequestInfo"] = otherInfo }), transcript, "readerAuthAll[0]"},
		"information removed": {edit(func(m map[string]cbor.RawMessage) { delete(m, "deviceRequestInfo") }), transcript, "readerAuthAll[0]"},
		"extension changed": {edit(func(m map[string]cbor.RawMessage) {
			m["deviceRequestInfo"] = tagged(t, changedExtension)
		}), transcript, "readerAuthAll[0]"},
		"another session": {signed, testTranscriptBytes(t, "replayed"), "readerAuthAll[0]"},
		"no session":      {signed, nil, "session"},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := DecodeDeviceRequest(tc.b)
			if err != nil {
				t.Fatalf("DecodeDeviceRequest: %v", err)
			}
			got := VerifyDeviceRequest(req, tc.session, trust)
			if got.Reader.Status != ReaderInvalid || got.Reader.Chain != nil || got.RequestInfoSigned {
				t.Fatalf("got %v, chain %d, signed %v; want invalid, no chain, unsigned (%v)", got.Reader.Status, len(got.Reader.Chain), got.RequestInfoSigned, got.Reader.Err)
			}
			if got.Reader.Err == nil || !strings.Contains(got.Reader.Err.Error(), tc.reason) {
				t.Errorf("Err = %v, want it to name %s", got.Reader.Err, tc.reason)
			}
		})
	}
}

// sampleInfoUseCases is sampleInfo's "useCases" entry, key and value.
func sampleInfoUseCases(t *testing.T) []byte {
	t.Helper()
	content, err := unwrapTag24(sampleInfo(t))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(content, mustCBOR(t, "useCases"))
	if i < 0 {
		t.Fatal("no useCases in sampleInfo")
	}
	return content[i:]
}

// tamperCOSE flips a bit of a COSE_Sign1's signature.
func tamperCOSE(t *testing.T, sig cbor.RawMessage) cbor.RawMessage {
	t.Helper()
	var parts []cbor.RawMessage
	if err := cbor.Unmarshal(sig, &parts); err != nil || len(parts) != 4 {
		t.Fatalf("not a COSE_Sign1: %v", err)
	}
	var s []byte
	if err := cbor.Unmarshal(parts[3], &s); err != nil {
		t.Fatal(err)
	}
	s[0] ^= 1
	parts[3] = mustCBOR(t, s)
	return mustCBOR(t, parts)
}

// The session convenience method checks against the session's own
// transcript: before the session is established there is none.
func TestDeviceSession_VerifyDeviceRequest(t *testing.T) {
	a := newTestSigner(t)
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	req := mustDecode(t, testRequest{docs: testDocs(1, nil), all: []testSigner{a}}.build(t, testTranscriptBytes(t, "x")))
	if got := holder.VerifyDeviceRequest(req, ReaderTrust{Roots: a.roots}); got.Reader.Status != ReaderInvalid {
		t.Errorf("before the session is established: %v, want invalid", got.Reader.Status)
	}
}
