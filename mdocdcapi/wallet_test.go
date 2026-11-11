package mdocdcapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
)

// walletHarness is a request signed by a reader certificate from a CA
// the wallet trusts, and the wallet's mdoc.
type walletHarness struct {
	harness
	roots *x509.CertPool
	data  []byte
	leaf  *x509.Certificate
}

func newWalletHarness(t testing.TB, elements map[string]map[string]bool) walletHarness {
	t.Helper()
	ca, caKey := testcert.CA(t, "mdocdcapi test reader CA")
	cert, key := testcert.Leaf(t, "mdocdcapi test reader", ca, caKey)
	reader := ReaderKey{Signer: key, Chain: []*x509.Certificate{cert, ca}}
	req, err := BuildRequest(RequestParams{Origin: testOrigin, DocType: testmdoc.DocType, Elements: elements, Readers: []ReaderKey{reader}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return walletHarness{
		harness: harness{f: testmdoc.Issue(t), reader: reader, request: req},
		roots:   roots, data: marshalData(t, req.Data), leaf: cert,
	}
}

func marshalData(t testing.TB, d RequestData) []byte {
	t.Helper()
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func familyName() [][2]string { return [][2]string{{isoNS, "family_name"}} }

// Request data another parser would read differently — a member twice,
// or a member named like deviceRequest or encryptionInfo in another
// case — is refused: the platform reads the same data.
func TestParseRequestAmbiguousJSON(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	for name, prefix := range map[string]string{
		"deviceRequest twice":         `{"deviceRequest":"AA",`,
		"case-variant encryptionInfo": `{"EncryptionInfo":"AA",`,
		"case-variant deviceRequest":  `{"devicerequest":"AA",`,
	} {
		if _, err := ParseRequest(append([]byte(prefix), h.data[1:]...), testOrigin); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A wallet answers the reader side's request, and the reader verifies
// the answer: only the consented element is disclosed.
func TestWalletRoundTrip(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	in, err := ParseRequest(h.data, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Documents) != 1 || in.Documents[0].DocType != testmdoc.DocType ||
		!in.Documents[0].Elements[isoNS]["family_name"] || in.Documents[0].Elements[isoNS]["given_name"] ||
		!in.Documents[0].Requested(isoNS, "given_name") || in.Documents[0].Requested(isoNS, "birth_date") {
		t.Fatalf("Documents = %+v", in.Documents)
	}
	reader, err := in.VerifyReader(h.roots, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !reader.Equal(h.leaf) {
		t.Errorf("VerifyReader = %s, want the reader's leaf", reader.Subject)
	}
	encrypted, err := in.Respond(0, h.f.IssuerSigned, h.f.DeviceKey, familyName())
	if err != nil {
		t.Fatal(err)
	}
	got, err := verify(t, h.harness, base64.RawURLEncoding.EncodeToString(encrypted), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.NameSpaces[isoNS]["family_name"] != "Doe" || len(got.NameSpaces[isoNS]) != 1 {
		t.Errorf("disclosed %v, want only family_name", got.NameSpaces)
	}

	var wrapped struct{ Response string }
	if err := json.Unmarshal(ResponseData(encrypted), &wrapped); err != nil || wrapped.Response != base64.RawURLEncoding.EncodeToString(encrypted) {
		t.Errorf("ResponseData = %s", ResponseData(encrypted))
	}
}

// A request parsed for another origin than the one it was made for has
// another session transcript: the reader's signature doesn't verify,
// and the answer doesn't decrypt at the reader.
func TestWalletBindsOrigin(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	in, err := ParseRequest(h.data, "https://attacker.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.VerifyReader(h.roots, time.Time{}); !errors.Is(err, ErrUntrustedReader) {
		t.Errorf("VerifyReader for another origin = %v, want ErrUntrustedReader", err)
	}
	encrypted, err := in.Respond(0, h.f.IssuerSigned, h.f.DeviceKey, familyName())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, h.harness, base64.RawURLEncoding.EncodeToString(encrypted), nil); err == nil {
		t.Error("an answer for another origin verified")
	}
}

func TestVerifyReaderRefuses(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	otherCA, _ := testcert.CA(t, "another CA")
	other := x509.NewCertPool()
	other.AddCert(otherCA)
	unsigned, err := BuildRequest(RequestParams{Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames()})
	if err != nil {
		t.Fatal(err)
	}
	selfSigned := newHarness(t, bothNames())

	cases := map[string]struct {
		data  []byte
		roots *x509.CertPool
		now   time.Time
	}{
		"untrusted root":      {h.data, other, time.Time{}},
		"unsigned":            {marshalData(t, unsigned.Data), h.roots, time.Time{}},
		"self-signed reader":  {marshalData(t, selfSigned.request.Data), selfSignedPool(selfSigned), time.Time{}},
		"reader cert expired": {h.data, h.roots, time.Now().AddDate(50, 0, 0)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in, err := ParseRequest(c.data, testOrigin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := in.VerifyReader(c.roots, c.now); !errors.Is(err, ErrUntrustedReader) {
				t.Errorf("VerifyReader = %v, want ErrUntrustedReader", err)
			}
		})
	}
	in, err := ParseRequest(h.data, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.VerifyReader(nil, time.Time{}); err == nil {
		t.Error("VerifyReader with no roots succeeded")
	}
}

func selfSignedPool(h harness) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(h.reader.Chain[0])
	return pool
}

// A first-edition reader signs each DocRequest and sends no
// ReaderAuthAll: its signature still identifies it.
func TestVerifyReaderPerDocument(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	var data RequestData
	if err := json.Unmarshal(h.data, &data); err != nil {
		t.Fatal(err)
	}
	data.DeviceRequest = rewriteDeviceRequest(t, data.DeviceRequest, func(dr map[string]cbor.RawMessage) {
		delete(dr, "readerAuthAll")
		dr["version"] = mustCBOR(t, "1.0")
	})
	in, err := ParseRequest(marshalData(t, data), testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.VerifyReader(h.roots, time.Time{}); err != nil {
		t.Errorf("VerifyReader of a per-document signature = %v", err)
	}
}

func rewriteDeviceRequest(t *testing.T, deviceRequest string, edit func(map[string]cbor.RawMessage)) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(deviceRequest)
	if err != nil {
		t.Fatal(err)
	}
	var dr map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &dr); err != nil {
		t.Fatal(err)
	}
	edit(dr)
	return base64.RawURLEncoding.EncodeToString(mustCBOR(t, dr))
}

func mustCBOR(t testing.TB, v any) []byte {
	t.Helper()
	out, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRespondRefuses(t *testing.T) {
	h := newWalletHarness(t, map[string]map[string]bool{isoNS: {"family_name": false}})
	in, err := ParseRequest(h.data, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		in       Incoming
		doc      int
		elements [][2]string
		want     string
	}{
		"unrequested element":    {in, 0, [][2]string{{isoNS, "family_name"}, {isoNS, "given_name"}}, "given_name weren't requested"},
		"nothing to disclose":    {in, 0, nil, "no element"},
		"no such document":       {in, 1, familyName(), "no document request 1"},
		"not a parsed request":   {Incoming{Documents: in.Documents}, 0, familyName(), "isn't a parsed request"},
		"element the mdoc lacks": {in, 0, nil, "no element"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.in.Respond(c.doc, h.f.IssuerSigned, h.f.DeviceKey, c.elements)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Respond = %v, want an error containing %q", err, c.want)
			}
		})
	}

	// Requested, but not in the held mdoc.
	birth := newWalletHarness(t, map[string]map[string]bool{isoNS: {"birth_date": false}})
	in, err = ParseRequest(birth.data, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Respond(0, birth.f.IssuerSigned, birth.f.DeviceKey, [][2]string{{isoNS, "birth_date"}}); err == nil || !strings.Contains(err.Error(), "holds none") {
		t.Errorf("Respond with an element the mdoc lacks = %v", err)
	}
}

func TestParseRequestRefuses(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	var good RequestData
	if err := json.Unmarshal(h.data, &good); err != nil {
		t.Fatal(err)
	}
	with := func(edit func(*RequestData)) []byte {
		d := good
		edit(&d)
		return marshalData(t, d)
	}
	otherProtocol := base64.RawURLEncoding.EncodeToString(mustCBOR(t, []any{"other", decodeEncryptionInfo(t, good.EncryptionInfo)}))
	shortNonce := decodeEncryptionInfo(t, good.EncryptionInfo)
	shortNonce.Nonce = shortNonce.Nonce[:8]
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherCurve := decodeEncryptionInfo(t, good.EncryptionInfo)
	if otherCurve.RecipientPublicKey, err = mdoc.NewCoseKey(&p384.PublicKey); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		data   []byte
		origin string
	}{
		"not JSON":              {[]byte("{"), testOrigin},
		"no encryptionInfo":     {with(func(d *RequestData) { d.EncryptionInfo = "" }), testOrigin},
		"origin with a path":    {h.data, testOrigin + "/"},
		"origin without scheme": {h.data, "verifier.example"},
		"too large":             {make([]byte, MaxRequestBytes+1), testOrigin},
		"deviceRequest not b64": {with(func(d *RequestData) { d.DeviceRequest = "!" }), testOrigin},
		"other protocol":        {with(func(d *RequestData) { d.EncryptionInfo = otherProtocol }), testOrigin},
		"short nonce": {with(func(d *RequestData) {
			d.EncryptionInfo = base64.RawURLEncoding.EncodeToString(mustCBOR(t, []any{"dcapi", shortNonce}))
		}), testOrigin},
		// Annex C's suite is DHKEM(P-256), so a P-384 key isn't sealed to.
		"P-384 recipient key": {with(func(d *RequestData) {
			d.EncryptionInfo = base64.RawURLEncoding.EncodeToString(mustCBOR(t, []any{"dcapi", otherCurve}))
		}), testOrigin},
		"version 2": {with(func(d *RequestData) {
			d.DeviceRequest = rewriteDeviceRequest(t, d.DeviceRequest, func(dr map[string]cbor.RawMessage) { dr["version"] = mustCBOR(t, "2.0") })
		}), testOrigin},
		"no document": {with(func(d *RequestData) {
			d.DeviceRequest = rewriteDeviceRequest(t, d.DeviceRequest, func(dr map[string]cbor.RawMessage) { dr["docRequests"] = mustCBOR(t, []any{}) })
		}), testOrigin},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequest(c.data, c.origin); err == nil {
				t.Error("ParseRequest succeeded")
			}
		})
	}
}

// readerWithEKU is a reader whose certificate, from its own CA, has
// the extended key usages ekus.
func readerWithEKU(t *testing.T, ekus ...asn1.ObjectIdentifier) (ReaderKey, *x509.CertPool) {
	t.Helper()
	ca, caKey := testcert.CA(t, "mdocdcapi EKU test reader CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "mdocdcapi EKU test reader"},
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
	return ReaderKey{Signer: key, Chain: []*x509.Certificate{cert, ca}}, roots
}

// A LeafPolicy can refuse a reader the roots recognize:
// RequireReaderAuthenticationEKU refuses one whose certificate isn't a
// reader authentication certificate.
func TestVerifyReaderTrust_LeafPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		ekus []asn1.ObjectIdentifier
		ok   bool
	}{
		"reader authentication EKU": {[]asn1.ObjectIdentifier{ReaderAuthenticationEKU}, true},
		"another EKU":               {[]asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 2}}, false},
		"no EKU":                    {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			reader, roots := readerWithEKU(t, tc.ekus...)
			req, err := BuildRequest(RequestParams{Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Readers: []ReaderKey{reader}})
			if err != nil {
				t.Fatal(err)
			}
			in, err := ParseRequest(marshalData(t, req.Data), testOrigin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := in.VerifyReader(roots, time.Time{}); err != nil {
				t.Fatalf("without a LeafPolicy: %v", err)
			}
			_, err = in.VerifyReaderTrust(ReaderTrust{Roots: roots, LeafPolicy: RequireReaderAuthenticationEKU})
			if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrUntrustedReader)) {
				t.Errorf("with RequireReaderAuthenticationEKU: %v, want ok %v", err, tc.ok)
			}
		})
	}
}

// A request past a limit is refused before any signature is checked.
func TestParseRequestRefusesOverLimits(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	var good RequestData
	if err := json.Unmarshal(h.data, &good); err != nil {
		t.Fatal(err)
	}
	repeat := func(key string, n int) []byte {
		return func() []byte {
			d := good
			d.DeviceRequest = rewriteDeviceRequest(t, d.DeviceRequest, func(dr map[string]cbor.RawMessage) {
				var one []cbor.RawMessage
				if err := cbor.Unmarshal(dr[key], &one); err != nil || len(one) == 0 {
					t.Fatalf("%s: %v", key, err)
				}
				many := make([]cbor.RawMessage, n)
				for i := range many {
					many[i] = one[0]
				}
				dr[key] = mustCBOR(t, many)
			})
			return marshalData(t, d)
		}()
	}
	many := map[string]bool{}
	for i := 0; i <= MaxRequestedElements; i++ {
		many[fmt.Sprintf("element_%d", i)] = false
	}
	tooManyElements := newWalletHarness(t, map[string]map[string]bool{isoNS: many})

	for name, data := range map[string][]byte{
		"documents":         repeat("docRequests", MaxDocRequests+1),
		"reader signatures": repeat("readerAuthAll", MaxReaderSignatures+1),
		"elements":          tooManyElements.data,
	} {
		if _, err := ParseRequest(data, testOrigin); err == nil || !strings.Contains(err.Error(), "more than") {
			t.Errorf("too many %s: %v", name, err)
		}
	}
	if _, err := ParseRequest(repeat("readerAuthAll", MaxReaderSignatures), testOrigin); err != nil {
		t.Errorf("%d reader signatures: %v", MaxReaderSignatures, err)
	}
	// A DeviceResponse holds one document of each type, so a reader
	// asks for each once.
	if _, err := ParseRequest(repeat("docRequests", 2), testOrigin); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a document type asked for twice: %v", err)
	}
}

// editDocRequests applies edit to the DocRequests of dr, a decoded
// DeviceRequest.
func editDocRequests(t *testing.T, dr map[string]cbor.RawMessage, edit func([]map[string]cbor.RawMessage)) {
	t.Helper()
	var docs []map[string]cbor.RawMessage
	if err := cbor.Unmarshal(dr["docRequests"], &docs); err != nil {
		t.Fatal(err)
	}
	edit(docs)
	dr["docRequests"] = mustCBOR(t, docs)
}

// tamperSignature flips a bit of sig's last byte, which, sig being a
// COSE_Sign1, is its signature's.
func tamperSignature(sig cbor.RawMessage) cbor.RawMessage {
	out := slices.Clone(sig)
	out[len(out)-1] ^= 1
	return out
}

// A reader signature whose certificate chains to a trusted root, but
// whose signature doesn't verify, recognizes no reader: as a
// ReaderAuthAll, and as a first-edition ReaderAuth, each the request's
// only signature.
func TestVerifyReaderRefusesTamperedSignature(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	var good RequestData
	if err := json.Unmarshal(h.data, &good); err != nil {
		t.Fatal(err)
	}
	with := func(edit func(dr map[string]cbor.RawMessage)) []byte {
		d := good
		d.DeviceRequest = rewriteDeviceRequest(t, d.DeviceRequest, edit)
		return marshalData(t, d)
	}
	onlyAll := func(tamper bool) []byte {
		return with(func(dr map[string]cbor.RawMessage) {
			editDocRequests(t, dr, func(docs []map[string]cbor.RawMessage) { delete(docs[0], "readerAuth") })
			if tamper {
				var all []cbor.RawMessage
				if err := cbor.Unmarshal(dr["readerAuthAll"], &all); err != nil {
					t.Fatal(err)
				}
				all[0] = tamperSignature(all[0])
				dr["readerAuthAll"] = mustCBOR(t, all)
			}
		})
	}
	onlyDocument := func(tamper bool) []byte {
		return with(func(dr map[string]cbor.RawMessage) {
			delete(dr, "readerAuthAll")
			dr["version"] = mustCBOR(t, "1.0")
			if tamper {
				editDocRequests(t, dr, func(docs []map[string]cbor.RawMessage) {
					docs[0]["readerAuth"] = tamperSignature(docs[0]["readerAuth"])
				})
			}
		})
	}
	// Both kinds present and both bad: each reason is reported.
	both := with(func(dr map[string]cbor.RawMessage) {
		var all []cbor.RawMessage
		if err := cbor.Unmarshal(dr["readerAuthAll"], &all); err != nil {
			t.Fatal(err)
		}
		all[0] = tamperSignature(all[0])
		dr["readerAuthAll"] = mustCBOR(t, all)
		editDocRequests(t, dr, func(docs []map[string]cbor.RawMessage) {
			docs[0]["readerAuth"] = tamperSignature(docs[0]["readerAuth"])
		})
	})
	if in, err := ParseRequest(both, testOrigin); err != nil {
		t.Fatal(err)
	} else if _, err := in.VerifyReader(h.roots, time.Time{}); err == nil || strings.Count(err.Error(), "signature verification failed") != 2 || !strings.Contains(err.Error(), "signed per document") {
		t.Errorf("both tampered: %v, want both reasons", err)
	}
	for name, data := range map[string]struct{ good, tampered []byte }{
		"ReaderAuthAll": {onlyAll(false), onlyAll(true)},
		"ReaderAuth":    {onlyDocument(false), onlyDocument(true)},
	} {
		t.Run(name, func(t *testing.T) {
			in, err := ParseRequest(data.good, testOrigin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := in.VerifyReader(h.roots, time.Time{}); err != nil {
				t.Fatalf("untampered: %v", err)
			}
			if in, err = ParseRequest(data.tampered, testOrigin); err != nil {
				t.Fatal(err)
			}
			_, err = in.VerifyReader(h.roots, time.Time{})
			if !errors.Is(err, ErrUntrustedReader) {
				t.Errorf("VerifyReader = %v, want ErrUntrustedReader", err)
			}
			// The signature's reason, not the absence of another kind.
			if err != nil && !strings.Contains(err.Error(), "signature verification failed") {
				t.Errorf("VerifyReader = %v, want the bad signature reported", err)
			}
		})
	}
}

// A first-edition request is signed by one reader on every DocRequest
// (VerifyReaderTrust): one whose DocRequests two trusted readers
// signed, or one with a DocRequest unsigned, recognizes no reader.
func TestVerifyReaderPerDocumentRefusesMixedSigners(t *testing.T) {
	ca, caKey := testcert.CA(t, "mdocdcapi test reader CA")
	certA, keyA := testcert.Leaf(t, "mdocdcapi test reader A", ca, caKey)
	certB, keyB := testcert.Leaf(t, "mdocdcapi test reader B", ca, caKey)
	readerB := ReaderKey{Signer: keyB, Chain: []*x509.Certificate{certB, ca}}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	req, err := BuildRequest(RequestParams{Origin: testOrigin, Documents: []DocumentRequest{
		{DocType: testmdoc.DocType, Elements: bothNames()},
		{DocType: "org.iso.23220.photoid.1", Elements: map[string]map[string]bool{"org.iso.23220.1": {"family_name": false}}},
	}, Readers: []ReaderKey{{Signer: keyA, Chain: []*x509.Certificate{certA, ca}}}})
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := sessionTranscript(req.Data.EncryptionInfo, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	perDocument := func(edit func(docs []map[string]cbor.RawMessage)) Incoming {
		d := req.Data
		d.DeviceRequest = rewriteDeviceRequest(t, d.DeviceRequest, func(dr map[string]cbor.RawMessage) {
			delete(dr, "readerAuthAll")
			dr["version"] = mustCBOR(t, "1.0")
			editDocRequests(t, dr, edit)
		})
		in, err := ParseRequest(marshalData(t, d), testOrigin)
		if err != nil {
			t.Fatal(err)
		}
		return in
	}

	if reader, err := perDocument(func([]map[string]cbor.RawMessage) {}).VerifyReader(roots, time.Time{}); err != nil || !reader.Equal(certA) {
		t.Fatalf("both DocRequests signed by one reader: %v", err)
	}
	for name, tc := range map[string]struct {
		edit func(docs []map[string]cbor.RawMessage)
		want string
	}{
		"another reader signs the second": {func(docs []map[string]cbor.RawMessage) {
			sig, err := signReaderAuth(readerB, readerAuthentication(transcript, docs[1]["itemsRequest"]))
			if err != nil {
				t.Fatal(err)
			}
			docs[1]["readerAuth"] = sig
		}, "different readers"},
		"the second unsigned": {func(docs []map[string]cbor.RawMessage) { delete(docs[1], "readerAuth") }, "a document request isn't signed"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := perDocument(tc.edit).VerifyReader(roots, time.Time{})
			if !errors.Is(err, ErrUntrustedReader) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("VerifyReader = %v, want ErrUntrustedReader: %s", err, tc.want)
			}
		})
	}
}

// A DeviceRequest that isn't CBOR, an itemsRequest that isn't
// #6.24(bstr .cbor ItemsRequest), and an EncryptionInfo without a
// nonce are refused.
func TestParseRequestRefusesMalformedStructures(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	var good RequestData
	if err := json.Unmarshal(h.data, &good); err != nil {
		t.Fatal(err)
	}
	withItemsRequest := func(itemsRequest any) []byte {
		d := good
		d.DeviceRequest = rewriteDeviceRequest(t, d.DeviceRequest, func(dr map[string]cbor.RawMessage) {
			editDocRequests(t, dr, func(docs []map[string]cbor.RawMessage) { docs[0]["itemsRequest"] = mustCBOR(t, itemsRequest) })
		})
		return marshalData(t, d)
	}
	items := itemsRequest{DocType: testmdoc.DocType, NameSpaces: bothNames()}
	inner := mustCBOR(t, items)
	params := decodeEncryptionInfo(t, good.EncryptionInfo)
	noNonce := good
	noNonce.EncryptionInfo = base64.RawURLEncoding.EncodeToString(mustCBOR(t, []any{"dcapi", map[string]any{"recipientPublicKey": params.RecipientPublicKey}}))
	notCBOR := good
	notCBOR.DeviceRequest = base64.RawURLEncoding.EncodeToString([]byte{0xa3, 0x67, 'v', 'e', 'r'}) // a map cut short

	if _, err := ParseRequest(withItemsRequest(cbor.Tag{Number: tag24, Content: inner}), testOrigin); err != nil {
		t.Fatalf("itemsRequest re-encoded: %v", err)
	}
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"deviceRequest not CBOR":         {marshalData(t, notCBOR), "decode DeviceRequest"},
		"itemsRequest under another tag": {withItemsRequest(cbor.Tag{Number: 100, Content: inner}), "itemsRequest must be #6.24"},
		"itemsRequest #6.24 of a map":    {withItemsRequest(cbor.Tag{Number: tag24, Content: items}), "itemsRequest must be #6.24"},
		"itemsRequest untagged":          {withItemsRequest(inner), "itemsRequest must be #6.24"},
		"no nonce":                       {marshalData(t, noNonce), "nonce must be at least 16 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequest(tc.data, testOrigin); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseRequest = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// nested is v inside n arrays.
func nested(n int, v any) any {
	for range n {
		v = []any{v}
	}
	return v
}

// withDuplicateKey is m, a CBOR map of fewer than 23 entries, encoded
// with its entry key a second time, at the end.
func withDuplicateKey(t testing.TB, m map[string]cbor.RawMessage, key string) []byte {
	t.Helper()
	if len(m) >= 23 {
		t.Fatalf("a map of %d entries", len(m))
	}
	out := []byte{0xa0 | byte(len(m)+1)}
	for _, k := range append(slices.Sorted(maps.Keys(m)), key) {
		out = append(out, mustCBOR(t, k)...)
		out = append(out, m[k]...)
	}
	return out
}

// The DeviceRequest and EncryptionInfo decoder refuses nesting past
// its MaxNestedLevels (16), and a map with a key twice, even where
// both values are the same.
func TestParseRequestRefusesCBORPastLimits(t *testing.T) {
	h := newWalletHarness(t, bothNames())
	var good RequestData
	if err := json.Unmarshal(h.data, &good); err != nil {
		t.Fatal(err)
	}
	// The DeviceRequest is the first level: a deviceRequestInfo of n-1
	// arrays makes n.
	levels := func(n int) []byte {
		d := good
		d.DeviceRequest = rewriteDeviceRequest(t, d.DeviceRequest, func(dr map[string]cbor.RawMessage) {
			dr["deviceRequestInfo"] = mustCBOR(t, nested(n-1, 0))
		})
		return marshalData(t, d)
	}
	raw, err := base64.RawURLEncoding.DecodeString(good.DeviceRequest)
	if err != nil {
		t.Fatal(err)
	}
	var dr map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &dr); err != nil {
		t.Fatal(err)
	}
	versionTwice := good
	versionTwice.DeviceRequest = base64.RawURLEncoding.EncodeToString(withDuplicateKey(t, dr, "version"))
	params := decodeEncryptionInfo(t, good.EncryptionInfo)
	nonceTwice := good
	nonceTwice.EncryptionInfo = base64.RawURLEncoding.EncodeToString(slices.Concat([]byte{0x82}, mustCBOR(t, "dcapi"),
		withDuplicateKey(t, map[string]cbor.RawMessage{"nonce": mustCBOR(t, params.Nonce), "recipientPublicKey": mustCBOR(t, params.RecipientPublicKey)}, "nonce")))

	if _, err := ParseRequest(levels(16), testOrigin); err != nil {
		t.Fatalf("16 levels: %v", err)
	}
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"17 levels":                   {levels(17), "max nested level"},
		"DeviceRequest version twice": {marshalData(t, versionTwice), "duplicate map key"},
		"EncryptionInfo nonce twice":  {marshalData(t, nonceTwice), "duplicate map key"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequest(tc.data, testOrigin); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseRequest = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
