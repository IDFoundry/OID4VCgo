package mdocdcapi

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

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
