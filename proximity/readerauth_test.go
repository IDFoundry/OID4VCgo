package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// testReader is a reader key whose certificate, from its own CA, has
// the extended key usages ekus, and the pool of that CA.
func testReader(t *testing.T, ekus ...asn1.ObjectIdentifier) (*ecdsa.PrivateKey, []*x509.Certificate, *x509.CertPool) {
	t.Helper()
	ca, caKey := testcert.CA(t, "proximity test reader CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, opt := range map[string]ReaderOption{
		"no chain":        WithReaderAuth(key, nil),
		"another key":     WithReaderAuth(otherKey, chain),
		"no signer":       WithReaderAuth(nil, chain),
		"unsupported key": WithReaderAuth(p384, []*x509.Certificate{testcert.SelfSigned(t, "p384", &p384.PublicKey, p384)}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReaderSession(holder.QRCode(), opt); err == nil {
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
		_, err = f.reader.Verify(msg, x509.NewCertPool(), time.Now())
		var se *DeviceResponseStatusError
		if !errors.As(err, &se) || se.Status != tc.want {
			t.Errorf("Verify = %v, want status %d", err, tc.want)
		}
	}
}
