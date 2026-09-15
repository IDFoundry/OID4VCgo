package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/cose"
)

func selfSignedCert(t *testing.T, pub, signer interface{}) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mdoc test issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func testClaims(t *testing.T, deviceKey interface{}) Claims {
	t.Helper()
	signed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	return Claims{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]map[string]interface{}{
			"org.iso.18013.5.1": {
				"family_name": "Doe",
				"given_name":  "John",
			},
		},
		DeviceKey:  deviceKey,
		Signed:     signed,
		ValidFrom:  signed,
		ValidUntil: signed.Add(365 * 24 * time.Hour),
	}
}

// fixture is a freshly issued IssuerSigned plus the material behind it,
// shared by every test below that just needs "some validly issued
// mdoc" rather than a specific claim shape.
type fixture struct {
	issuerKey *ecdsa.PrivateKey
	deviceKey *ecdsa.PrivateKey
	cert      []byte
	claims    Claims
	signed    IssuerSigned
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	cert := selfSignedCert(t, &issuerKey.PublicKey, issuerKey)
	claims := testClaims(t, &deviceKey.PublicKey)
	signed, err := Issue(issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{cert}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return fixture{issuerKey: issuerKey, deviceKey: deviceKey, cert: cert, claims: claims, signed: signed}
}

func TestIssueVerifyRoundTripES256(t *testing.T) {
	f := newFixture(t)

	verified, err := Verify(f.signed, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.DocType != f.claims.DocType {
		t.Errorf("DocType = %q, want %q", verified.DocType, f.claims.DocType)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["family_name"]; got != "Doe" {
		t.Errorf("family_name = %v, want Doe", got)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["given_name"]; got != "John" {
		t.Errorf("given_name = %v, want John", got)
	}
	devicePub, ok := verified.DeviceKey.(*ecdsa.PublicKey)
	if !ok || !devicePub.Equal(&f.deviceKey.PublicKey) {
		t.Errorf("DeviceKey = %v, want %v", verified.DeviceKey, &f.deviceKey.PublicKey)
	}
	if len(verified.X5Chain) != 1 {
		t.Fatalf("X5Chain has %d entries, want 1", len(verified.X5Chain))
	}
}

func TestIssueVerifyRoundTripEdDSA(t *testing.T) {
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	devicePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	cert := selfSignedCert(t, issuerPub, issuerPriv)

	claims := testClaims(t, devicePub)
	signed, err := Issue(issuerPriv, cose.EdDSA, claims, IssueOptions{X5Chain: [][]byte{cert}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	verified, err := Verify(signed, issuerPub, cose.EdDSA, VerifyOptions{
		Now: func() time.Time { return claims.Signed.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verified.DeviceKey.(ed25519.PublicKey).Equal(devicePub) {
		t.Errorf("DeviceKey mismatch")
	}
}

func TestVerifyRejectsTamperedElementValue(t *testing.T) {
	f := newFixture(t)

	items := f.signed.NameSpaces["org.iso.18013.5.1"]
	for i, item := range items {
		if item.ElementIdentifier == "family_name" {
			item.ElementValue = "Tampered"
			items[i] = item
		}
	}

	if _, err := Verify(f.signed, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	}); err == nil {
		t.Errorf("Verify accepted a tampered element value")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	f := newFixture(t)

	if _, err := Verify(f.signed, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.ValidUntil.Add(time.Hour) },
	}); err == nil {
		t.Errorf("Verify accepted an expired MSO")
	}
}

func TestVerifyRejectsNotYetValid(t *testing.T) {
	f := newFixture(t)

	if _, err := Verify(f.signed, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.ValidFrom.Add(-time.Hour) },
	}); err == nil {
		t.Errorf("Verify accepted a not-yet-valid MSO")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	f := newFixture(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	if _, err := Verify(f.signed, &otherKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	}); err == nil {
		t.Errorf("Verify accepted a signature under the wrong key")
	}
}

func TestIssueRequiresFields(t *testing.T) {
	f := newFixture(t)
	validOpts := IssueOptions{X5Chain: [][]byte{f.cert}}

	cases := []struct {
		name   string
		mutate func(*Claims)
		opts   IssueOptions
	}{
		{"missing DocType", func(c *Claims) { c.DocType = "" }, validOpts},
		{"missing NameSpaces", func(c *Claims) { c.NameSpaces = nil }, validOpts},
		{"empty namespace", func(c *Claims) {
			c.NameSpaces["org.iso.18013.5.1"] = map[string]interface{}{}
		}, validOpts},
		{"missing DeviceKey", func(c *Claims) { c.DeviceKey = nil }, validOpts},
		{"missing Signed", func(c *Claims) { c.Signed = time.Time{} }, validOpts},
		{"missing ValidFrom", func(c *Claims) { c.ValidFrom = time.Time{} }, validOpts},
		{"missing ValidUntil", func(c *Claims) { c.ValidUntil = time.Time{} }, validOpts},
		{"missing X5Chain", func(c *Claims) {}, IssueOptions{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := testClaims(t, &f.deviceKey.PublicKey)
			tc.mutate(&claims)
			if _, err := Issue(f.issuerKey, cose.ES256, claims, tc.opts); err == nil {
				t.Errorf("Issue succeeded despite %s", tc.name)
			}
		})
	}
}

func TestIssueRejectsUnsupportedDeviceKeyType(t *testing.T) {
	f := newFixture(t)
	claims := testClaims(t, "not-a-key")
	if _, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}}); err == nil {
		t.Errorf("Issue accepted an unsupported DeviceKey type")
	}
}

func TestIssuerSignedMarshalUnmarshalRoundTrip(t *testing.T) {
	f := newFixture(t)

	wire, err := f.signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded, err := UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}

	verified, err := Verify(decoded, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Verify(decoded): %v", err)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["family_name"]; got != "Doe" {
		t.Errorf("family_name = %v, want Doe", got)
	}
}

func TestUnmarshalIssuerSignedRejectsMalformedInput(t *testing.T) {
	if _, err := UnmarshalIssuerSigned([]byte("not cbor")); err == nil {
		t.Errorf("UnmarshalIssuerSigned accepted malformed input")
	}
}

func TestIssuerSignedMarshalRejectsEmptyNamespace(t *testing.T) {
	signed := IssuerSigned{
		NameSpaces: map[string][]IssuerSignedItem{"org.iso.18013.5.1": {}},
		IssuerAuth: []byte{0x80},
	}
	if _, err := signed.Marshal(); err == nil {
		t.Errorf("Marshal accepted a namespace with no data elements")
	}
}

func TestDigestIDsAreUniqueWithinNamespace(t *testing.T) {
	f := newFixture(t)
	claims := testClaims(t, &f.deviceKey.PublicKey)
	claims.NameSpaces["org.iso.18013.5.1"] = map[string]interface{}{
		"a": 1, "b": 2, "c": 3, "d": 4, "e": 5,
	}
	signed, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	seen := map[uint64]bool{}
	for _, item := range signed.NameSpaces["org.iso.18013.5.1"] {
		if seen[item.DigestID] {
			t.Errorf("duplicate DigestID %d", item.DigestID)
		}
		seen[item.DigestID] = true
		if len(item.Random) < 16 {
			t.Errorf("Random has length %d, want >= 16", len(item.Random))
		}
	}
}
