package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

func selfSignedCert(t testing.TB, pub, signer interface{}) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mdoc test issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
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

	verified, err := Verify(f.signed, f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
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
	if verified.Status != nil {
		t.Errorf("Status = %v, want nil (Claims.Status was never set)", verified.Status)
	}
}

// issueAndVerifyWithStatus issues claims (after mutate sets one of
// Claims.Status/Claims.IdentifierList) and verifies the result,
// returning the verified Status for the caller's own assertions. Shared
// by the status_list and identifier_list variants of "issue with a
// Status mechanism set, verify it round-trips" (in-memory and, via
// wireRoundTrip, over the wire) — Issue/Verify's own plumbing is
// identical either way, only the assigned field and expected shape
// differ.
func issueAndVerifyWithStatus(t *testing.T, f fixture, wireRoundTrip bool, mutate func(*Claims)) *Status {
	t.Helper()
	claims := f.claims
	mutate(&claims)
	signed, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if wireRoundTrip {
		wire, err := signed.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		signed, err = UnmarshalIssuerSigned(wire)
		if err != nil {
			t.Fatalf("UnmarshalIssuerSigned: %v", err)
		}
	}

	verified, err := Verify(signed, claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return claims.Signed.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verified.Status
}

// TestIssueVerifyRoundTrip_WithStatusList mirrors ISO/IEC 18013-5's own
// Annex D.6 "Status list example" worked values (idx 1340,
// https://example.com/statuslists/1) — §12.3.6.2/§12.3.6.5.
func TestIssueVerifyRoundTrip_WithStatusList(t *testing.T) {
	f := newFixture(t)
	status := issueAndVerifyWithStatus(t, f, false, func(c *Claims) {
		c.Status = &StatusListRef{
			Idx: 1340, URI: "https://example.com/statuslists/1", Certificate: []byte{0xaa, 0xbb, 0xcc},
		}
	})
	if status == nil || status.StatusList == nil {
		t.Fatalf("Status = %v, want a populated StatusList", status)
	}
	sl := status.StatusList
	if sl.Idx != 1340 {
		t.Errorf("Idx = %d, want 1340", sl.Idx)
	}
	if sl.URI != "https://example.com/statuslists/1" {
		t.Errorf("URI = %q, want https://example.com/statuslists/1", sl.URI)
	}
	if !bytes.Equal(sl.Certificate, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("Certificate = %x, want aabbcc", sl.Certificate)
	}
}

// TestIssueVerifyRoundTrip_WithIdentifierList mirrors ISO/IEC 18013-5's
// own Annex D.6 "Identifier list example" worked values (id 0xcccc,
// https://example.com/identifierlists/1) — §12.3.6.2/§12.3.6.4.
func TestIssueVerifyRoundTrip_WithIdentifierList(t *testing.T) {
	f := newFixture(t)
	status := issueAndVerifyWithStatus(t, f, false, func(c *Claims) {
		c.IdentifierList = &IdentifierListRef{
			ID: []byte{0xcc, 0xcc}, URI: "https://example.com/identifierlists/1", Certificate: []byte{0xaa, 0xbb, 0xcc},
		}
	})
	if status == nil || status.IdentifierList == nil {
		t.Fatalf("Status = %v, want a populated IdentifierList", status)
	}
	il := status.IdentifierList
	if !bytes.Equal(il.ID, []byte{0xcc, 0xcc}) {
		t.Errorf("ID = %x, want cccc", il.ID)
	}
	if il.URI != "https://example.com/identifierlists/1" {
		t.Errorf("URI = %q, want https://example.com/identifierlists/1", il.URI)
	}
	if !bytes.Equal(il.Certificate, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("Certificate = %x, want aabbcc", il.Certificate)
	}
	if status.StatusList != nil {
		t.Errorf("StatusList = %v, want nil", status.StatusList)
	}
}

// TestIssuerSignedMarshalUnmarshalRoundTrip_PreservesStatus mirrors
// TestIssuerSignedMarshalUnmarshalRoundTrip, checking that Status
// survives a full wire round trip too — it lives inside the already-signed
// IssuerAuth payload, so this exercises Verify's own MSO decoding on a
// value that actually came off the wire, not just the in-memory one
// Issue returned. TestIssuerSignedMarshalUnmarshalRoundTrip_PreservesIdentifierList
// is the identifier_list-mechanism sibling.
func TestIssuerSignedMarshalUnmarshalRoundTrip_PreservesStatus(t *testing.T) {
	f := newFixture(t)
	status := issueAndVerifyWithStatus(t, f, true, func(c *Claims) {
		c.Status = &StatusListRef{Idx: 42, URI: "https://example.com/statuslists/1"}
	})
	if status == nil || status.StatusList == nil || status.StatusList.Idx != 42 {
		t.Errorf("Status = %v", status)
	}
	if status.StatusList.Certificate != nil {
		t.Errorf("Certificate = %x, want nil (never set)", status.StatusList.Certificate)
	}
}

func TestIssuerSignedMarshalUnmarshalRoundTrip_PreservesIdentifierList(t *testing.T) {
	f := newFixture(t)
	status := issueAndVerifyWithStatus(t, f, true, func(c *Claims) {
		c.IdentifierList = &IdentifierListRef{ID: []byte{0xcc, 0xcc}, URI: "https://example.com/identifierlists/1"}
	})
	if status == nil || status.IdentifierList == nil || !bytes.Equal(status.IdentifierList.ID, []byte{0xcc, 0xcc}) {
		t.Errorf("Status = %v", status)
	}
	if status.IdentifierList.Certificate != nil {
		t.Errorf("Certificate = %x, want nil (never set)", status.IdentifierList.Certificate)
	}
}

// TestIssueRejectsStatusAndIdentifierListTogether checks this
// package's own conservative default of rejecting both status_list and
// identifier_list set at once — see Status's own doc comment (mso.go)
// for why that's this package's choice, not a literal §12.3.6 MUST.
func TestIssueRejectsStatusAndIdentifierListTogether(t *testing.T) {
	f := newFixture(t)
	claims := f.claims
	claims.Status = &StatusListRef{Idx: 1, URI: "https://example.com/statuslists/1"}
	claims.IdentifierList = &IdentifierListRef{ID: []byte{0xaa}, URI: "https://example.com/identifierlists/1"}
	if _, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}}); err == nil {
		t.Fatal("Issue: want error when both Status and IdentifierList are set")
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

	verified, err := Verify(signed, claims.DocType, issuerPub, cose.EdDSA, VerifyOptions{
		Now: func() time.Time { return claims.Signed.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verified.DeviceKey.(ed25519.PublicKey).Equal(devicePub) {
		t.Errorf("DeviceKey mismatch")
	}
}

// TestVerifyRejectsTamperedElementValue simulates real-world tampering
// — swapping in different bytes for an item, the way UnmarshalIssuerSigned
// would if the wire bytes it decoded had been altered — rather than
// mutating the decoded IssuerSignedItem.ElementValue directly. Verify
// always digests f.signed's cached rawItems (see IssuerSigned's doc
// comment), which mutating the exported NameSpaces field doesn't
// touch, so this is the only way to exercise the digest-mismatch path
// realistically.
func TestVerifyRejectsTamperedElementValue(t *testing.T) {
	f := newFixture(t)

	items := f.signed.NameSpaces["org.iso.18013.5.1"]
	var target IssuerSignedItem
	for _, item := range items {
		if item.ElementIdentifier == "family_name" {
			target = item
		}
	}
	target.ElementValue = "Tampered"
	tamperedBytes, err := issuerSignedItemBytes(target)
	if err != nil {
		t.Fatalf("issuerSignedItemBytes: %v", err)
	}
	for i, item := range items {
		if item.ElementIdentifier == "family_name" {
			f.signed.rawItems["org.iso.18013.5.1"][i] = tamperedBytes
		}
	}

	if _, err := Verify(f.signed, f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	}); err == nil {
		t.Errorf("Verify accepted a tampered element value")
	}
}

// TestVerifyRejectsTamperedElementValueOverWire is the same scenario
// as TestVerifyRejectsTamperedElementValue, but through an actual
// Marshal/UnmarshalIssuerSigned round trip, confirming the real wire
// path (not just direct field access available to this internal test
// package) rejects tampering too.
func TestVerifyRejectsTamperedElementValueOverWire(t *testing.T) {
	f := newFixture(t)

	items := f.signed.NameSpaces["org.iso.18013.5.1"]
	var target IssuerSignedItem
	for _, item := range items {
		if item.ElementIdentifier == "family_name" {
			target = item
		}
	}
	target.ElementValue = "Tampered"
	tamperedBytes, err := issuerSignedItemBytes(target)
	if err != nil {
		t.Fatalf("issuerSignedItemBytes: %v", err)
	}
	for i, item := range items {
		if item.ElementIdentifier == "family_name" {
			f.signed.rawItems["org.iso.18013.5.1"][i] = tamperedBytes
		}
	}

	wire, err := f.signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	if _, err := Verify(decoded, f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	}); err == nil {
		t.Errorf("Verify accepted a tampered element value received over the wire")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	f := newFixture(t)

	if _, err := Verify(f.signed, f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.ValidUntil.Add(time.Hour) },
	}); err == nil {
		t.Errorf("Verify accepted an expired MSO")
	}
}

func TestVerifyRejectsNotYetValid(t *testing.T) {
	f := newFixture(t)

	if _, err := Verify(f.signed, f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
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

	if _, err := Verify(f.signed, f.claims.DocType, &otherKey.PublicKey, cose.ES256, VerifyOptions{
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

	verified, err := Verify(decoded, f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
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

// TestMapValuedElementValueVerifiesReliably guards against the bug
// IssuerSigned's rawItems cache fixes: Go randomizes map iteration
// order per range, so encoding the same map-typed ElementValue twice
// (once for its digest, again to produce the wire bytes) could once
// produce different bytes and a spurious digest mismatch. Run several
// iterations, since the bug was probabilistic — a single run could
// pass by chance even with the bug present.
func TestMapValuedElementValueVerifiesReliably(t *testing.T) {
	for i := 0; i < 20; i++ {
		f := newFixture(t)
		claims := testClaims(t, &f.deviceKey.PublicKey)
		claims.NameSpaces["org.iso.18013.5.1"] = map[string]interface{}{
			"nested": map[string]interface{}{
				"alpha": 1, "bravo": 2, "charlie": 3, "delta": 4,
				"echo": 5, "foxtrot": 6, "golf": 7, "hotel": 8,
			},
		}
		signed, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}})
		if err != nil {
			t.Fatalf("iteration %d: Issue: %v", i, err)
		}

		// In-memory path (no wire round trip).
		if _, err := Verify(signed, claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
			Now: func() time.Time { return claims.Signed.Add(time.Hour) },
		}); err != nil {
			t.Fatalf("iteration %d: Verify (in-memory): %v", i, err)
		}

		// Wire round trip.
		wire, err := signed.Marshal()
		if err != nil {
			t.Fatalf("iteration %d: Marshal: %v", i, err)
		}
		decoded, err := UnmarshalIssuerSigned(wire)
		if err != nil {
			t.Fatalf("iteration %d: UnmarshalIssuerSigned: %v", i, err)
		}
		if _, err := Verify(decoded, claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
			Now: func() time.Time { return claims.Signed.Add(time.Hour) },
		}); err != nil {
			t.Fatalf("iteration %d: Verify (wire round trip): %v", i, err)
		}
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
