package statuslist

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

const x5cTestURI = "https://issuer.example.com/statuslists/1"

// TestX5C_RoundTrips issues a Status List Token carrying its signer's
// certificate chain, in each format, and checks it against the CA that
// issued the signer: index 1 is revoked, index 0 valid.
func TestX5C_RoundTrips(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0, 1}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claims := TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}

	jwt, err := IssueTokenX5C(leafKey, jose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatalf("IssueTokenX5C: %v", err)
	}
	cwt, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatalf("IssueTokenCWTX5Chain: %v", err)
	}
	for idx, want := range map[uint64]StatusType{0: StatusValid, 1: StatusInvalid} {
		ref := StatusListRef{Idx: idx, URI: x5cTestURI}
		if got, _, err := CheckX5C(jwt, roots, ref, VerifyOptions{}); err != nil || got != want {
			t.Errorf("CheckX5C(idx %d) = %v, %v; want %v", idx, got, err, want)
		}
		if got, _, err := CheckCWTX5Chain(cwt, roots, ref, VerifyOptions{}); err != nil || got != want {
			t.Errorf("CheckCWTX5Chain(idx %d) = %v, %v; want %v", idx, got, err, want)
		}
		if got, _, err := CheckCWTX5Chain(cwt[1:], roots, ref, VerifyOptions{}); err != nil || got != want {
			t.Errorf("CheckCWTX5Chain(untagged, idx %d) = %v, %v; want %v", idx, got, err, want)
		}
	}
}

// TestX5C_Rejects checks a token is refused when its chain doesn't verify
// to roots, its signer is self-signed, or it's another list's; and that
// issuing refuses a chain that isn't the signer's.
func TestX5C_Rejects(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	otherCA, _ := testcert.CA(t, "another CA")
	selfSigned, selfSignedKey := testcert.SelfSignedLeaf(t, "self-signed signer")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	untrusted := x509.NewCertPool()
	untrusted.AddCert(otherCA)
	selfRoots := x509.NewCertPool()
	selfRoots.AddCert(selfSigned)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claims := TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}

	jwt, err := IssueTokenX5C(leafKey, jose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	cwt, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	selfJWT, err := IssueTokenX5C(selfSignedKey, jose.ES256, claims, []*x509.Certificate{selfSigned})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckX5C(jwt, untrusted, ref, VerifyOptions{}); err == nil {
		t.Error("CheckX5C accepted a chain that doesn't verify to roots")
	}
	if _, _, err := CheckCWTX5Chain(cwt, untrusted, ref, VerifyOptions{}); err == nil {
		t.Error("CheckCWTX5Chain accepted a chain that doesn't verify to roots")
	}
	if _, _, err := CheckX5C(selfJWT, selfRoots, ref, VerifyOptions{}); err == nil {
		t.Error("CheckX5C accepted a self-signed signer")
	}
	other := StatusListRef{Idx: 0, URI: "https://issuer.example.com/statuslists/2"}
	if _, _, err := CheckX5C(jwt, roots, other, VerifyOptions{}); err == nil {
		t.Error("CheckX5C accepted another list's token")
	}
	if _, err := IssueTokenX5C(selfSignedKey, jose.ES256, claims, []*x509.Certificate{leaf}); err == nil {
		t.Error("IssueTokenX5C accepted a chain that isn't the signer's")
	}
	if _, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, claims, nil); err == nil {
		t.Error("IssueTokenCWTX5Chain accepted an empty chain")
	}
	refuse := VerifyOptions{LeafPolicy: func(*x509.Certificate, [][]*x509.Certificate) error {
		return errors.New("not this credential's issuer")
	}}
	if _, _, err := CheckX5C(jwt, roots, ref, refuse); err == nil {
		t.Error("CheckX5C accepted a signer its LeafPolicy refused")
	}
	if _, _, err := CheckCWTX5Chain(cwt, roots, ref, refuse); err == nil {
		t.Error("CheckCWTX5Chain accepted a signer its LeafPolicy refused")
	}
	if _, _, err := CheckX5C("not.a.token", roots, ref, VerifyOptions{}); err == nil {
		t.Error("CheckX5C accepted a malformed token")
	}
	if _, _, err := CheckCWTX5Chain([]byte("not cbor"), roots, ref, VerifyOptions{}); err == nil {
		t.Error("CheckCWTX5Chain accepted a malformed token")
	}
}
