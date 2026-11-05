package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

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
		if got, _, err := CheckX5C(jwt, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil || got != want {
			t.Errorf("CheckX5C(idx %d) = %v, %v; want %v", idx, got, err, want)
		}
		if got, _, err := CheckCWTX5Chain(cwt, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil || got != want {
			t.Errorf("CheckCWTX5Chain(idx %d) = %v, %v; want %v", idx, got, err, want)
		}
		if got, _, err := CheckCWTX5Chain(cwt[1:], roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil || got != want {
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
	// IssueTokenX5C won't sign with a self-signed certificate, so the
	// token is signed directly.
	selfJWT, err := issueToken(selfSignedKey, jose.ES256, claims, map[string]any{
		"typ": TokenTyp, "x5c": []any{base64.StdEncoding.EncodeToString(selfSigned.Raw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckX5C(jwt, untrusted, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CheckX5C accepted a chain that doesn't verify to roots")
	}
	if _, _, err := CheckCWTX5Chain(cwt, untrusted, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CheckCWTX5Chain accepted a chain that doesn't verify to roots")
	}
	if _, _, err := CheckX5C(selfJWT, selfRoots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CheckX5C accepted a self-signed signer")
	}
	other := StatusListRef{Idx: 0, URI: "https://issuer.example.com/statuslists/2"}
	if _, _, err := CheckX5C(jwt, roots, other, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CheckX5C accepted another list's token")
	}
	if _, err := IssueTokenX5C(selfSignedKey, jose.ES256, claims, []*x509.Certificate{leaf}); err == nil {
		t.Error("IssueTokenX5C accepted a chain that isn't the signer's")
	}
	if _, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, claims, nil); err == nil {
		t.Error("IssueTokenCWTX5Chain accepted an empty chain")
	}
	refuse := VerifyOptions{UnboundSigner: AnyListSigner, LeafPolicy: func(*x509.Certificate, [][]*x509.Certificate) error {
		return errors.New("not this credential's issuer")
	}}
	if _, _, err := CheckX5C(jwt, roots, ref, refuse); err == nil {
		t.Error("CheckX5C accepted a signer its LeafPolicy refused")
	}
	if _, _, err := CheckCWTX5Chain(cwt, roots, ref, refuse); err == nil {
		t.Error("CheckCWTX5Chain accepted a signer its LeafPolicy refused")
	}
	if _, _, err := CheckX5C("not.a.token", roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CheckX5C accepted a malformed token")
	}
	if _, _, err := CheckCWTX5Chain([]byte("not cbor"), roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CheckCWTX5Chain accepted a malformed token")
	}
}

// issuerSigner is a certificate under ca naming issuer, and its key.
func issuerSigner(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, issuer string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// With VerifyOptions.Issuer set, a Status List Token signed by another
// issuer's certificate under the same roots is refused, as is one whose
// own iss is another issuer's: an issuer's status is its own to sign.
func TestX5C_SignerIsTheIssuer(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	const issuerA, issuerB = "https://issuer-a.example", "https://issuer-b.example"
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	token := func(issuer, iss string) string {
		t.Helper()
		cert, key := issuerSigner(t, ca, caKey, issuer)
		claims := TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}
		if iss != "" {
			claims.Additional = map[string]any{"iss": iss}
		}
		jwt, err := IssueTokenX5C(key, jose.ES256, claims, []*x509.Certificate{cert})
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	opts := VerifyOptions{UnboundSigner: AnyListSigner, Issuer: issuerA}
	if _, _, err := CheckX5C(token(issuerA, issuerA), roots, ref, opts); err != nil {
		t.Errorf("issuer A's own list: %v", err)
	}
	if _, _, err := CheckX5C(token(issuerB, ""), roots, ref, opts); err == nil {
		t.Error("accepted issuer A's status signed by issuer B's certificate")
	}
	if _, _, err := CheckX5C(token(issuerA, issuerB), roots, ref, opts); err == nil {
		t.Error("accepted a list whose iss is another issuer's")
	}
	if _, _, err := CheckX5C(token(issuerB, ""), roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("without Issuer, the signer isn't bound: %v", err)
	}
}

// A Status List Token signed with the key that signed the Referenced
// Token is the issuer's own, whatever its certificate names (the
// same-key arrangement of draft-ietf-oauth-status-list §11.3): the EU
// reference PID issuer's certificates name no one. A token from
// another key that names no one is still refused.
func TestX5C_SignerHoldsTheIssuersKey(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	unnamed := func(key *ecdsa.PrivateKey) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	token := func(key *ecdsa.PrivateKey) string {
		t.Helper()
		jwt, err := IssueTokenX5C(key, jose.ES256, TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}, []*x509.Certificate{unnamed(key)})
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	credentialKey, otherKey := testKey(t), testKey(t)
	opts := VerifyOptions{UnboundSigner: AnyListSigner, Issuer: "https://backend.issuer.example", IssuerKey: &credentialKey.PublicKey}
	if _, _, err := CheckX5C(token(credentialKey), roots, ref, opts); err != nil {
		t.Errorf("signed with the credential's own key: %v", err)
	}
	if _, _, err := CheckX5C(token(otherKey), roots, ref, opts); err == nil {
		t.Error("accepted a list signed by another key whose certificate names no one")
	}
}

// The publisher won't sign with a chain HAIP 1.0 §6.1 forbids: a
// self-signed signing certificate, or one that carries its trust anchor.
func TestIssueTokenX5C_RefusesForbiddenChains(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	leaf, leafKey := testcert.Leaf(t, "status signer", ca, caKey)
	selfSigned, selfKey := testcert.SelfSignedLeaf(t, "self-signed signer")
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	claims := TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}
	if _, err := IssueTokenX5C(leafKey, jose.ES256, claims, []*x509.Certificate{leaf}); err != nil {
		t.Errorf("a CA-issued signer: %v", err)
	}
	if _, err := IssueTokenX5C(leafKey, jose.ES256, claims, []*x509.Certificate{leaf, ca}); err == nil {
		t.Error("signed with the trust anchor in x5c")
	}
	if _, err := IssueTokenX5C(selfKey, jose.ES256, claims, []*x509.Certificate{selfSigned}); err == nil {
		t.Error("signed with a self-signed certificate")
	}
}

// IssuerKey binds a CWT token's signer as it binds a JWT token's: a
// list signed by another key under the same roots is refused.
func TestCheckCWTX5Chain_HonorsIssuerKey(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	_, otherKey := testcert.Leaf(t, "another issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	cwt, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	ref := StatusListRef{URI: x5cTestURI}
	if _, _, err := CheckCWTX5Chain(cwt, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner, IssuerKey: &leafKey.PublicKey}); err != nil {
		t.Errorf("signed by the issuer's key: %v", err)
	}
	if _, _, err := CheckCWTX5Chain(cwt, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner, IssuerKey: &otherKey.PublicKey}); err == nil {
		t.Error("a list another key signed was accepted for this issuer")
	}
}

// An unprotected x5chain is accepted (RFC 9360), unless
// X5ChainProtectedOnly asks for ISO/IEC 18013-5 §12.3.6.3's protected one.
func TestCheckCWTX5Chain_X5ChainProtectedOnly(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	cwtSL, err := toCWTStatusList(sl)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cbor.Marshal(map[int]any{cwtClaimSub: x5cTestURI, cwtClaimIat: time.Now().Unix(), cwtClaimStatusList: cwtSL})
	if err != nil {
		t.Fatal(err)
	}
	token, err := cose.SignTagged(cose.ES256, leafKey, cose.Headers{Typ: CWTTokenMediaType}, cose.Headers{X5Chain: [][]byte{leaf.Raw}}, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := StatusListRef{URI: x5cTestURI}
	if _, _, err := CheckCWTX5Chain(token, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("unprotected x5chain: %v", err)
	}
	if _, _, err := CheckCWTX5Chain(token, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner, X5ChainProtectedOnly: true}); err == nil {
		t.Error("unprotected x5chain accepted with X5ChainProtectedOnly")
	}
	// A Cache's memo of it is refused alike.
	ctx := context.Background()
	m, err := verifyMemo(ctx, token, true, roots, x5cTestURI, VerifyOptions{UnboundSigner: AnyListSigner})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.recheck(ctx, roots, x5cTestURI, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("unprotected x5chain, cached: %v", err)
	}
	if err := m.recheck(ctx, roots, x5cTestURI, VerifyOptions{UnboundSigner: AnyListSigner, X5ChainProtectedOnly: true}); err == nil {
		t.Error("unprotected x5chain accepted with X5ChainProtectedOnly, cached")
	}
}
