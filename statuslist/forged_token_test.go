package statuslist

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// forgedTokenClaims are a Status List Token's claims for x5cTestURI:
// index 0 revoked in the issuer's, valid in a forger's.
func forgedTokenClaims(t *testing.T, status uint8) TokenClaims {
	t.Helper()
	sl, err := New(Bits1, []uint8{status}, "")
	if err != nil {
		t.Fatal(err)
	}
	return TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}
}

// A Status List Token not signed by the issuer's key is refused, in
// either format, however valid it otherwise is: one signed by another
// key, or the issuer's with its payload or signature changed. A forged
// list could otherwise report a revoked credential valid.
func TestCheck_RefusesTokenNotSignedByTheIssuer(t *testing.T) {
	issuerKey, forgerKey := testKey(t), testKey(t)
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	opts := VerifyOptions{UnboundSigner: AnyListSigner}
	revoked, valid := forgedTokenClaims(t, 1), forgedTokenClaims(t, 0)

	jwt, err := IssueToken(issuerKey, jose.ES256, revoked, "")
	if err != nil {
		t.Fatal(err)
	}
	if status, _, err := Check(jwt, &issuerKey.PublicKey, jose.ES256, ref, opts); err != nil || status != StatusInvalid {
		t.Fatalf("the issuer's JWT: Check = %v, %v; want %v", status, err, StatusInvalid)
	}
	forgedJWT, err := IssueToken(forgerKey, jose.ES256, valid, "")
	if err != nil {
		t.Fatal(err)
	}
	parts, forgedParts := strings.Split(jwt, "."), strings.Split(forgedJWT, ".")
	for name, token := range map[string]string{
		"another key":     forgedJWT,
		"changed payload": parts[0] + "." + forgedParts[1] + "." + parts[2],
	} {
		_, _, err := Check(token, &issuerKey.PublicKey, jose.ES256, ref, opts)
		if err == nil || !strings.Contains(err.Error(), "verify token signature") {
			t.Errorf("JWT, %s: Check = %v, want a signature refusal", name, err)
		}
	}

	cwt, err := IssueTokenCWT(issuerKey, cose.ES256, revoked, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, err := CheckCWT(cwt, &issuerKey.PublicKey, cose.ES256, ref, opts); err != nil || status != StatusInvalid {
		t.Fatalf("the issuer's CWT: CheckCWT = %v, %v; want %v", status, err, StatusInvalid)
	}
	forgedCWT, err := IssueTokenCWT(forgerKey, cose.ES256, valid, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The signature is the COSE_Sign1's last element.
	changedSig := append([]byte{}, cwt...)
	changedSig[len(changedSig)-1] ^= 1
	for name, token := range map[string][]byte{
		"another key":       forgedCWT,
		"changed signature": changedSig,
	} {
		_, _, err := CheckCWT(token, &issuerKey.PublicKey, cose.ES256, ref, opts)
		if err == nil || !strings.Contains(err.Error(), "verify CWT signature") {
			t.Errorf("CWT, %s: CheckCWT = %v, want a signature refusal", name, err)
		}
	}
}

// A Status List Token carrying the issuer's trusted certificate chain
// but signed by another key is refused, in either format: the chain
// names a signer, it doesn't vouch for whoever attached it.
func TestCheckX5C_RefusesTokenNotSignedByTheLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	forgerKey := testKey(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	opts := VerifyOptions{UnboundSigner: AnyListSigner}
	revoked, valid := forgedTokenClaims(t, 1), forgedTokenClaims(t, 0)

	jwt, err := IssueTokenX5C(leafKey, jose.ES256, revoked, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	if status, _, err := CheckX5C(jwt, roots, ref, opts); err != nil || status != StatusInvalid {
		t.Fatalf("the leaf's JWT: CheckX5C = %v, %v; want %v", status, err, StatusInvalid)
	}
	forgedJWT, err := issueToken(forgerKey, jose.ES256, valid, map[string]any{
		"typ": TokenTyp, "x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckX5C(forgedJWT, roots, ref, opts); err == nil || !strings.Contains(err.Error(), "verify token signature") {
		t.Errorf("CheckX5C = %v, want a signature refusal", err)
	}

	cwt, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, revoked, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	if status, _, err := CheckCWTX5Chain(cwt, roots, ref, opts); err != nil || status != StatusInvalid {
		t.Fatalf("the leaf's CWT: CheckCWTX5Chain = %v, %v; want %v", status, err, StatusInvalid)
	}
	forgedCWT, err := issueTokenCWT(forgerKey, cose.ES256, valid, cose.Headers{Typ: CWTTokenMediaType, X5Chain: [][]byte{leaf.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckCWTX5Chain(forgedCWT, roots, ref, opts); err == nil || !strings.Contains(err.Error(), "verify CWT signature") {
		t.Errorf("CheckCWTX5Chain = %v, want a signature refusal", err)
	}
}
