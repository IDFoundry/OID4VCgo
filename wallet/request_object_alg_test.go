package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A Request Object signed ES384 or ES512 (the EUDI reference verifier
// signs ES512 by default) by a trusted P-384 or P-521 certificate is
// accepted (OID4VP 1.0 §5.9.3; HAIP 1.0 §7 makes ES256 a minimum), and
// one whose alg isn't the one its certificate's key takes is refused.
func TestParseAuthorizationRequest_ES384ES512(t *testing.T) {
	v, _, _ := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t), State: "s1"})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	_, payload, err := jose.DecodeUnverified(built.RequestObject)
	if err != nil {
		t.Fatal(err)
	}
	ca, caKey := testcert.CA(t, "request object alg test CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	trust := wallet.X5CVerifierRoots{Roots: roots}

	// resign signs the built request's claims with key under alg, as the
	// Verifier whose certificate (from ca) holds signerKey's public key.
	resign := func(alg string, key, signerKey *ecdsa.PrivateKey) (string, string) {
		leaf := testcert.LeafFor(t, "verifier "+alg, &signerKey.PublicKey, ca, caKey)
		sum := sha256.Sum256(leaf.Raw)
		clientID := "x509_hash:" + base64.RawURLEncoding.EncodeToString(sum[:])
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		claims["client_id"] = clientID
		return testjose.SignClaims(t, alg, key, map[string]any{
			"typ": "oauth-authz-req+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
		}, claims), clientID
	}
	gen := func(c elliptic.Curve) *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	p256, p384, p521 := gen(elliptic.P256()), gen(elliptic.P384()), gen(elliptic.P521())

	for name, tc := range map[string]struct {
		alg       string
		key, cert *ecdsa.PrivateKey
		want      string
	}{
		"ES384 by P-384":                 {"ES384", p384, p384, ""},
		"ES512 by P-521":                 {"ES512", p521, p521, ""},
		"ES512 header, P-384 key":        {"ES512", p384, p384, "ES512 requires a P-521 public key"},
		"ES384 header, P-521 key":        {"ES384", p521, p521, "ES384 requires a P-384 public key"},
		"ES256 header, P-384 key":        {"ES256", p384, p384, "ES256 requires a P-256 public key"},
		"ES512 by P-521, P-256 cert":     {"ES512", p521, p256, "ES512 requires a P-521 public key"},
		"ES512 by another P-521 key":     {"ES512", gen(elliptic.P521()), p521, "ES512 signature verification failed"},
		"ES384 by P-384, P-521 cert key": {"ES384", p384, p521, "ES384 requires a P-384 public key"},
	} {
		t.Run(name, func(t *testing.T) {
			requestObject, clientID := resign(tc.alg, tc.key, tc.cert)
			got, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
				RequestObject: requestObject, ClientID: clientID, VerifierTrust: trust,
			})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ParseAuthorizationRequest: %v", err)
				}
				if got.ClientID != clientID || got.State != "s1" || got.Nonce != built.Nonce {
					t.Errorf("got %+v", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseAuthorizationRequest = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
