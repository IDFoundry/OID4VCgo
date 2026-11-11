package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// Signed Credential Issuer Metadata (OID4VCI 1.0 §12.2.3) signed ES384
// by a P-384 certificate or ES512 by a P-521 one is used; signed under
// an alg its certificate's key doesn't take, it isn't.
func TestFetchCredentialIssuerMetadata_SignedES384ES512(t *testing.T) {
	root, rootKey := testcert.CA(t, "metadata root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for name, tc := range map[string]struct {
		alg   string
		curve elliptic.Curve
		want  string
	}{
		"ES384 by P-384": {"ES384", elliptic.P384(), ""},
		"ES512 by P-521": {"ES512", elliptic.P521(), ""},
		"ES512 by P-384": {"ES512", elliptic.P384(), "ES512 requires a P-521 public key"},
		"ES384 by P-256": {"ES384", elliptic.P256(), "ES384 requires a P-384 public key"},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := testcert.LeafFor(t, "metadata signer", &key.PublicKey, root, rootKey)
			issuerURL := serveMetadata(t, func(issuerURL, _ string) (string, string) {
				body, _ := json.Marshal(testMetadata(t, issuerURL))
				claims := map[string]any{}
				_ = json.Unmarshal(body, &claims)
				claims["sub"], claims["iat"] = issuerURL, time.Now().Unix()
				return "application/jwt", testjose.SignClaims(t, tc.alg, key, map[string]any{
					"typ": issuer.MetadataJWSTyp, "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
				}, claims)
			})
			got, err := signedMetadataWallet(t, roots, true).FetchCredentialIssuerMetadata(t.Context(), issuerURL)
			if tc.want == "" {
				if err != nil || got.CredentialIssuer.String() != issuerURL {
					t.Fatalf("FetchCredentialIssuerMetadata = %+v, %v", got.CredentialIssuer, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("FetchCredentialIssuerMetadata = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
