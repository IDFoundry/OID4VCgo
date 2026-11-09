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

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// Signed metadata whose typ isn't the metadata JWT's, or whose x5c is a
// trusted signer's but whose signature is another key's, is refused,
// though its chain and claims are valid.
func TestFetchCredentialIssuerMetadata_SignedHeader(t *testing.T) {
	root, rootKey := testcert.CA(t, "metadata root")
	leaf, leafKey := testcert.Leaf(t, "metadata signer", root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	forgerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x5c := []string{base64.StdEncoding.EncodeToString(leaf.Raw)}
	for name, tc := range map[string]struct {
		key    *ecdsa.PrivateKey
		header map[string]any
		want   string // "" accepted
	}{
		"valid":                  {leafKey, map[string]any{"typ": issuer.MetadataJWSTyp, "x5c": x5c}, ""},
		"no typ":                 {leafKey, map[string]any{"x5c": x5c}, "typ"},
		"typ JWT":                {leafKey, map[string]any{"typ": "JWT", "x5c": x5c}, "typ"},
		"a Request Object's typ": {leafKey, map[string]any{"typ": "oauth-authz-req+jwt", "x5c": x5c}, "typ"},
		"signed by another key":  {forgerKey, map[string]any{"typ": issuer.MetadataJWSTyp, "x5c": x5c}, "signature verification failed"},
	} {
		issuerURL := serveMetadata(t, func(issuerURL, _ string) (string, string) {
			body, _ := json.Marshal(testMetadata(t, issuerURL))
			claims := map[string]any{}
			_ = json.Unmarshal(body, &claims)
			claims["sub"], claims["iat"] = issuerURL, time.Now().Unix()
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			token, err := jose.Sign(jose.ES256, tc.key, tc.header, payload)
			if err != nil {
				t.Fatal(err)
			}
			return "application/jwt", token
		})
		_, err := signedMetadataWallet(t, roots, true).FetchCredentialIssuerMetadata(t.Context(), issuerURL)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v, want accepted", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want one mentioning %q", name, err, tc.want)
		}
	}
}
