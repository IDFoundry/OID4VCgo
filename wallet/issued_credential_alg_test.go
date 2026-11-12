package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// resignSDJWT re-signs sdjwt's Issuer-signed JWT under alg with key,
// carrying leaf in x5c; its payload, and so its Disclosures, stay as
// they are.
func resignSDJWT(t testing.TB, sdjwt, alg string, key *ecdsa.PrivateKey, leaf *x509.Certificate) string {
	t.Helper()
	issuerJWT, rest, _ := strings.Cut(sdjwt, "~")
	header, payload, err := jose.DecodeUnverified(issuerJWT)
	if err != nil {
		t.Fatal(err)
	}
	header["x5c"] = []string{base64.StdEncoding.EncodeToString(leaf.Raw)}
	return testjose.Sign(t, alg, key, header, payload) + "~" + rest
}

// An SD-JWT VC an Issuer signed ES384 with a P-384 certificate, or
// ES512 with a P-521 one, is accepted on receipt (the EUDI PID issuer
// picks the algorithm by its key's curve); one whose alg isn't the one
// its certificate's key takes is refused.
func TestVerifyIssuedCredential_ES384ES512(t *testing.T) {
	f := caIssuedFixture(t)
	ca, caKey := testcert.CA(t, "issued credential alg test CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for name, tc := range map[string]struct {
		alg   string
		curve elliptic.Curve
		want  string
	}{
		"ES384 by P-384": {"ES384", elliptic.P384(), ""},
		"ES512 by P-521": {"ES512", elliptic.P521(), ""},
		"ES512 by P-384": {"ES512", elliptic.P384(), `header alg "ES512" does not match expected "ES384"`},
		"ES256 by P-521": {"ES256", elliptic.P521(), `header alg "ES256" does not match expected "ES512"`},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := testcert.LeafFor(t, "issuer "+name, &key.PublicKey, ca, caKey)
			got, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
				Configuration: f.sdjwtConf, Credential: resignSDJWT(t, f.sdjwt, tc.alg, key, leaf),
				HolderKey: &f.holder.PublicKey, IssuerRoots: roots,
			})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("VerifyIssuedCredential: %v", err)
				}
				if got.Claims["given_name"] != "Alice" {
					t.Errorf("given_name = %v", got.Claims["given_name"])
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("VerifyIssuedCredential = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
