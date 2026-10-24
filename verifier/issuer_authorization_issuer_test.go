package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// IssuerAuthorization.Issuer is the credential's iss only when the key
// resolver checked the certificate names it; ClaimedIssuer is the iss
// either way. An issuer under the same roots writing another's iss
// can't pass a hook that allows issuers by name.
func TestIssuerAuthorized_IssuerOnlyWhenChecked(t *testing.T) {
	const iss = "https://issuer-b.example"
	ca, caKey := testcert.CA(t, "issuer CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(iss)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	for name, requireName := range map[string]bool{"default": false, "RequireIssuerName": true} {
		t.Run(name, func(t *testing.T) {
			var seen verifier.IssuerAuthorization
			f := newTxFixture(t, func(c *verifier.TransactionsConfig) {
				c.Verify.IssuerKeys = verifier.X5CIssuerKeyResolver{Roots: roots, RequireIssuerName: requireName, Revocation: certrevocation.NoCheck{}}
				c.Verify.IssuerAuthorized = func(_ context.Context, a verifier.IssuerAuthorization) error {
					seen = a
					return nil
				}
			})
			holderKey := testP256Key(t)
			holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			cred, _, err := sdjwtvc.Issue(key, jose.ES256, sdjwtvc.Claims{
				VCT: "urn:tx:1", Iss: iss, CNF: map[string]any{"jwk": holderJWK},
				Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
			}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
			if err != nil {
				t.Fatal(err)
			}
			f.held = wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}
			if _, err := f.txs.HandleResponse(context.Background(), f.answer(f.begin("browser-binding-A", false), nil)); err != nil {
				t.Fatalf("HandleResponse: %v", err)
			}
			want := ""
			if requireName {
				want = iss
			}
			if seen.Issuer != want || seen.ClaimedIssuer != iss {
				t.Errorf("Issuer = %q, ClaimedIssuer = %q; want %q and %q", seen.Issuer, seen.ClaimedIssuer, want, iss)
			}
			if !slices.Equal(seen.MatchedTypes, []string{"urn:tx:1"}) {
				t.Errorf("MatchedTypes = %v, want [urn:tx:1]", seen.MatchedTypes)
			}
		})
	}
}
