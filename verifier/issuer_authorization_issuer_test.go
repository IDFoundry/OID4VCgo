package verifier_test

import (
	"context"
	"crypto"
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

// ownKeyResolver embeds an X5CIssuerKeyResolver, and with it its
// BindsIssuerName, but resolves keys its own way: without checking the
// credential's iss, whatever RequireIssuerName says.
type ownKeyResolver struct{ verifier.X5CIssuerKeyResolver }

func (r ownKeyResolver) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, jose.Alg, error) {
	unnamed := r.X5CIssuerKeyResolver
	unnamed.RequireIssuerName = false
	return unnamed.ResolveIssuerKey(ctx, header, payload)
}

// IssuerAuthorization.Issuer is the credential's iss only when the key
// resolver checked the certificate names it; ClaimedIssuer is the iss
// either way. An issuer under the same roots writing another's iss
// can't pass a hook that allows issuers by name, even through a
// resolver that embeds an X5CIssuerKeyResolver with RequireIssuerName
// but resolves keys its own way.
func TestIssuerAuthorized_IssuerOnlyWhenChecked(t *testing.T) {
	const iss, other = "https://issuer-b.example", "https://issuer-c.example"
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

	named := verifier.X5CIssuerKeyResolver{Roots: roots, RequireIssuerName: true, Revocation: certrevocation.NoCheck{}}
	for name, tc := range map[string]struct {
		keys        verifier.SDJWTVCIssuerKeyResolver
		iss, issuer string
	}{
		"default":                                     {verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}, iss, ""},
		"RequireIssuerName":                           {named, iss, iss},
		"embedded, the certificate's iss":             {ownKeyResolver{named}, iss, iss},
		"embedded, an iss it doesn't name":            {ownKeyResolver{named}, other, ""},
		"embedded by pointer, an iss it doesn't name": {&ownKeyResolver{named}, other, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var seen verifier.IssuerAuthorization
			f := newTxFixture(t, func(c *verifier.TransactionsConfig) {
				c.Verify.IssuerKeys = tc.keys
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
				VCT: "urn:tx:1", Iss: tc.iss, CNF: map[string]any{"jwk": holderJWK},
				Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
			}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
			if err != nil {
				t.Fatal(err)
			}
			f.held = wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}
			if _, err := f.txs.HandleResponse(context.Background(), f.answer(f.begin("browser-binding-A", false), nil)); err != nil {
				t.Fatalf("HandleResponse: %v", err)
			}
			if seen.Issuer != tc.issuer || seen.ClaimedIssuer != tc.iss {
				t.Errorf("Issuer = %q, ClaimedIssuer = %q; want %q and %q", seen.Issuer, seen.ClaimedIssuer, tc.issuer, tc.iss)
			}
			if !slices.Equal(seen.MatchedTypes, []string{"urn:tx:1"}) {
				t.Errorf("MatchedTypes = %v, want [urn:tx:1]", seen.MatchedTypes)
			}
		})
	}
}
