package verifier_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// pathsIssuerKeyResolver is an SDJWTVCIssuerChainResolver of a
// caller's own: it resolves the issuer's key, and reports chains as the
// paths it verified.
type pathsIssuerKeyResolver struct {
	fixedSDJWTVCIssuerKeyResolver
	chains [][]*x509.Certificate
}

func (r pathsIssuerKeyResolver) ResolveIssuerChains(context.Context, map[string]any) ([][]*x509.Certificate, error) {
	return r.chains, nil
}

// The issuer chain VerifyResponse reports, which trusted_authorities and
// status list binding decide on, is the resolver's first path whose
// leaf holds the key the credential verified with: a path to another
// key, even listed first, says nothing about who issued it.
func TestVerifyResponse_IssuerChainIsTheSigningKeys(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer CA")
	otherCA, otherCAKey := testcert.CA(t, "another CA")
	issuerCert, issuerKey := testcert.Leaf(t, "issuer", ca, caKey)
	otherCert, _ := testcert.Leaf(t, "another issuer", otherCA, otherCAKey)

	_, _, v := newTestVerifierWithConfig(t)
	query := testIdentityQuery(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: built.Nonce,
		IssuerKeys: pathsIssuerKeyResolver{
			fixedSDJWTVCIssuerKeyResolver: fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
			chains:                        [][]*x509.Certificate{{otherCert, otherCA}, {issuerCert, ca}},
		},
		MaxKeyBindingAge: time.Hour,
	})
	vc := testverify.RequireOneCredential(t, result, err, "identity_credential")
	if len(vc.IssuerChain) != 1 || !bytes.Equal(vc.IssuerChain[0], issuerCert.Raw) {
		t.Errorf("IssuerChain has %d certificates, want the issuer's leaf alone (its path without the anchor)", len(vc.IssuerChain))
	}
}
