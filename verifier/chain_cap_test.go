package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// Chains that verify but are refused for revocation, or by the leaf
// policy, come from a CA the Verifier trusts and aren't counted toward
// MaxFailedIssuerChainsPerResponse: an honest response presenting more
// such credentials than the limit, before a valid one, is verified,
// whatever their order, the others discarded. Chains no root anchors
// still are counted, so more than the limit of them refuses the
// response, even beside a valid credential.
func TestVerifyResponse_RefusedTrustedChainsArentCapped(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	other, otherKey := testcert.CA(t, "a root this verifier doesn't trust")
	n := verifier.MaxFailedIssuerChainsPerResponse + 1
	type issuer struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}
	var revoked []*x509.Certificate
	var revokedIssuers, refusedIssuers, untrusted []issuer
	for i := range n {
		c, k := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(int64(100 + i)), Subject: pkix.Name{CommonName: fmt.Sprintf("revoked issuer %d", i)}}, ca, caKey)
		revoked = append(revoked, c)
		revokedIssuers = append(revokedIssuers, issuer{c, k})
		c, k = testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(int64(200 + i)), Subject: pkix.Name{CommonName: fmt.Sprintf("refused issuer %d", i)}}, ca, caKey)
		refusedIssuers = append(refusedIssuers, issuer{c, k})
		c, k = testcert.Leaf(t, fmt.Sprintf("foreign issuer %d", i), other, otherKey)
		untrusted = append(untrusted, issuer{c, k})
	}
	good, goodKey := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(300), Subject: pkix.Name{CommonName: "valid issuer"}}, ca, caKey)
	policy := func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		if strings.HasPrefix(leaf.Subject.CommonName, "refused") {
			return errors.New("not an issuer of this type")
		}
		return nil
	}
	resolver := verifier.X5CIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: policy, Revocation: testcert.CRLs(t, ca, caKey, revoked...)}

	_, _, v := newTestVerifierWithConfig(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: multipleQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	present := func(issuers []issuer) []string {
		var out []string
		for _, iss := range issuers {
			out = append(out, keyBoundPresentation(t, testVCT, sdjwtvc.IssueOptions{IssuerCertificate: iss.cert}, iss.key, v.ClientID(), built.Nonce))
		}
		return out
	}
	valid := keyBoundPresentation(t, testVCT, sdjwtvc.IssueOptions{IssuerCertificate: good}, goodKey, v.ClientID(), built.Nonce)
	verify := func(presentations []string) (verifier.VerifyResponseResult, error) {
		return v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: multipleQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
			ExpectedNonce: built.Nonce, MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
		})
	}

	for _, c := range []struct {
		name          string
		presentations []string
	}{
		{"revoked, then valid", append(present(revokedIssuers), valid)},
		{"refused by the leaf policy, then valid", append(present(refusedIssuers), valid)},
		{"valid, then revoked", append([]string{valid}, present(revokedIssuers)...)},
	} {
		res, err := verify(c.presentations)
		if err != nil || len(res.Credentials) != 1 || len(res.Discarded) != n {
			t.Errorf("%s: %d verified, %d discarded, %v; want 1 and %d", c.name, len(res.Credentials), len(res.Discarded), err, n)
		}
	}
	_, err = verify(append(present(untrusted), valid))
	var vErr *verifier.Error
	if !errors.As(err, &vErr) || vErr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), "failed to verify") {
		t.Errorf("untrusted, then valid: %v; want the response refused for its failed chains", err)
	}
}
