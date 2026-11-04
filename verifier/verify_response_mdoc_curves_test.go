package verifier_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An OpenID4VP mdoc presentation whose IssuerAuth is signed on P-384 or
// P-521 verifies with ES384 or ES512, and its device signature with
// the algorithm of the MSO device key's curve; IssuerAuth resolved
// under another algorithm than its key's is refused.
func TestVerifyMdocResponseNISTCurves(t *testing.T) {
	for _, tc := range []struct {
		name           string
		issuer, device elliptic.Curve
		alg            cose.Alg
	}{
		{"P-384 issuer, P-384 device", elliptic.P384(), elliptic.P384(), cose.ES384},
		{"P-521 issuer, P-256 device", elliptic.P521(), elliptic.P256(), cose.ES512},
		{"P-256 issuer, P-521 device", elliptic.P256(), elliptic.P521(), cose.ES256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mf := newMdocVerifyFixture(t)
			mf.f = testmdoc.IssueOn(t, tc.issuer, tc.device)
			result, err := mf.verifyWith(t, mf.nonce, func(req *verifier.VerifyResponseRequest) {
				req.MdocIssuerKeys = fixedMdocIssuerKeyResolver{pub: &mf.f.IssuerKey.PublicKey, alg: tc.alg}
			})
			assertMdocGivenNameAlice(t, result, err)
			for _, wrong := range []cose.Alg{cose.ES256, cose.ES384, cose.ES512} {
				if wrong == tc.alg {
					continue
				}
				if _, err := mf.verifyWith(t, mf.nonce, func(req *verifier.VerifyResponseRequest) {
					req.MdocIssuerKeys = fixedMdocIssuerKeyResolver{pub: &mf.f.IssuerKey.PublicKey, alg: wrong}
				}); err == nil {
					t.Errorf("IssuerAuth verified under %d", wrong)
				}
			}
		})
	}
}
