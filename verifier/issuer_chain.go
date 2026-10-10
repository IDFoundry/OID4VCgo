package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// MdocIssuerChainResolver is an MdocIssuerKeyResolver that can also
// return the certificate paths it verified a presented x5chain on, the
// document signer first: given one, VerifyResponse (and mdocdcapi)
// apply ISO/IEC 18013-5's document signer checks
// (mdoc.CheckDocumentSigner) — among them that an mDL's issuing_country
// matches its signer's certificate. X5ChainIssuerKeyResolver is one. A
// resolver that establishes trust without certificates isn't, and gets
// no such checks.
type MdocIssuerChainResolver interface {
	MdocIssuerKeyResolver
	ResolveMdocIssuerChains(ctx context.Context, x5chain [][]byte, docType string) ([][]*x509.Certificate, error)
}

// keyBoundChain is chain if its leaf certificate's key is issuerPub,
// the key the credential verified with, and nil otherwise: a chain
// that didn't sign the credential says nothing about who issued it,
// whatever it validates to (a header can carry any public chain, and
// an mdoc's x5chain isn't even signed).
func keyBoundChain(chain [][]byte, issuerPub crypto.PublicKey) [][]byte {
	if len(chain) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil
	}
	key, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !key.Equal(issuerPub) {
		return nil
	}
	return chain
}

// CheckMdocIssuer applies the checks of an mdoc's issuer that need its
// certificates, after mdoc.Verify succeeded with issuerPub: when
// resolver is an MdocIssuerChainResolver, ISO/IEC 18013-5's document
// signer checks over the paths it verified x5chain on. It returns
// x5chain when its leaf's key is issuerPub, nil otherwise.
func CheckMdocIssuer(ctx context.Context, resolver MdocIssuerKeyResolver, x5chain [][]byte, docType string, issuerPub crypto.PublicKey, verified mdoc.VerifiedMSO) ([][]byte, error) {
	bound := keyBoundChain(x5chain, issuerPub)
	chainResolver, ok := resolver.(MdocIssuerChainResolver)
	if !ok {
		return bound, nil
	}
	if bound == nil {
		return nil, errors.New("the issuer's x5chain isn't the one its key resolved from")
	}
	chains, err := chainResolver.ResolveMdocIssuerChains(ctx, x5chain, docType)
	if err != nil {
		return nil, fmt.Errorf("issuer certificate chain: %w", err)
	}
	if _, err := mdoc.CheckDocumentSigner(verified, chains); err != nil {
		return nil, err
	}
	return bound, nil
}
