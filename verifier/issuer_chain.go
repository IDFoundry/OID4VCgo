package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
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

// SDJWTVCIssuerChainResolver is an SDJWTVCIssuerKeyResolver that
// verifies the issuer's x5c chain, and gives the paths it verified:
// given one, VerifyResponse hands TrustedAuthorities and
// IssuerAuthorized (VerifiedCredential.IssuerChain) the verified path,
// without its trust anchor, rather than the x5c header, which can carry
// certificates that aren't on it. X5CIssuerKeyResolver is one.
//
// For both, the paths are the ones the resolver's own role policy
// approves each on its own, not every path the chain verifies on: the
// first is the issuer chain the rest of the verification decides on.
type SDJWTVCIssuerChainResolver interface {
	SDJWTVCIssuerKeyResolver
	ResolveIssuerChains(ctx context.Context, header map[string]any) ([][]*x509.Certificate, error)
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
// signer checks over the paths it verified x5chain on.
//
// It returns the issuer chain to trust: the path that passed the
// document signer checks, document signer first, without its trust
// anchor. Never x5chain itself: an mdoc's x5chain is an unprotected
// COSE header, so the holder can add, drop or reorder certificates in
// it, or swap the leaf for one with the same key their own CA issued.
// Nor another verified path: through a cross-certificate the holder
// adds, a second path may end at an anchor that never passed the
// country check. A resolver that wraps another (logging, caching)
// reaches its MdocIssuerChainResolver through Unwrap; one that isn't
// one authenticates only the key, so the chain is nil, and a
// trusted_authorities check on it fails. Under AssuranceProduction,
// VerifyResponse requires an MdocIssuerChainResolver.
func CheckMdocIssuer(ctx context.Context, resolver MdocIssuerKeyResolver, x5chain [][]byte, docType string, issuerPub crypto.PublicKey, verified mdoc.VerifiedMSO) ([][]byte, error) {
	chainResolver, ok := mdocChainResolver(resolver)
	if !ok {
		return nil, nil
	}
	if keyBoundChain(x5chain, issuerPub) == nil {
		return nil, errors.New("the issuer's x5chain isn't the one its key resolved from")
	}
	chains, err := chainResolver.ResolveMdocIssuerChains(ctx, x5chain, docType)
	if err != nil {
		return nil, fmt.Errorf("issuer certificate chain: %w", err)
	}
	return checkDocumentSignerPaths(chains, issuerPub, verified)
}

// checkDocumentSignerPaths is CheckMdocIssuer's document signer checks
// over chains, the paths the resolver verified the issuer's x5chain on.
func checkDocumentSignerPaths(chains [][]*x509.Certificate, issuerPub crypto.PublicKey, verified mdoc.VerifiedMSO) ([][]byte, error) {
	path, err := mdoc.CheckDocumentSigner(verified, chains)
	if err != nil {
		return nil, err
	}
	trusted := verifiedPath([][]*x509.Certificate{path}, issuerPub)
	if trusted == nil {
		return nil, errors.New("the issuer certificate path that passed the document signer checks isn't the key's")
	}
	return trusted, nil
}

// MdocIssuer is an mdoc issuer's key, as ResolveMdocIssuer resolved it
// from the issuer's x5chain, with what Check needs to check the issuer
// once mdoc.Verify has verified the document with the key.
type MdocIssuer struct {
	// Key is the key the document's IssuerAuth must verify with.
	Key crypto.PublicKey
	// Alg is the COSE algorithm Key signs with.
	Alg oid4vci.COSEAlg

	resolver MdocIssuerKeyResolver
	x5chain  [][]byte
	docType  string
	// chains are the paths x5chain verified on when the key was
	// resolved, for an X5ChainIssuerKeyResolver; verifiedChains says
	// they were.
	chains         [][]*x509.Certificate
	verifiedChains bool
}

// ResolveMdocIssuer is resolver.ResolveMdocIssuerKey(ctx, x5chain,
// docType), keeping what MdocIssuer.Check needs: VerifyResponse and
// mdocdcapi call it, mdoc.Verify, then Check. An
// X5ChainIssuerKeyResolver (or a pointer to one) verifies x5chain once,
// for the key and for the document signer checks, with the same
// verification time, roots, LeafPolicy and Revocation as the two calls
// it replaces; any other resolver is asked twice, as
// ResolveMdocIssuerKey and then CheckMdocIssuer would ask it.
func ResolveMdocIssuer(ctx context.Context, resolver MdocIssuerKeyResolver, x5chain [][]byte, docType string) (MdocIssuer, error) {
	issuer := MdocIssuer{resolver: resolver, x5chain: x5chain, docType: docType}
	if r, ok := x5chainResolver(resolver); ok {
		leaf, chains, err := r.verify(ctx, x5chain, docType)
		if err != nil {
			return MdocIssuer{}, err
		}
		alg, err := mdocAlgForKey(leaf.PublicKey)
		if err != nil {
			return MdocIssuer{}, err
		}
		issuer.Key, issuer.Alg, issuer.chains, issuer.verifiedChains = leaf.PublicKey, alg, chains, true
		return issuer, nil
	}
	key, alg, err := resolver.ResolveMdocIssuerKey(ctx, x5chain, docType)
	if err != nil {
		return MdocIssuer{}, err
	}
	issuer.Key, issuer.Alg = key, alg
	return issuer, nil
}

// Check is CheckMdocIssuer for i's resolver, x5chain, document type and
// key, after mdoc.Verify succeeded with i.Key: it returns the issuer
// chain to trust, as CheckMdocIssuer does, from the paths
// ResolveMdocIssuer verified where it verified them.
func (i MdocIssuer) Check(ctx context.Context, verified mdoc.VerifiedMSO) ([][]byte, error) {
	if !i.verifiedChains {
		return CheckMdocIssuer(ctx, i.resolver, i.x5chain, i.docType, i.Key, verified)
	}
	if keyBoundChain(i.x5chain, i.Key) == nil {
		return nil, errors.New("the issuer's x5chain isn't the one its key resolved from")
	}
	return checkDocumentSignerPaths(i.chains, i.Key, verified)
}

// x5chainResolver is resolver as an X5ChainIssuerKeyResolver, when it's
// exactly one: a type embedding it may resolve keys or chains its own
// way.
func x5chainResolver(resolver MdocIssuerKeyResolver) (X5ChainIssuerKeyResolver, bool) {
	switch r := resolver.(type) {
	case X5ChainIssuerKeyResolver:
		return r, true
	case *X5ChainIssuerKeyResolver:
		if r != nil {
			return *r, true
		}
	}
	return X5ChainIssuerKeyResolver{}, false
}

// MdocIssuerKeyResolverWrapper is a resolver that wraps another, a
// logging or caching one, say: Unwrap returns the one it wraps, so the
// document signer checks of an MdocIssuerChainResolver it wraps still
// apply.
type MdocIssuerKeyResolverWrapper interface {
	Unwrap() MdocIssuerKeyResolver
}

// mdocChainResolver is resolver as an MdocIssuerChainResolver, or the
// one it wraps, through Unwrap.
func mdocChainResolver(resolver MdocIssuerKeyResolver) (MdocIssuerChainResolver, bool) {
	for range 16 {
		if chain, ok := resolver.(MdocIssuerChainResolver); ok {
			return chain, true
		}
		wrapper, ok := resolver.(MdocIssuerKeyResolverWrapper)
		if !ok {
			return nil, false
		}
		resolver = wrapper.Unwrap()
	}
	return nil, false
}

// verifiedPath is the first of chains whose leaf has issuerPub, as DER,
// without its last certificate, the trust anchor the path ends at: the
// form an x5chain takes (RFC 9360 §2), every certificate in it
// verified.
func verifiedPath(chains [][]*x509.Certificate, issuerPub crypto.PublicKey) [][]byte {
	for _, path := range chains {
		if len(path) == 0 {
			continue
		}
		key, ok := path[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !key.Equal(issuerPub) {
			continue
		}
		if len(path) > 1 {
			path = path[:len(path)-1]
		}
		ders := make([][]byte, len(path))
		for i, cert := range path {
			ders[i] = cert.Raw
		}
		return ders
	}
	return nil
}
