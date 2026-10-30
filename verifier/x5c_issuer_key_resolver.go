package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// X5CIssuerKeyResolver implements SDJWTVCIssuerKeyResolver by
// validating a presented "dc+sd-jwt" credential's own "x5c" header
// (RFC 7515 §4.1.6) against Roots — HAIP 1.0 §5.3's own MUST for
// "dc+sd-jwt" issuer trust, which SDJWTVCIssuerKeyResolver's own doc
// comment names as a deployment policy decision but leaves
// unimplemented anywhere in this repo. Confirmed live against the
// OpenID Foundation conformance suite's own two checks on this exact
// requirement ("Credential MUST contain an x5c in the header", "Leaf
// certificate in x5c chain must not be self-signed" —
// cmd/conformance-wallet-vp's own README) — this resolver enforces
// both on the verifying side, not just the issuing side
// credential/sdjwtvc.IssueOptions.IssuerCertificate satisfies on the
// issuing side.
//
// The issuer is the leaf's subject (SD-JWT VC, the x5c header). An iss
// alongside x5c needn't correspond to a name in the leaf (SD-JWT VC
// §2.5, as the editors' copy now says outright), and issuers such as
// the EU reference PID issuer send a leaf with no subject alternative
// name at all, so by default iss is carried but not checked against
// it: a credential's iss is then only as trustworthy as every issuer
// under Roots. RequireIssuerName checks it.
//
// A self-signed leaf is always rejected, even if that exact
// certificate also happens to be present in Roots — see
// internal/certchain.VerifyLeaf's own doc comment for why.
//
// Revocation is checked on every verified path from the leaf to Roots
// that LeafPolicy approves: the credential is accepted only through a
// path on which no certificate is revoked, and that path is the issuer
// chain VerifyResponse reports.
type X5CIssuerKeyResolver struct {
	// Roots is the trust anchor set a presented x5c chain must
	// validate against. REQUIRED.
	Roots *x509.CertPool
	// LeafPolicy, if set, is run on the chain-verified leaf and its
	// verified paths, and can refuse it. Chain validation accepts a
	// leaf with any key usage, so a certificate issued for another role
	// under the same Roots (a relying party's, a wallet provider's)
	// would otherwise be accepted too: prefer Roots that anchor only
	// this role's certificates, and use LeafPolicy to require what
	// distinguishes them (an extended key usage, a certificate policy)
	// where the anchors are shared. nil means
	// DefaultSDJWTIssuerLeafPolicy, which refuses the certificates
	// whose key usage clearly denotes another role (a TLS server's, an
	// mdoc reader's, say). A LeafPolicy that's set replaces it: one
	// adding a requirement calls DefaultSDJWTIssuerLeafPolicy first, so
	// as not to drop those refusals, and AnyIssuerLeaf opts out of them
	// explicitly.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// Revocation decides whether a certificate on a verified path — the
	// issuer's own, or an intermediate CA's — has been revoked. A chain
	// that verifies says nothing about a certificate its CA has since
	// revoked: an issuer whose key was stolen would keep signing
	// accepted credentials until its certificate expired. REQUIRED,
	// with no default: pass certrevocation.CRLs{...} with your CAs'
	// current lists, your own certrevocation.Checker (OCSP, for
	// example), or certrevocation.NoCheck{} to decline — see its doc
	// comment for when that's acceptable.
	Revocation certrevocation.Checker
	// RequireIssuerName refuses a credential whose iss the leaf doesn't
	// name: a "dns:" iss must be one of its dNSName subject alternative
	// names, any other exactly one of its uniformResourceIdentifier
	// names; a credential without iss is refused. It's a relying
	// party's policy, not a requirement of SD-JWT VC: use it where one
	// root certifies several issuers, so none can sign in another's
	// name. Without it, IssuerAuthorization.Issuer is
	// empty, and VerifyResponseRequest.IssuerAuthorized decides from the
	// verified certificate (IssuerChain) instead.
	RequireIssuerName bool
}

// Validate reports a resolver that can't verify anything as
// configured: one without Revocation, or whose Revocation is itself
// incomplete (a certrevocation.CRLs without Lists). VerifyResponse,
// NewTransactions and mdocdcapi.VerifyResponse call it on the
// resolvers they're given, so the mistake shows before any credential
// does; ResolveIssuerKey and ResolveIssuerChains refuse to resolve
// without it passing too.
func (r X5CIssuerKeyResolver) Validate() error {
	return validateRevocation("X5CIssuerKeyResolver", r.Revocation)
}

// leafPolicy is LeafPolicy, or DefaultSDJWTIssuerLeafPolicy.
func (r X5CIssuerKeyResolver) leafPolicy() func(*x509.Certificate, [][]*x509.Certificate) error {
	if r.LeafPolicy != nil {
		return r.LeafPolicy
	}
	return DefaultSDJWTIssuerLeafPolicy
}

// sdjwtIssuerRole is DefaultSDJWTIssuerLeafPolicy's role. The mDL
// document signer's extended key usage (mdoc.MDLDocumentSignerEKU)
// isn't among its other roles: an issuer may sign its SD-JWT VCs with
// its document signer's certificate.
var sdjwtIssuerRole = certchain.LeafRole{
	Name:         "the issuer certificate",
	OtherISOEKUs: []asn1.ObjectIdentifier{certchain.ReaderAuthenticationEKU},
}

// DefaultSDJWTIssuerLeafPolicy is the issuer certificate check
// X5CIssuerKeyResolver makes where no LeafPolicy is set. Chain
// validation alone accepts any certificate under Roots, so a TLS
// server's certificate from an ecosystem CA that also issues those
// would sign accepted credentials. It refuses a certificate whose key
// usage extension doesn't allow digital signatures, that is an OCSP
// signer, whose extended key usage includes ISO/IEC 18013-5's mdoc
// reader authentication (Annex B), or whose extended key usage lists
// only purposes that denote another role — TLS server or client
// authentication, code signing, email protection, time stamping,
// IPsec, mdoc reader authentication. It refuses the leaf, too, when
// every verified path in chains (leaf first, as a LeafPolicy receives
// them) has an intermediate CA whose extended key usage lists only such
// purposes: a CA restricted to issuing TLS certificates, say. It accepts
// a certificate without those extensions, or whose extended key usage
// lists any other purpose (anyExtendedKeyUsage, the mDL document
// signer's, or a private one): SD-JWT VC defines no issuer purpose to
// require. A deployment whose issuer certificates carry one sets
// LeafPolicy to require it, after calling this.
func DefaultSDJWTIssuerLeafPolicy(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return sdjwtIssuerRole.Check(leaf, chains)
}

// AnyIssuerLeaf is a LeafPolicy that accepts every chain-verified
// leaf: the explicit opt-out of DefaultSDJWTIssuerLeafPolicy (or of
// mdoc.DefaultDocumentSignerPolicy, for X5ChainIssuerKeyResolver), for
// Roots that anchor only issuers' certificates.
func AnyIssuerLeaf(*x509.Certificate, [][]*x509.Certificate) error { return nil }

// ResolveIssuerChains implements SDJWTVCIssuerChainResolver: the paths
// from the x5c header's leaf to Roots, as ResolveIssuerKey verifies it,
// that LeafPolicy approves each on its own (certchain.ApprovedChains)
// and Revocation passes: the issuer chain VerifyResponse reports is one
// of them.
func (r X5CIssuerKeyResolver) ResolveIssuerChains(ctx context.Context, header map[string]any) ([][]*x509.Certificate, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	ders, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return nil, err
	}
	_, chains, err := certchain.VerifyTrustedChainsAt(ctx, ders, r.Roots, r.leafPolicy(), r.Revocation, verificationTime(ctx))
	return chains, err
}

// BindsIssuerName implements IssuerNameBinding.
func (r X5CIssuerKeyResolver) BindsIssuerName() bool { return r.RequireIssuerName }

// ResolveIssuerKey implements SDJWTVCIssuerKeyResolver.
func (r X5CIssuerKeyResolver) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	if err := r.Validate(); err != nil {
		return nil, "", err
	}
	ders, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return nil, "", err
	}
	if err := certchain.CheckNoAnchor(ders); err != nil {
		return nil, "", err
	}
	leaf, _, err := certchain.VerifyTrustedChainsAt(ctx, ders, r.Roots, r.leafPolicy(), r.Revocation, verificationTime(ctx))
	if err != nil {
		return nil, "", err
	}
	if r.RequireIssuerName {
		// Required means present: a credential naming no issuer would
		// pass a check of the one it names.
		issRaw, present := payload["iss"]
		if !present {
			return nil, "", errors.New("RequireIssuerName: the credential names no issuer (iss)")
		}
		iss, ok := issRaw.(string)
		if !ok {
			return nil, "", errors.New("iss is not a string")
		}
		if err := certchain.CheckIssuerName(leaf, iss); err != nil {
			return nil, "", err
		}
	}
	alg, err := sdjwtvcAlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented certificate chain against an in-memory CertPool
// never touches the network.
func (r X5CIssuerKeyResolver) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}
