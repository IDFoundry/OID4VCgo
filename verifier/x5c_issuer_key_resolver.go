package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
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
// SD-JWT VC has the x5c header's leaf certify the issuer's key; which
// issuer that is, the resolver can't tell from any name. An iss
// alongside x5c needn't correspond to a name in the leaf (SD-JWT VC
// §2.5, as the editors' copy now says outright), and issuers such as
// the EU reference PID issuer send a leaf with no subject alternative
// name at all, so by default iss is carried but not checked against
// it: a credential's iss is then only as trustworthy as every issuer
// under Roots. RequireIssuerName checks it, but a name in the leaf is
// only as trustworthy as every CA under Roots too: each can certify a
// leaf with any subject or subject alternative name. Tell issuers
// apart by the trust anchor that verified their chain
// (VerifiedCredential.IssuerAnchor, IssuerAuthorization.IssuerAnchor),
// or by giving each type its own anchors (RootsByVCT).
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
	// validate against, for a credential type RootsByVCT doesn't name.
	// Leave it nil, with RootsByVCT set, to accept only the types it
	// names. One of the two is REQUIRED.
	Roots *x509.CertPool

	// RootsByVCT, OPTIONAL, are the trust anchors for each credential
	// type, keyed on the vct in the Issuer-signed JWT: a credential of a
	// type it names must chain to that type's anchors, not to Roots.
	// Without it, every anchor in Roots may sign every type — a loyalty
	// club's CA a PID, say — so where the anchors are different
	// providers', name each one's types here. A type named with nil
	// anchors is refused.
	//
	// A credential's aka_vcts are types it says it is of too, and can
	// answer a query through (dcql.CredentialQuery), but they're its
	// issuer's own claim (SD-JWT VC draft-19 §7.7). So with RootsByVCT
	// set, the credential's chain must validate against the anchors of
	// each of its aka_vcts as well: RootsByVCT's for a type it names,
	// else Roots, else the credential is refused. The issuer chain
	// reported is the one validated against its vct's anchors.
	//
	// ResolveIssuerChains, which isn't given the credential, can't tell
	// its type: with RootsByVCT set it refuses. VerifyResponse resolves
	// an X5CIssuerKeyResolver's key and chains together, with the
	// credential; a resolver of your own that wraps one and implements
	// ResolveIssuerChains by calling it is refused there too.
	RootsByVCT map[string]*x509.CertPool

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
	// root you trust for all of them certifies several issuers, so that
	// none of those issuers can sign in another's name. It holds only
	// where no other trusted CA can issue a certificate naming that
	// issuer: every CA under Roots can put any name in a leaf it
	// certifies (and a dNSName name constraint doesn't constrain a URI
	// name). Where Roots are several providers', tell them apart by
	// IssuerAnchor or RootsByVCT, not by this. Without it,
	// IssuerAuthorization.Issuer is empty.
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
// LeafPolicy to require it, after calling this. The mDL document
// signer's extended key usage (mdoc.MDLDocumentSignerEKU) isn't another
// role's: an issuer may sign its SD-JWT VCs with its document signer's
// certificate.
//
// A wallet receiving an SD-JWT VC makes the same check where no
// IssuerLeafPolicy is set (wallet.VerifyIssuedCredentialParams,
// walletflow.Config).
//
// Without an extended key usage to require, it can't tell this role's
// certificates from another's that carry none, so walletflow.New
// doesn't count it as a leaf policy separating a trust pool from
// another role's that shares an anchor with it (walletflow.Config):
// there it's as if unset.
func DefaultSDJWTIssuerLeafPolicy(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return certchain.SDJWTIssuerRole.Check(leaf, chains)
}

func init() { certchain.RegisterNonSeparating(DefaultSDJWTIssuerLeafPolicy) }

// AnyIssuerLeaf is a LeafPolicy that accepts every chain-verified
// leaf: the explicit opt-out of DefaultSDJWTIssuerLeafPolicy (or of
// mdoc.DefaultDocumentSignerPolicy, for X5ChainIssuerKeyResolver), for
// Roots that anchor only issuers' certificates. A wallet opts out of
// the same defaults by setting it as its IssuerLeafPolicy
// (wallet.VerifyIssuedCredentialParams, walletflow.Config).
//
// It tells no role's certificates apart, so walletflow.New doesn't
// count it as a leaf policy separating a trust pool from another
// role's that shares an anchor with it (walletflow.Config): there
// it's as if unset.
func AnyIssuerLeaf(*x509.Certificate, [][]*x509.Certificate) error { return nil }

func init() { certchain.RegisterNonSeparating(AnyIssuerLeaf) }

// ResolveIssuerChains implements SDJWTVCIssuerChainResolver: the paths
// from the x5c header's leaf to Roots, as ResolveIssuerKey verifies it,
// that LeafPolicy approves each on its own (certchain.ApprovedChains)
// and Revocation passes: the issuer chain VerifyResponse reports is one
// of them. With RootsByVCT set it refuses: the header doesn't say the
// credential's type, which chooses the anchors.
func (r X5CIssuerKeyResolver) ResolveIssuerChains(ctx context.Context, header map[string]any) ([][]*x509.Certificate, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if len(r.RootsByVCT) > 0 {
		return nil, errors.New("verifier: X5CIssuerKeyResolver with RootsByVCT can't resolve issuer chains without the credential's vct")
	}
	ders, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return nil, err
	}
	_, chains, err := verifyTrustedChains(ctx, nil, "x5c", ders, r.Roots, r.leafPolicy(), r.Revocation, nil)
	return chains, err
}

// BindsIssuerName implements IssuerNameBinding.
func (r X5CIssuerKeyResolver) BindsIssuerName() bool { return r.RequireIssuerName }

// ResolveIssuerKey implements SDJWTVCIssuerKeyResolver.
func (r X5CIssuerKeyResolver) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	pub, alg, _, err := r.resolveIssuerKeyAndChains(ctx, nil, header, payload, nil)
	return pub, alg, err
}

// resolveIssuerKeyAndChains is ResolveIssuerKey, with the chains
// ResolveIssuerChains would return for the same header and ctx, from
// the one verification of them, memoized in memo when it isn't nil.
func (r X5CIssuerKeyResolver) resolveIssuerKeyAndChains(ctx context.Context, memo *chainMemo, header, payload map[string]any, signed leafSignature) (crypto.PublicKey, oid4vci.JOSEAlg, [][]*x509.Certificate, error) {
	if err := r.Validate(); err != nil {
		return nil, "", nil, err
	}
	ders, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return nil, "", nil, err
	}
	if err := certchain.CheckNoAnchor(ders); err != nil {
		return nil, "", nil, err
	}
	roots, akaRoots, err := r.rootsFor(payload)
	if err != nil {
		return nil, "", nil, err
	}
	leaf, chains, err := verifyTrustedChains(ctx, memo, "x5c", ders, roots, r.leafPolicy(), r.Revocation, signed)
	if err != nil {
		return nil, "", nil, err
	}
	for _, roots := range akaRoots {
		// The signature is checked: only the chain is left to check.
		if _, _, err := verifyTrustedChains(ctx, memo, "x5c", ders, roots, r.leafPolicy(), r.Revocation, nil); err != nil {
			return nil, "", nil, fmt.Errorf("the issuer isn't trusted for one of the credential's aka_vcts: %w", err)
		}
	}
	if r.RequireIssuerName {
		// Required means present: a credential naming no issuer would
		// pass a check of the one it names.
		issRaw, present := payload["iss"]
		if !present {
			return nil, "", nil, errors.New("RequireIssuerName: the credential names no issuer (iss)")
		}
		iss, ok := issRaw.(string)
		if !ok {
			return nil, "", nil, errors.New("iss is not a string")
		}
		if err := certchain.CheckIssuerName(leaf, iss); err != nil {
			return nil, "", nil, err
		}
	}
	alg, err := jose.AlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", nil, err
	}
	return leaf.PublicKey, alg, chains, nil
}

// rootsFor is the trust anchors a credential whose Issuer-signed JWT
// has payload must chain to: its vct's (typeRoots), and, with
// RootsByVCT set, each other set its aka_vcts' types have, once each.
func (r X5CIssuerKeyResolver) rootsFor(payload map[string]any) (*x509.CertPool, []*x509.CertPool, error) {
	if len(r.RootsByVCT) == 0 {
		if r.Roots == nil {
			return nil, nil, errors.New("verifier: X5CIssuerKeyResolver needs Roots or RootsByVCT")
		}
		return r.Roots, nil, nil
	}
	vct, ok := payload["vct"].(string)
	if !ok {
		return nil, nil, errors.New("verifier: the credential has no vct to choose its trust anchors by (RootsByVCT)")
	}
	roots, err := r.typeRoots(vct)
	if err != nil {
		return nil, nil, err
	}
	raw, present := payload["aka_vcts"]
	if !present {
		return roots, nil, nil
	}
	aka, ok := raw.([]any)
	if !ok {
		return nil, nil, errors.New("verifier: aka_vcts is not an array")
	}
	var akaRoots []*x509.CertPool
	for _, t := range aka {
		s, ok := t.(string)
		if !ok {
			return nil, nil, errors.New("verifier: aka_vcts has an entry that is not a string")
		}
		pool, err := r.typeRoots(s)
		if err != nil {
			return nil, nil, fmt.Errorf("aka_vcts: %w", err)
		}
		if pool != roots && !slices.Contains(akaRoots, pool) {
			akaRoots = append(akaRoots, pool)
		}
	}
	return roots, akaRoots, nil
}

// typeRoots is the trust anchors a credential of type vct must chain
// to: RootsByVCT's for a type it names, else Roots.
func (r X5CIssuerKeyResolver) typeRoots(vct string) (*x509.CertPool, error) {
	if roots, ok := r.RootsByVCT[vct]; ok {
		// A type named with no roots falls back to none: Roots weren't
		// chosen for it.
		if roots == nil {
			return nil, fmt.Errorf("verifier: no trust anchors for credential type %q", vct)
		}
		return roots, nil
	}
	if r.Roots == nil {
		return nil, fmt.Errorf("verifier: no trust anchors for credential type %q", vct)
	}
	return r.Roots, nil
}

// anchorPools is every trust anchor set r verifies against: Roots and
// RootsByVCT's.
func (r X5CIssuerKeyResolver) anchorPools() []*x509.CertPool {
	pools := []*x509.CertPool{r.Roots}
	for _, roots := range r.RootsByVCT {
		pools = append(pools, roots)
	}
	return pools
}

// x5cResolver is keys as an X5CIssuerKeyResolver, when it's exactly
// one: a type embedding it may resolve keys or chains its own way.
func x5cResolver(keys SDJWTVCIssuerKeyResolver) (X5CIssuerKeyResolver, bool) {
	switch r := keys.(type) {
	case X5CIssuerKeyResolver:
		return r, true
	case *X5CIssuerKeyResolver:
		if r != nil {
			return *r, true
		}
	}
	return X5CIssuerKeyResolver{}, false
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented certificate chain against an in-memory CertPool
// never touches the network.
func (r X5CIssuerKeyResolver) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}
