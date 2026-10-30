package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// AttestationStatusChecker checks a verified key attestation's
// revocation status (see Dependencies.AttestationStatus).
// a.Claims.Status is its "status" claim, nil when it has none; a Token
// Status List reference in it parses with statuslist.ParseStatusClaim,
// and the list fetched from its uri checks with statuslist.Checker (or
// statuslist.CheckX5C). Whether an attestation without a status claim
// is acceptable is the implementation's decision.
//
// Bind the Status List Token's signer to the attestation's: under
// roots shared by several Wallet Providers, any of them could otherwise
// sign a list that decides another's attestation's status. Set the
// checker's Options.IssuerKey to a.SignerKey, so only a list signed
// with the attestation's own key is accepted. Don't bind it by
// a.Claims.Issuer (Options.Issuer): the attestation's iss is whatever
// its signer wrote, and unless the X5CAttestationVerifier binds it
// (AttestationIssuerInCertificate, AttestationIssuerBoundToAnchor),
// any provider trusted under the same roots could name another
// provider there, and so choose whose lists decide its attestation.
//
// The status list's uri is the Wallet Provider's to choose, and this
// runs before anything about it is trusted beyond the attestation's
// signature: fetch it with statuslist.Fetcher (as statuslist.Checker
// does), which connects only to public addresses, never with a plain
// http.Client that would let an attestation point the issuer at its
// own network.
//
// An error refuses the key attestation, in one of two ways:
//   - one wrapping ErrKeyAttestationRevoked says the attestation isn't
//     valid: a status other than VALID (a *statuslist.NotValidError),
//     or a status claim the issuer can't accept, such as none where
//     one is required. A Credential Request is refused with
//     invalid_proof, and a deferred transaction's re-check
//     (IssueDeferredCredential) denies the transaction.
//   - any other says the status couldn't be determined now: a Status
//     List that couldn't be fetched or verified, say. A Credential
//     Request is answered with a server error (500), which the Wallet
//     retries, rather than told its keys are invalid; a deferred
//     transaction stays pending, until the status can be checked, the
//     transaction expires (Limits.DeferredTransactionLifetime) or the
//     attestation's exp passes.
//
// A checker that would rather accept an attestation whose status it
// can't determine (soft-fail) returns nil itself.
type AttestationStatusChecker interface {
	CheckAttestationStatus(ctx context.Context, a VerifiedKeyAttestation) error
}

// ErrKeyAttestationRevoked is what an AttestationStatusChecker wraps
// for a key attestation whose status says it's no longer valid, or that
// it refuses for its status claim, as opposed to one whose status it
// couldn't determine (see AttestationStatusChecker).
var ErrKeyAttestationRevoked = errors.New("issuer: the key attestation is revoked or suspended")

// VerifiedKeyAttestation is a key attestation whose signature verified,
// as AttestationStatusChecker sees it.
type VerifiedKeyAttestation struct {
	// Claims are its verified claims.
	Claims attestation.VerifiedClaims

	// SignerKey is the key its signature verified with: the one
	// Dependencies.AttestationVerifier resolved.
	SignerKey crypto.PublicKey

	// SignerCertificates is its x5c header's certificate chain, leaf
	// first, when it has one whose leaf holds SignerKey; nil otherwise.
	// X5CAttestationVerifier has verified it to its Roots; another
	// AttestationVerifier may not have looked at it.
	SignerCertificates []*x509.Certificate
}

// signerCertificates is a's x5c chain, leaf first, if its leaf holds
// signer; nil if it has none, or another.
func signerCertificates(a attestation.KeyAttestation, signer crypto.PublicKey) []*x509.Certificate {
	x5c := a.X5C()
	if len(x5c) == 0 {
		return nil
	}
	entries := make([]any, len(x5c))
	for i, s := range x5c {
		entries[i] = s
	}
	ders, err := certchain.DERsFromBase64(entries)
	if err != nil {
		return nil
	}
	certs := make([]*x509.Certificate, len(ders))
	for i, der := range ders {
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil
		}
	}
	if !certchain.SameKey(certs[0].PublicKey, signer) {
		return nil
	}
	return certs
}

// X5CAttestationVerifier implements AttestationVerifier by validating
// a presented Key Attestation JWT's own "x5c" header (RFC 7515
// §4.1.6) against Roots — a reference implementation of the one
// concrete trust strategy this package's own doc comments describe
// ("an x5c chain's own trust anchor"), the issuer-side analog of
// verifier.X5CIssuerKeyResolver/X5ChainIssuerKeyResolver. A self-signed
// leaf is always rejected, even if that exact certificate is itself a
// configured root — see internal/certchain.VerifyLeaf's own doc
// comment for why. A caller whose Key Attestation trust model is DID
// resolution, a private key registry, or OpenID Federation's own
// "trust_chain" (KeyAttestation.TrustChain) needs its own
// AttestationVerifier implementation instead — see that interface's
// own doc comment.
//
// A valid chain proves only that some Wallet Provider certified under
// Roots signed the attestation, not which one: its "iss", and the
// key_storage and user_authentication levels it asserts, are whatever
// that provider wrote. With roots shared between Wallet Providers (a
// trust list's CA, one pool for several providers' CAs), any of them
// could sign an attestation in another's name. IssuerBinding ties the
// signing certificate to the attestation's "iss", the choice
// fapigo/server.X5CAttesterChain's IssuerBinding makes for a Wallet
// Attestation. AssuranceProduction requires the choice to be explicit:
// a binding, or SingleWalletProvider to declare that Roots certify one
// Wallet Provider alone, so nothing needs binding. Set
// AttestationIssuerBoundToAnchor whenever the anchors certify more than
// one Wallet Provider.
//
// LeafPolicy defaults to DefaultAttestationLeafPolicy, which refuses a
// signing certificate issued for another role under the same roots.
type X5CAttestationVerifier struct {
	// Roots is the trust anchor set a presented x5c chain must
	// validate against. Required unless IssuerBinding is
	// AttestationIssuerBoundToAnchor, which builds it from Anchors
	// instead and refuses Roots.
	Roots *x509.CertPool
	// LeafPolicy, if set, is run on the chain-verified leaf and its
	// verified paths, and can refuse it. Chain validation accepts a
	// leaf with any key usage, so a certificate issued for another role
	// under the same Roots (a relying party's, a wallet provider's)
	// would otherwise be accepted too: prefer Roots that anchor only
	// this role's certificates, and use LeafPolicy to require what
	// distinguishes them (an extended key usage, a certificate policy)
	// where the anchors are shared. nil means
	// DefaultAttestationLeafPolicy, which refuses the certificates whose
	// key usage clearly denotes another role (a TLS server's, an mdoc
	// reader's, an OCSP signer's, say). A LeafPolicy that's set
	// replaces it: one adding a requirement calls
	// DefaultAttestationLeafPolicy first, so as not to drop those
	// refusals, and AnyAttestationLeaf opts out of them explicitly.
	// Under AttestationIssuerBoundToAnchor only a path LeafPolicy
	// approves on its own can end at the bound anchor.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// Revocation, if set, checks the attestation's certificate chain
	// for revocation: only a verified path LeafPolicy approves and
	// Revocation passes is accepted (and, under
	// AttestationIssuerBoundToAnchor, can end at the bound anchor), and
	// an attestation signed under a revoked certificate — a Wallet
	// Provider's, say, or the CA that certified it — is refused with an
	// error wrapping certrevocation.ErrRevoked. When no path passes and
	// one was refused for revocation that couldn't be decided (any
	// other error, certrevocation.ErrNoCurrentCRL from a CRL list that
	// has expired, say), the error says so: the Credential Request gets
	// a server error rather than invalid_proof, and a deferred
	// transaction stays pending (see AttestationVerifier). nil checks
	// no revocation, which AssuranceProduction refuses: there, pass
	// certrevocation.CRLs (a certrevocation.Refresher's Checker), your
	// own Checker, or certrevocation.NoCheck{} to decline. See
	// certrevocation.
	Revocation certrevocation.Checker

	// IssuerBinding decides what ties the signing certificate to the
	// attestation's "iss". The zero value, AttestationIssuerUnbound,
	// ties nothing — see AttestationIssuerBinding — and
	// AssuranceProduction takes it only with SingleWalletProvider.
	IssuerBinding AttestationIssuerBinding

	// SingleWalletProvider declares that Roots anchor the certificates
	// of a single Wallet Provider, so IssuerBinding is deliberately
	// AttestationIssuerUnbound: no other provider's certificate can
	// chain to them to sign in its name. Under AssuranceProduction,
	// AttestationIssuerUnbound needs it; with any other IssuerBinding
	// it's refused, as a contradiction.
	SingleWalletProvider bool

	// Anchors are the trust anchors, each bound to the attestation
	// issuers it may vouch for, under AttestationIssuerBoundToAnchor.
	// Required for that binding, and must be empty under the others.
	Anchors []AttestationAnchor
}

// AttestationIssuerBinding decides what ties an X5CAttestationVerifier
// signing certificate to the Key Attestation's "iss" (OpenID4VCI
// Appendix D.1), the Wallet Provider it claims to come from.
type AttestationIssuerBinding uint8

const (
	// AttestationIssuerUnbound ties nothing in the certificate to the
	// attestation's "iss": any certificate chaining to Roots may sign an
	// attestation naming any issuer, or none. Sound only when Roots
	// anchor a single Wallet Provider's certificates.
	AttestationIssuerUnbound AttestationIssuerBinding = iota

	// AttestationIssuerInCertificate requires the attestation to carry
	// an "iss" its signing certificate names: a URI subject alternative
	// name exactly equal to it or, for a "dns:" iss, a DNS name — the
	// rule an SD-JWT VC's iss is held to against its x5c. That stops a
	// provider from signing in another's name only while it can't get
	// that name into a certificate: under roots shared by providers, one
	// that runs a CA under them (or holds an intermediate without name
	// constraints) can issue itself a certificate naming another. Choose
	// AttestationIssuerBoundToAnchor for a trust list of several
	// providers' own CAs; this suits roots that certify only names they
	// have vetted.
	AttestationIssuerInCertificate

	// AttestationIssuerBoundToAnchor requires what
	// AttestationIssuerInCertificate does and, in addition, that the
	// chain verify to one of Anchors bound to the attestation's "iss",
	// so a CA under provider A's anchor can't sign an attestation in
	// provider B's name even with every provider's anchor trusted.
	AttestationIssuerBoundToAnchor
)

// AttestationAnchor is a trust anchor bound to the Key Attestation
// issuers it may vouch for, for AttestationIssuerBoundToAnchor: a chain
// ending at Certificate is accepted only for an attestation whose "iss"
// is one of Issuers (and which the signing certificate names) — the
// shape of fapigo/server.AttesterAnchor, so a deployment that binds its
// Wallet Attestations' anchors can bind its Key Attestations' the same
// way.
type AttestationAnchor struct {
	// Certificate is the anchor. Required.
	Certificate *x509.Certificate

	// Issuers are the attestation "iss" values this anchor may vouch
	// for. At least one, none empty.
	Issuers []string
}

// validate checks the fields v.IssuerBinding reads: Anchors set, and
// usable, exactly when it's AttestationIssuerBoundToAnchor, and Roots
// not set then. A nil Roots otherwise is refused when a chain is
// verified, as it always has been.
func (v X5CAttestationVerifier) validate() error {
	if err := certchain.ValidateRevocation(v.Revocation); err != nil {
		return fmt.Errorf("X5CAttestationVerifier.Revocation: %w", err)
	}
	if v.SingleWalletProvider && v.IssuerBinding != AttestationIssuerUnbound {
		return errors.New("X5CAttestationVerifier.SingleWalletProvider declares that nothing needs binding; it applies only to AttestationIssuerUnbound")
	}
	switch v.IssuerBinding {
	case AttestationIssuerUnbound, AttestationIssuerInCertificate:
		if len(v.Anchors) != 0 {
			return errors.New("X5CAttestationVerifier.Anchors applies only to AttestationIssuerBoundToAnchor; use Roots")
		}
		return nil
	case AttestationIssuerBoundToAnchor:
	default:
		return fmt.Errorf("X5CAttestationVerifier.IssuerBinding %d is unknown", v.IssuerBinding)
	}
	if v.Roots != nil {
		return errors.New("AttestationIssuerBoundToAnchor builds its roots from X5CAttestationVerifier.Anchors; leave Roots nil")
	}
	if len(v.Anchors) == 0 {
		return errors.New("AttestationIssuerBoundToAnchor needs X5CAttestationVerifier.Anchors")
	}
	for i, a := range v.Anchors {
		if a.Certificate == nil {
			return fmt.Errorf("X5CAttestationVerifier.Anchors[%d] has no certificate", i)
		}
		if len(a.Issuers) == 0 || slices.Contains(a.Issuers, "") {
			return fmt.Errorf("X5CAttestationVerifier.Anchors[%d] (%s) must be bound to at least one issuer, none empty", i, a.Certificate.Subject)
		}
	}
	return nil
}

// validateAttestationVerifier runs X5CAttestationVerifier's own
// configuration check when av is one, so New refuses a misconfigured
// binding rather than every key attestation afterwards.
func validateAttestationVerifier(av AttestationVerifier) error {
	if t, ok := av.(*X5CAttestationVerifier); ok && t == nil {
		return errors.New("attestation_verifier is a nil *X5CAttestationVerifier")
	}
	v, ok := asX5CAttestationVerifier(av)
	if !ok {
		return nil
	}
	if err := v.validate(); err != nil {
		return fmt.Errorf("attestation_verifier: %w", err)
	}
	return nil
}

// asX5CAttestationVerifier is av as an X5CAttestationVerifier, by value
// or by non-nil pointer, if it is one.
func asX5CAttestationVerifier(av AttestationVerifier) (X5CAttestationVerifier, bool) {
	switch t := av.(type) {
	case X5CAttestationVerifier:
		return t, true
	case *X5CAttestationVerifier:
		if t != nil {
			return *t, true
		}
	}
	return X5CAttestationVerifier{}, false
}

// ResolveAttestationKey implements AttestationVerifier.
//
// Under an IssuerBinding it reads the attestation's "iss" before the
// signature is verified. That's sound: the issuer verifies the
// signature with the key returned here, the certificate's, so an "iss"
// that key didn't sign is refused then.
func (v X5CAttestationVerifier) ResolveAttestationKey(ctx context.Context, a attestation.KeyAttestation) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	if err := v.validate(); err != nil {
		return nil, "", fmt.Errorf("issuer: %w", err)
	}
	x5c := a.X5C()
	entries := make([]any, len(x5c))
	for i, s := range x5c {
		entries[i] = s
	}
	var leaf *x509.Certificate
	var err error
	if v.IssuerBinding == AttestationIssuerUnbound {
		leaf, _, err = resolveX5CLeaf(ctx, entries, v.Roots, attestationLeafPolicy(v.LeafPolicy), v.Revocation)
	} else {
		leaf, err = v.resolveBoundLeaf(ctx, entries, a.Issuer())
	}
	if err != nil {
		return nil, "", err
	}
	alg, err := algForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// resolveBoundLeaf verifies x5c as resolveX5CLeaf does, then holds its
// leaf to v.IssuerBinding for iss: the leaf names iss and, under
// AttestationIssuerBoundToAnchor, a path LeafPolicy approves and
// Revocation passes ends at an anchor bound to iss.
func (v X5CAttestationVerifier) resolveBoundLeaf(ctx context.Context, x5c []any, iss string) (*x509.Certificate, error) {
	if iss == "" {
		return nil, errors.New("issuer: key attestation has no iss to bind its signing certificate to")
	}
	roots := v.Roots
	if v.IssuerBinding == AttestationIssuerBoundToAnchor {
		roots = x509.NewCertPool()
		for _, anchor := range v.Anchors {
			roots.AddCert(anchor.Certificate)
		}
	}
	leaf, approved, err := resolveX5CLeaf(ctx, x5c, roots, attestationLeafPolicy(v.LeafPolicy), v.Revocation)
	if err != nil {
		return nil, err
	}
	if err := certchain.CheckIssuerName(leaf, iss); err != nil {
		return nil, fmt.Errorf("issuer: key attestation signing certificate: %w", err)
	}
	if v.IssuerBinding == AttestationIssuerBoundToAnchor && !chainEndsAtAnchorFor(approved, v.Anchors, iss) {
		return nil, fmt.Errorf("issuer: key attestation signing certificate chain doesn't end at a trust anchor bound to iss %q", iss)
	}
	return leaf, nil
}

// chainEndsAtAnchorFor reports whether one of chains — each leaf first,
// anchor last, as x509.Certificate.Verify returns them — ends at one of
// anchors bound to iss.
func chainEndsAtAnchorFor(chains [][]*x509.Certificate, anchors []AttestationAnchor, iss string) bool {
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		for _, a := range anchors {
			if a.Certificate.Equal(root) && slices.Contains(a.Issuers, iss) {
				return true
			}
		}
	}
	return false
}

// attestationRole is DefaultAttestationLeafPolicy's role: a Wallet
// Provider's, certifying a Wallet's keys. Neither an mDL document
// signer nor an mdoc reader is one.
var attestationRole = certchain.LeafRole{
	Name:         "the attestation signing certificate",
	OtherISOEKUs: []asn1.ObjectIdentifier{certchain.MDLDocumentSignerEKU, certchain.ReaderAuthenticationEKU},
	Strict:       true,
}

// DefaultAttestationLeafPolicy is the signing certificate check
// X5CAttestationVerifier and X5CProofBindingKeyResolver make where no
// LeafPolicy is set. Chain validation alone accepts any certificate
// under Roots, so a TLS server's certificate from an ecosystem CA that
// also certifies Wallet Providers could sign a key attestation
// claiming any key storage for any key. It refuses a certificate whose
// key usage extension doesn't allow digital signatures, that is an
// OCSP signer, whose extended key usage lists any purpose that denotes
// another role — TLS server or client authentication, code signing,
// email protection, time stamping, IPsec, or ISO/IEC 18013-5's mDL
// document signer or mdoc reader authentication (Annex B) — or every
// verified path in chains (leaf first, as a LeafPolicy receives them)
// of which has an intermediate CA whose extended key usage lists only
// such purposes. It accepts a certificate without those extensions, or
// whose extended key usage lists only anyExtendedKeyUsage or purposes
// of its own: OpenID4VCI defines no Wallet Provider purpose to require.
// A deployment whose providers' certificates carry one sets LeafPolicy
// to require it, after calling this.
func DefaultAttestationLeafPolicy(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return attestationRole.Check(leaf, chains)
}

// AnyAttestationLeaf is a LeafPolicy that accepts every chain-verified
// leaf: the explicit opt-out of DefaultAttestationLeafPolicy, for an
// X5CAttestationVerifier or X5CProofBindingKeyResolver whose Roots
// anchor only that role's certificates.
func AnyAttestationLeaf(*x509.Certificate, [][]*x509.Certificate) error { return nil }

// attestationLeafPolicy is policy, or DefaultAttestationLeafPolicy when
// it's nil.
func attestationLeafPolicy(policy func(*x509.Certificate, [][]*x509.Certificate) error) func(*x509.Certificate, [][]*x509.Certificate) error {
	if policy != nil {
		return policy
	}
	return DefaultAttestationLeafPolicy
}

// checkProductionAttestationBinding refuses, under AssuranceProduction,
// an X5CAttestationVerifier left at AttestationIssuerUnbound without
// SingleWalletProvider: under roots that certify several Wallet
// Providers, any of them could sign a key attestation in another's
// name.
func checkProductionAttestationBinding(deps Dependencies) error {
	v, ok := asX5CAttestationVerifier(deps.AttestationVerifier)
	if !ok || v.IssuerBinding != AttestationIssuerUnbound || v.SingleWalletProvider {
		return nil
	}
	return errors.New("dependencies.attestation_verifier: X5CAttestationVerifier needs an explicit IssuerBinding under AssuranceProduction: AttestationIssuerBoundToAnchor (with Anchors) where its roots certify more than one Wallet Provider, AttestationIssuerInCertificate, or SingleWalletProvider to declare that its Roots certify one Wallet Provider alone")
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented x5c chain against an in-memory Roots pool never
// touches the network, so LiveFetchHardened is unconditionally true.
func (v X5CAttestationVerifier) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}

// algForKey maps pub to the JOSE algorithm this package's own signers
// use for it — the same ES256/EdDSA-only mapping
// verifier.sdjwtvcAlgForKey establishes on the verifying side, kept as
// its own small copy here rather than a cross-package export: it's a
// trivial, self-contained switch, not the security-relevant logic
// internal/certchain centralizes.
func algForKey(pub crypto.PublicKey) (jose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return jose.ES256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("issuer: unsupported public key type %T", pub)
	}
}
