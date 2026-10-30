package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListRef returns the Token Status List reference vc carries, in
// one form whichever format it is: an SD-JWT VC's "status" claim or an
// mdoc's MSO status. cwt reports which Status List Token form to fetch
// for it — CWT for an mdoc, JWT for an SD-JWT VC — as
// statuslist.Checker.Check takes it. ok is false when vc has no status
// list reference; err is set when it has a malformed one, when it has a
// status naming no mechanism this package knows (an SD-JWT VC "status"
// with no status_list, an MSO status with neither status_list nor
// identifier_list: a misspelt key, or a mechanism defined elsewhere), or
// when it's an mdoc whose only status is an identifier list, which isn't
// a Token Status List (identifierlist.Checker checks it, given the
// mdoc's document signer path) — so a caller that checks status when ok
// doesn't skip it. A status that can't be read isn't "no status": read
// as one, a credential revoked through it would pass.
//
//	ref, cwt, ok, err := vc.StatusListRef()
//	if err == nil && ok {
//		err = checker.RequireValid(ctx, ref, cwt)
//	}
//	if err != nil {
//		// refuse vc: revoked, suspended, or its status unreadable
//	}
//
// A StatusPolicy (TransactionsConfig.Status) does this for every
// credential in an answer.
func (vc VerifiedCredential) StatusListRef() (ref statuslist.StatusListRef, cwt, ok bool, err error) {
	if vc.MdocStatus != nil {
		sl := vc.MdocStatus.StatusList
		if sl == nil {
			if vc.MdocStatus.IdentifierList != nil {
				// A status this package can't check isn't "no status":
				// read as one, a revoked mdoc would pass.
				return statuslist.StatusListRef{}, false, false, fmt.Errorf("verifier: the mdoc's status is an identifier list, not a status list: check it with RequireValidStatus, or with identifierlist.Checker given the mdoc's document signer path (its IssuerChain)")
			}
			// The MSO has a status, but neither member this package
			// reads (mdoc.Status).
			return statuslist.StatusListRef{}, false, false, errors.New("verifier: the mdoc's status names no status mechanism this package knows (neither status_list nor identifier_list)")
		}
		return statuslist.StatusListRef{Idx: sl.Idx, URI: sl.URI}, true, true, nil
	}
	raw, present := vc.Claims["status"]
	if !present {
		return statuslist.StatusListRef{}, false, false, nil
	}
	status, isObject := raw.(map[string]any)
	if !isObject {
		// A status this package can't read isn't "no status" either.
		return statuslist.StatusListRef{}, false, false, fmt.Errorf("verifier: the credential's status claim is a %T, not an object", raw)
	}
	if ref, err = statuslist.ParseStatusClaim(status); err != nil {
		return statuslist.StatusListRef{}, false, false, err
	}
	return ref, false, true, nil
}

// RequireValidStatus is an Accept that checks the status of every
// credential in an answer that carries a status reference, with
// checker, as a StatusPolicy with that Checker does: prefer the policy,
// as TransactionsConfig.Status, which runs before Accept and which
// AssuranceProduction requires (or NoStatusCheck), and checks checker's
// Fetcher and Options.Revocation there. An answer is refused when any of them isn't
// VALID (statuslist.NotValidError), when an mdoc is on its identifier
// list (identifierlist.ErrRevoked), when a status can't be read, when a
// reference is malformed, or when a credential's status names no
// mechanism this package knows. An mdoc's identifier list is checked
// with an identifierlist.Checker that has checker's Fetcher, Roots and
// Options, so checker.Fetcher.MaxBytes caps an identifier list's size
// too (zero there means identifierlist's own 4 MiB, not 1 MiB: a list
// grows with the MSOs it revokes). A credential with no status
// reference passes: it has no status to check, and nothing here can
// revoke it. Where every credential accepted must be revocable, wrap
// it in RequireStatusReference.
//
// Only the credential's own status is checked here. Its issuer's
// certificate chain was checked for revocation when it was verified
// (X5CIssuerKeyResolver.Revocation, X5ChainIssuerKeyResolver.Revocation);
// the Status List Token signer's is checked only when checker's
// Options.Revocation is set (see the package documentation).
//
// A Status List Token must be signed by the credential's issuer, so
// another issuer's certificate under the same roots can't decide its
// status. For an SD-JWT VC that's the key that signed the credential,
// or a certificate naming the credential's iss, or without one the URI
// its own certificate names (statuslist.VerifyOptions.Issuer). For an
// mdoc it's ISO/IEC 18013-5 §12.3.6's rule (mdoc.StatusTrust): a chain
// to the Certificate the MSO's status names, or else to the CA that
// signed the document signer. A credential that can't be tied to an
// issuer — verified by a resolver that reports no issuer chain, with
// no iss or MSO status Certificate to go by — has its status check
// refused: pass RequireValidStatusFrom a StatusIssuerPolicy to decide
// its signer (AnyStatusListSigner accepts any under the roots).
// Where status lists come from a separate Status Issuer, use
// RequireValidStatusFrom.
//
// Under AssuranceProduction, checker.Fetcher must be one whose
// HardenedForProduction is true: this function doesn't know the
// Verifier's assurance level, so it can't refuse one that isn't; a
// StatusPolicy can.
func RequireValidStatus(checker statuslist.Checker) func(ctx context.Context, id string, result VerifyResponseResult) error {
	return RequireValidStatusFrom(checker, nil)
}

// RequireStatusReference is an Accept that refuses an answer with a
// credential carrying no status reference (no SD-JWT VC "status"
// claim, no mdoc MSO status), then runs accept, if set, on it:
//
//	Accept: verifier.RequireStatusReference(verifier.RequireValidStatus(checker)),
//
// StatusPolicy.RequireReference does the same before Accept.
//
// RequireValidStatus alone lets such a credential through, which an
// issuer can't revoke afterwards: a stolen document signer's or issuer's
// key, say, could mint them until its certificate is revoked — and,
// with an issuer key resolver whose Revocation is
// certrevocation.NoCheck{}, until it expires. An mdoc identifier list
// is a reference too; a status naming no mechanism this package knows,
// or a malformed one, isn't: nothing here could check it.
func RequireStatusReference(accept func(ctx context.Context, id string, result VerifyResponseResult) error) func(ctx context.Context, id string, result VerifyResponseResult) error {
	return func(ctx context.Context, id string, result VerifyResponseResult) error {
		if err := requireReferences(result.Credentials); err != nil {
			return err
		}
		if accept == nil {
			return nil
		}
		return accept(ctx, id, result)
	}
}

// requireReferences refuses a credential among vcs with no status
// reference this package can check: a Token Status List entry, or an
// mdoc identifier list.
func requireReferences(vcs []VerifiedCredential) error {
	for _, vc := range vcs {
		_, _, ok, _ := vc.StatusListRef()
		if !ok && (vc.MdocStatus == nil || vc.MdocStatus.IdentifierList == nil) {
			return fmt.Errorf("verifier: credential status: the credential for credential query %q carries no status reference this package can check", vc.CredentialQueryID)
		}
	}
	return nil
}

// StatusIssuerPolicy decides whether leaf, the chain-verified
// certificate that signed a Status List Token, belongs to a Status
// Issuer trusted to sign issuer's status lists: nil to accept it, an
// error to refuse. issuer is the credential's (its iss, or the URI its
// own certificate names), so a Status Issuer can be accepted for some
// issuers and not others; it's "" for an mdoc, or an SD-JWT VC with
// neither, so decide from leaf and chains.
type StatusIssuerPolicy func(issuer string, leaf *x509.Certificate, chains [][]*x509.Certificate) error

// RequireValidStatusFrom is RequireValidStatus for deployments whose
// status lists may be signed by a separate Status Issuer on the
// credential issuer's behalf (draft-ietf-oauth-status-list): an SD-JWT
// VC's Status List Token is accepted when its signer is the
// credential's issuer, as RequireValidStatus requires, or a Status
// Issuer statusIssuers accepts for that issuer. Anyone else under the
// roots is refused. checker.Options.LeafPolicy, if set, still applies
// to every signer. For an mdoc's identifier list, statusIssuers decides
// the signer only when the mdoc carries no issuer chain and its MSO
// names no Certificate. A nil statusIssuers is RequireValidStatus.
func RequireValidStatusFrom(checker statuslist.Checker, statusIssuers StatusIssuerPolicy) func(ctx context.Context, id string, result VerifyResponseResult) error {
	policy := &StatusPolicy{Checker: checker, StatusIssuers: statusIssuers}
	return func(ctx context.Context, _ string, result VerifyResponseResult) error {
		return policy.Check(ctx, result.Credentials...)
	}
}

// requireValid checks every status reference vc carries.
func requireValid(ctx context.Context, checker statuslist.Checker, statusIssuers StatusIssuerPolicy, vc VerifiedCredential) error {
	if vc.MdocStatus != nil && vc.MdocStatus.IdentifierList != nil {
		if err := requireNotOnIdentifierList(ctx, checker, statusIssuers, vc); err != nil {
			return err
		}
		if vc.MdocStatus.StatusList == nil {
			return nil
		}
	}
	ref, cwt, ok, err := vc.StatusListRef()
	if err != nil || !ok {
		return err
	}
	// Its status list is its issuer's, or its Status Issuer's, to sign.
	c := checker
	if cwt {
		c, err = mdocStatusChecker(checker, vc, statusIssuers)
	} else {
		c.Options, err = statusOptionsFor(c.Options, vc.issuerName(), vc.issuerKey(), statusIssuers)
	}
	if err != nil {
		return err
	}
	return c.RequireValid(ctx, ref, cwt)
}

// requireNotOnIdentifierList checks the identifier list vc's MSO names,
// with checker's Fetcher, Roots and Options. Its signer is bound to the
// mdoc's issuer by §12.3.6.2's rule alone: statusIssuers decides it only
// when the mdoc has no issuer chain and its MSO names no Certificate.
func requireNotOnIdentifierList(ctx context.Context, checker statuslist.Checker, statusIssuers StatusIssuerPolicy, vc VerifiedCredential) error {
	ref := identifierlist.Ref(*vc.MdocStatus.IdentifierList)
	path, err := vc.issuerPath()
	if err != nil {
		return err
	}
	o := checker.Options
	c := identifierlist.Checker{Fetcher: checker.Fetcher, Roots: checker.Roots, Options: identifierlist.VerifyOptions{
		Now: o.Now, MaxAge: o.MaxAge, MaxClockSkew: o.MaxClockSkew, LeafPolicy: o.LeafPolicy, Revocation: o.Revocation,
	}}
	if len(path) == 0 && len(ref.Certificate) == 0 {
		// Nothing ties the list's signer to the document's issuer but
		// statusIssuers.
		if statusIssuers == nil {
			return errUnboundStatusSigner
		}
		c.Options.UnboundSigner = unnamedStatusIssuer(statusIssuers)
	}
	return c.RequireNotRevoked(ctx, ref, path)
}

// unnamedStatusIssuer is statusIssuers as a LeafPolicy, for a credential
// with no issuer name.
func unnamedStatusIssuer(statusIssuers StatusIssuerPolicy) func(*x509.Certificate, [][]*x509.Certificate) error {
	return func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		return statusIssuers("", leaf, chains)
	}
}

// statusOptionsFor is opts for checking issuer's status list: signed by
// issuer, or with statusIssuers, by issuer or a Status Issuer it
// accepts for issuer. With neither issuer nor issuerKey, nothing binds
// the signer but statusIssuers, so it's required.
func statusOptionsFor(opts statuslist.VerifyOptions, issuer string, issuerKey crypto.PublicKey, statusIssuers StatusIssuerPolicy) (statuslist.VerifyOptions, error) {
	if issuer == "" && issuerKey == nil && statusIssuers == nil {
		return opts, errUnboundStatusSigner
	}
	if statusIssuers == nil {
		opts.Issuer, opts.IssuerKey = issuer, issuerKey
		return opts, nil
	}
	base := opts.LeafPolicy
	opts.LeafPolicy = func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		if base != nil {
			if err := base(leaf, chains); err != nil {
				return err
			}
		}
		if certchain.SameKey(leaf.PublicKey, issuerKey) || (issuer != "" && certchain.CheckIssuerName(leaf, issuer) == nil) {
			return nil
		}
		if err := statusIssuers(issuer, leaf, chains); err != nil {
			return fmt.Errorf("neither the credential's issuer %q nor a Status Issuer for it: %w", issuer, err)
		}
		return nil
	}
	// A Status Issuer's token may carry its own iss.
	opts.Issuer = ""
	return opts, nil
}

// errUnboundStatusSigner refuses a status check whose Status List Token
// signer nothing ties to the credential's issuer: any CA under the
// checker's roots could sign a VALID list for it.
var errUnboundStatusSigner = errors.New("the credential was verified with no issuer certificate, so its status list's signer can't be bound to its issuer: verify it with a resolver that reports its issuer chain, or pass RequireValidStatusFrom a StatusIssuerPolicy (AnyStatusListSigner, to accept every signer under the checker's roots)")

// AnyStatusListSigner is a StatusIssuerPolicy accepting every Status
// List Token signer under the checker's roots, for any credential:
// pass it to RequireValidStatusFrom only where every signer those roots
// anchor may decide every credential's status — roots of one issuer
// alone, say. Without a policy, a credential that can't be tied to an
// issuer certificate (verified by a resolver that reports no issuer
// chain) has its status check refused.
func AnyStatusListSigner(string, *x509.Certificate, [][]*x509.Certificate) error { return nil }

// issuerName is an SD-JWT VC's issuer, for its status list: its iss,
// or without one the URI its x5c leaf names, which is then the issuer.
// "" when it has neither, and its status list isn't bound to it.
func (vc VerifiedCredential) issuerName() string {
	if iss, ok := vc.Claims["iss"].(string); ok && iss != "" {
		return iss
	}
	if len(vc.IssuerChain) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(vc.IssuerChain[0])
	if err != nil || len(leaf.URIs) == 0 {
		return ""
	}
	return leaf.URIs[0].String()
}

// issuerKey is the public key that signed vc, from the issuer chain it
// was verified with; nil without one.
func (vc VerifiedCredential) issuerKey() crypto.PublicKey {
	if len(vc.IssuerChain) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(vc.IssuerChain[0])
	if err != nil {
		return nil
	}
	return leaf.PublicKey
}

// mdocStatusChecker is checker for an mdoc's revocation list: its
// signer trusted as ISO/IEC 18013-5 §12.3.6 says (mdoc.StatusTrust), or
// a Status Issuer statusIssuers accepts, given no issuer name. An mdoc
// verified with no issuer chain, and whose MSO names no status
// Certificate, is refused unless statusIssuers decides its signer. The
// list must carry exp and its signer's x5chain protected (§12.3.6.3).
func mdocStatusChecker(checker statuslist.Checker, vc VerifiedCredential, statusIssuers StatusIssuerPolicy) (statuslist.Checker, error) {
	var ref *mdoc.StatusListRef
	if vc.MdocStatus != nil {
		ref = vc.MdocStatus.StatusList
	}
	path, err := vc.issuerPath()
	if err != nil {
		return checker, err
	}
	c := checker
	c.Options.RequireExp = true
	c.Options.X5ChainProtectedOnly = true
	base := checker.Options.LeafPolicy
	if (ref == nil || len(ref.Certificate) == 0) && len(path) == 0 {
		// Nothing ties the list's signer to the document's issuer but
		// statusIssuers.
		if statusIssuers == nil {
			return checker, errUnboundStatusSigner
		}
		c.Options.LeafPolicy = certchain.BothPolicies(base, unnamedStatusIssuer(statusIssuers))
		return c, nil
	}
	trust, err := mdoc.StatusTrust(ref, path)
	if err != nil {
		return checker, err
	}
	if trust.Roots != nil {
		c.Roots = trust.Roots
		return c, nil
	}
	c.Options.LeafPolicy = func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		if base != nil {
			if err := base(leaf, chains); err != nil {
				return err
			}
		}
		err := trust.LeafPolicy(leaf, chains)
		if err != nil && statusIssuers != nil && statusIssuers("", leaf, chains) == nil {
			return nil
		}
		return err
	}
	return c, nil
}

// issuerPath is vc.IssuerChain parsed: an mdoc's document signer path
// as verified, leaf first, without its anchor.
func (vc VerifiedCredential) issuerPath() ([]*x509.Certificate, error) {
	path := make([]*x509.Certificate, 0, len(vc.IssuerChain))
	for _, der := range vc.IssuerChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("issuer chain: %w", err)
		}
		path = append(path, cert)
	}
	return path, nil
}
