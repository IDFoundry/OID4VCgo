package certrevocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ErrRevoked is the error, through errors.Is, a Checker returns for a
// certificate its revocation information names as revoked.
var ErrRevoked = errors.New("certrevocation: certificate is revoked")

// ErrNoCurrentCRL is the error, through errors.Is, CRLs returns when a
// certificate's issuer has no usable CRL: none at all, or none that's
// current, complete and signed by that issuer. The certificate may well
// be good, but nothing says so, and CRLs fails closed rather than
// accept it unchecked — a deployment that sees it should look at how
// it refreshes its lists, not at the certificate.
var ErrNoCurrentCRL = errors.New("certrevocation: no current CRL from the certificate's issuer")

// Checker decides whether a certificate chain a relying party has
// verified includes a revoked certificate.
type Checker interface {
	// CheckRevocation returns nil when no certificate in check.Chain
	// below its last, the trust anchor, is revoked at check.Now (nor,
	// when the anchor isn't self-signed, the anchor: see Check.Chain).
	// An error refuses the chain: one that wraps ErrRevoked when a
	// certificate is revoked; any other when revocation can't be
	// decided, which a Checker should treat as a refusal too rather
	// than accept the certificate unchecked.
	CheckRevocation(ctx context.Context, check Check) error
}

// Check is what a Checker is asked about.
type Check struct {
	// Chain is a verified certificate path, leaf first, ending at the
	// trust anchor it was verified against. Every certificate below the
	// anchor is checked against its issuer's — the next certificate's —
	// revocation information. A self-signed anchor, a root, never is.
	// An anchor that isn't self-signed — a leaf pinned as a trust
	// anchor, or an intermediate CA certificate placed among the roots —
	// is checked against the revocation information of the CA it names
	// as its issuer. Otherwise pinning a certificate would exempt it
	// from revocation altogether, and a pool holding a revoked
	// intermediate beside its root would verify the path ending at the
	// intermediate, on which the root's revocation of it is never asked.
	Chain []*x509.Certificate
	// Now is the instant the chain was verified at, at which a CRL must
	// be current; CRLs takes a zero Now as the current time.
	Now time.Time
}

// CRLs checks a chain against Certificate Revocation Lists (RFC 5280
// §5). Every certificate below the trust anchor is checked against a
// CRL its issuer signed: the leaf against its CA's, and an
// intermediate CA against the CA above it.
//
// A list is used for an issuer only when its issuer name matches, its
// signature verifies against that issuer's key, and the check's Now
// falls in [thisUpdate, nextUpdate), its thisUpdate allowed up to
// CRLClockSkew ahead of Now. A list without a nextUpdate is never
// current: it gives no time after which a relying party must look
// again. Only complete, direct CRLs are used: a delta CRL, or one
// whose issuing distribution point extension limits its scope (to some
// reasons, to CA or end-entity certificates, or to an indirect CRL's
// other issuers), is skipped rather than read as complete. So is one
// carrying a critical extension, on the list or on an entry, other
// than the few this package processes (the authority key identifier,
// CRL number, reason code and invalidity date), which RFC 5280 §5.2
// and §5.3 forbid using at all. A
// certificate is refused with ErrRevoked when a usable list names its
// serial number, and with ErrNoCurrentCRL when its issuer has no usable
// list at all — a missing or stale CRL fails closed rather than letting
// a revoked certificate through.
//
// A chain ending at a certificate that isn't self-signed is checked
// against a CRL from the CA that certificate names as its issuer too: a
// leaf pinned in the roots, which x509 verifies as the path [leaf], or
// an intermediate CA certificate among the roots, which x509 verifies
// as a path ending at it — beside the path through its root, when the
// root is in the pool as well. That CA isn't on the path, so its
// certificate, needed to verify the CRL's signature, comes from
// Issuers: without it there, the chain is refused with ErrNoCurrentCRL.
// A self-signed anchor, a root, has no issuer to ask and isn't checked.
// Where revocation is checked, put only self-signed roots in the trust
// anchors: an intermediate there (a "whole chain" bundle loaded as the
// roots, say) needs its own CA's certificate in Issuers and a current
// CRL from it, or every path ending at it is refused.
type CRLs struct {
	// Lists returns the current CRLs: at least one from each CA that
	// issues a certificate in a chain checked — the CA issuing leaf
	// certificates, and the CA above each intermediate. It is called on
	// every check: keep the parsed lists in memory and refresh them in
	// the background before their nextUpdate, rather than fetching
	// here, where a slow or unreachable distribution point would hold
	// up every verification. Refresher does that for lists fetched
	// over HTTP: pass its Lists method, or use Refresher.Checker. An
	// error refuses the chain, wrapped. Required.
	Lists func(ctx context.Context) ([]*x509.RevocationList, error)

	// Issuers are the certificates of CAs that issued trust anchors
	// that aren't self-signed, used only to check such an anchor: the
	// one whose name and key issued it is the issuer its CRL must come
	// from and be verified against. They're neither trust anchors nor
	// checked for revocation themselves. Needed only where a leaf or an
	// intermediate CA, rather than a root, is among the trust anchors;
	// Refresher.Checker sets its configured issuers here.
	Issuers []*x509.Certificate
}

// CRLClockSkew is how far ahead of the current time a CRL's thisUpdate
// may be and the CRL still be used, by CRLs and Refresher alike: a CA
// whose clock runs a little fast would otherwise publish CRLs unusable
// for their first moments.
const CRLClockSkew = 5 * time.Minute

var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}

	// understoodCRLExtensions are the CRL extensions, and
	// understoodEntryExtensions the CRL entry extensions, a critical
	// one of which doesn't keep a list from being used: the authority
	// key identifier and CRL number, which x509 parses, and the reason
	// code and invalidity date, which don't change that an entry
	// revokes its certificate.
	understoodCRLExtensions   = []asn1.ObjectIdentifier{{2, 5, 29, 35}, {2, 5, 29, 20}}
	understoodEntryExtensions = []asn1.ObjectIdentifier{{2, 5, 29, 21}, {2, 5, 29, 24}}
)

// Validate reports a CRLs that can't check anything: one without Lists.
// A configuration that takes a Checker calls it when it's built, so the
// mistake shows then rather than on the first verification.
func (c CRLs) Validate() error {
	if c.Lists == nil {
		return errors.New("certrevocation: CRLs.Lists is required")
	}
	return nil
}

// CheckRevocation implements Checker.
func (c CRLs) CheckRevocation(ctx context.Context, check Check) error {
	if err := c.Validate(); err != nil {
		return err
	}
	lists, err := c.Lists(ctx)
	if err != nil {
		return fmt.Errorf("certrevocation: CRLs: %w", err)
	}
	now := check.Now
	if now.IsZero() {
		now = time.Now()
	}
	for i := 0; i+1 < len(check.Chain); i++ {
		if err := checkAgainstCRLs(check.Chain[i], check.Chain[i+1], lists, now); err != nil {
			return err
		}
	}
	if len(check.Chain) == 0 {
		return nil
	}
	if anchor := check.Chain[len(check.Chain)-1]; !selfSigned(anchor) {
		return c.checkAnchor(anchor, lists, now)
	}
	return nil
}

// checkAnchor checks cert, a trust anchor that isn't self-signed,
// against a CRL from the one of c.Issuers that issued it.
func (c CRLs) checkAnchor(cert *x509.Certificate, lists []*x509.RevocationList, now time.Time) error {
	for _, issuer := range c.Issuers {
		if issuer != nil && bytes.Equal(cert.RawIssuer, issuer.RawSubject) && cert.CheckSignatureFrom(issuer) == nil {
			return checkAgainstCRLs(cert, issuer, lists, now)
		}
	}
	return fmt.Errorf("%w: %q is a trust anchor that isn't self-signed, and the certificate of its issuer %q, to verify a CRL against, isn't among CRLs.Issuers", ErrNoCurrentCRL, cert.Subject, cert.Issuer)
}

// selfSigned reports whether cert names itself as its issuer and its
// own key verifies its signature.
func selfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// checkAgainstCRLs refuses cert when a usable CRL from issuer names it,
// or when issuer has no usable CRL.
func checkAgainstCRLs(cert, issuer *x509.Certificate, lists []*x509.RevocationList, now time.Time) error {
	usable := false
	for _, list := range lists {
		if !crlUsableFor(list, issuer, now) {
			continue
		}
		usable = true
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("%w: %q (serial %s), by %q", ErrRevoked, cert.Subject, cert.SerialNumber, issuer.Subject)
			}
		}
	}
	if !usable {
		return fmt.Errorf("%w: %q, for %q", ErrNoCurrentCRL, issuer.Subject, cert.Subject)
	}
	return nil
}

// crlUsableFor reports whether list is a complete, current CRL issuer
// signed.
func crlUsableFor(list *x509.RevocationList, issuer *x509.Certificate, now time.Time) bool {
	if list == nil || !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
		return false
	}
	if list.NextUpdate.IsZero() || notYetValid(list, now) || !now.Before(list.NextUpdate) {
		return false
	}
	return completeAndDirect(list) && criticalUnderstood(list) && list.CheckSignatureFrom(issuer) == nil
}

// notYetValid reports whether list's thisUpdate is more than
// CRLClockSkew after now.
func notYetValid(list *x509.RevocationList, now time.Time) bool {
	return now.Add(CRLClockSkew).Before(list.ThisUpdate)
}

// criticalUnderstood reports whether every critical extension list
// carries, on the list itself or on an entry, is one this package
// understands.
func criticalUnderstood(list *x509.RevocationList) bool {
	for _, ext := range list.Extensions {
		if ext.Critical && !slices.ContainsFunc(understoodCRLExtensions, ext.Id.Equal) {
			return false
		}
	}
	for _, entry := range list.RevokedCertificateEntries {
		for _, ext := range entry.Extensions {
			if ext.Critical && !slices.ContainsFunc(understoodEntryExtensions, ext.Id.Equal) {
				return false
			}
		}
	}
	return true
}

// completeAndDirect reports whether list is neither a delta CRL nor one
// an issuing distribution point extension may limit the scope of.
func completeAndDirect(list *x509.RevocationList) bool {
	for _, ext := range list.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) || ext.Id.Equal(oidIssuingDistributionPoint) {
			return false
		}
	}
	return true
}

// NoCheck explicitly declines checking revocation: every chain passes.
// It exists so that declining is a visible line of code, never a
// Revocation field left unset by mistake. It's the right choice only
// where something else stands in for revocation: certificates so
// short-lived that one compromised is no worse than its remaining
// validity, a trust framework that removes a compromised issuer from
// the trust anchor set itself (and gets that change to every relying
// party promptly), or a test or conformance setup whose certificates
// publish no revocation information. Anywhere else, a certificate
// whose key was stolen keeps being accepted until it expires.
type NoCheck struct{}

// CheckRevocation implements Checker by accepting every chain.
func (NoCheck) CheckRevocation(context.Context, Check) error { return nil }
