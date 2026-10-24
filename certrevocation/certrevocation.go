package certrevocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
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
	// below its last, the trust anchor, is revoked at check.Now. An
	// error refuses the chain: one that wraps ErrRevoked when a
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
	// revocation information; the anchor itself never is.
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
// falls in [thisUpdate, nextUpdate). A list without a nextUpdate is
// never current: it gives no time after which a relying party must
// look again. Only complete, direct CRLs are used: a delta CRL, or one
// whose issuing distribution point extension limits its scope (to some
// reasons, to CA or end-entity certificates, or to an indirect CRL's
// other issuers), is skipped rather than read as complete. A
// certificate is refused with ErrRevoked when a usable list names its
// serial number, and with ErrNoCurrentCRL when its issuer has no usable
// list at all — a missing or stale CRL fails closed rather than letting
// a revoked certificate through.
type CRLs struct {
	// Lists returns the current CRLs: at least one from each CA that
	// issues a certificate in a chain checked — the CA issuing leaf
	// certificates, and the CA above each intermediate. It is called on
	// every check: keep the parsed lists in memory and refresh them in
	// the background before their nextUpdate, rather than fetching
	// here, where a slow or unreachable distribution point would hold
	// up every verification. An error refuses the chain, wrapped.
	// Required.
	Lists func(ctx context.Context) ([]*x509.RevocationList, error)
}

var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
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
	return nil
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
	if list.NextUpdate.IsZero() || now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) {
		return false
	}
	for _, ext := range list.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) || ext.Id.Equal(oidIssuingDistributionPoint) {
			return false
		}
	}
	return list.CheckSignatureFrom(issuer) == nil
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
