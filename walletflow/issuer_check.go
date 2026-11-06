package walletflow

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Why a credential's status is what it is, in CredentialStatus.Reason.
const (
	// ReasonStatusList is a status the issuer's Token Status List gives
	// a copy: StatusInvalid (revoked, final), StatusSuspended or an
	// application-specific "0x" value.
	ReasonStatusList = "status_list"
	// ReasonIdentifierList is an mdoc on its issuer's identifier list
	// (ISO/IEC 18013-5 §12.3.6.4): StatusInvalid, final.
	ReasonIdentifierList = "identifier_list"
	// ReasonIssuerCertificateRevoked is StatusInvalid because the
	// certificate that signed every copy still live, or a CA above it,
	// is revoked (certrevocation.ErrRevoked under
	// Config.IssuerRevocation). It isn't final: a later check with a
	// CRL that no longer lists it (a lifted certificateHold) makes the
	// credential valid again.
	ReasonIssuerCertificateRevoked = "issuer_certificate_revoked"
	// ReasonIssuerUntrusted is StatusInvalid because the certificate
	// chain that signed every copy still live no longer verifies under
	// the issuer roots and leaf policy configured now: the issuer was
	// removed from them, or a certificate on the chain has expired. Not
	// final either.
	ReasonIssuerUntrusted = "issuer_untrusted"
	// ReasonNoCurrentCRL is StatusUnknown because a revocation check
	// couldn't be decided for want of a current CRL
	// (certrevocation.ErrNoCurrentCRL) from a CA on the issuer's chain
	// or on a status list's signer's: refresh the revocation lists and
	// check again.
	ReasonNoCurrentCRL = "no_current_crl"
	// ReasonUnrecognizedStatus is StatusUnknown because the credential
	// has a status naming no mechanism the wallet knows (see
	// StatusUnknown).
	ReasonUnrecognizedStatus = "unrecognized_status"
)

// issuerOutcome is what checking one copy's issuer certificate chain
// found.
type issuerOutcome int

const (
	// issuerTrusted: the chain verifies and isn't revoked.
	issuerTrusted issuerOutcome = iota
	// issuerRevoked: a certificate on every verified path is revoked.
	issuerRevoked
	// issuerUntrusted: the chain no longer verifies under the roots
	// and leaf policy configured now.
	issuerUntrusted
	// issuerUndecided: revocation couldn't be decided for want of a
	// current CRL.
	issuerUndecided
)

// issuerChecks are the outcomes of checking the issuer certificate
// chains of a credential's live copies, by their Credential: empty when
// none has a chain to check.
type issuerChecks map[string]issuerOutcome

// checkIssuers checks the issuer certificate chain each copy of c live
// at now carries (an SD-JWT VC's x5c, an mdoc's IssuerAuth x5chain)
// against the issuer roots and leaf policy configured for c now and
// Config.IssuerRevocation, at now, as on receipt: so a signer revoked
// since, or an issuer no longer trusted, is seen. A copy carrying no
// chain, or a wallet configured with no issuer roots for c, has nothing
// to check and is left out. Revocation that can't be decided for
// another reason than a missing CRL (a Checker's own failure) is an
// error, as a status list that can't be fetched is.
func (w *Wallet) checkIssuers(ctx context.Context, c StoredCredential, now time.Time) (issuerChecks, error) {
	roots, policy := w.cfg.issuerTrust(c.Format, c.DocType)
	if roots == nil {
		return nil, nil
	}
	if policy == nil && c.Format == mdoc.CredentialFormat {
		// As wallet.VerifyIssuedCredential has it on receipt.
		policy = mdoc.DefaultDocumentSignerPolicy
	}
	checks := issuerChecks{}
	// A batch's copies usually carry one chain: each chain is verified
	// once.
	byChain := map[[sha256.Size]byte]issuerOutcome{}
	for _, cp := range c.AllCopies() {
		if !copyLive(c, cp, now) {
			continue
		}
		if _, done := checks[cp.Credential]; done {
			continue
		}
		chain := issuerChain(c.Format, cp.Credential)
		if len(chain) == 0 {
			continue
		}
		digest := chainDigest(chain)
		if check, done := byChain[digest]; done {
			checks[cp.Credential] = check
			continue
		}
		_, _, err := certchain.VerifyTrustedChainsAt(ctx, chain, roots, policy, w.cfg.IssuerRevocation, now)
		var check issuerOutcome
		switch {
		case err == nil:
			check = issuerTrusted
		case errors.Is(err, certrevocation.ErrNoCurrentCRL):
			check = issuerUndecided
		case errors.Is(err, certchain.ErrRevocationUndecided):
			return nil, err
		case errors.Is(err, certrevocation.ErrRevoked):
			check = issuerRevoked
		default:
			check = issuerUntrusted
		}
		checks[cp.Credential], byChain[digest] = check, check
	}
	return checks, nil
}

// chainDigest names chain, its certificates as DER, each length
// prefixed so that no two chains share it.
func chainDigest(chain [][]byte) [sha256.Size]byte {
	h := sha256.New()
	for _, der := range chain {
		_ = binary.Write(h, binary.BigEndian, uint32(len(der))) // #nosec G115 -- a certificate is far below 4 GiB
		h.Write(der)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// issuerChain is the certificate chain, leaf first, as DER, that
// credential, one stored copy in format, carries for its signer: an
// SD-JWT VC's x5c, an mdoc's IssuerAuth x5chain. nil when it carries
// none or can't be read: it was verified on receipt.
func issuerChain(format, credential string) [][]byte {
	switch format {
	case sdjwtvc.CredentialFormat:
		issuerJWT, _, _ := strings.Cut(credential, "~")
		header, _, err := jose.DecodeUnverified(issuerJWT)
		if err != nil {
			return nil
		}
		ders, err := certchain.X5CDERsFromHeader(header)
		if err != nil {
			return nil
		}
		return ders
	case mdoc.CredentialFormat:
		issuerSigned, err := storedIssuerSigned(credential)
		if err != nil {
			return nil
		}
		_, path, err := mdoc.IssuerAuthStatus(issuerSigned)
		if err != nil {
			return nil
		}
		ders := make([][]byte, len(path))
		for i, cert := range path {
			ders[i] = cert.Raw
		}
		return ders
	}
	return nil
}

// untrusted reports whether copy cp is to be marked IssuerUntrusted
// after checks: refused now, or undecided and marked before.
func (checks issuerChecks) untrusted(cp CredentialCopy) bool {
	switch checks[cp.Credential] {
	case issuerRevoked, issuerUntrusted:
		return true
	case issuerUndecided:
		return cp.IssuerUntrusted
	}
	return false
}

// issuerStatus is what checks make of c, beside its lists: with
// revokedByList the copies its lists revoke, the reason c is
// StatusInvalid when no copy of c live at now is left that neither
// list nor checks refuse, ReasonNoCurrentCRL when a copy's revocation
// couldn't be decided, or "" when neither.
func (checks issuerChecks) issuerStatus(c StoredCredential, now time.Time, revokedByList map[string]bool) string {
	var refused, revoked, undecided, good bool
	for _, cp := range c.AllCopies() {
		if !copyLive(c, cp, now) || cp.Revoked || revokedByList[cp.Credential] {
			continue
		}
		outcome, checked := checks[cp.Credential]
		if !checked {
			// Live, with no chain to check: as good as it was.
			good = true
			continue
		}
		switch outcome {
		case issuerRevoked:
			refused, revoked = true, true
		case issuerUntrusted:
			refused = true
		case issuerUndecided:
			undecided = true
			good = good || !cp.IssuerUntrusted
		default:
			good = true
		}
	}
	switch {
	case refused && !good && !undecided:
		if revoked {
			return ReasonIssuerCertificateRevoked
		}
		return ReasonIssuerUntrusted
	case undecided:
		return ReasonNoCurrentCRL
	}
	return ""
}

// issuerReason reports whether reason, a CredentialStatus's, is one an
// issuer certificate check gave: not final, unlike a list's.
func issuerReason(reason string) bool {
	return reason == ReasonIssuerCertificateRevoked || reason == ReasonIssuerUntrusted
}
