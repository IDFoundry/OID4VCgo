package walletflow

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/registration"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// RegistrationStatus is what the wallet found of the Verifier's
// registration.
type RegistrationStatus string

const (
	// RegistrationNone: the request carries no registration the wallet
	// checks (or Config.RegistrarRoots is unset).
	RegistrationNone RegistrationStatus = "none"
	// RegistrationVerified: a registrar the wallet trusts registered
	// this Verifier.
	RegistrationVerified RegistrationStatus = "verified"
	// RegistrationInvalid: the request carries a registration that
	// didn't verify — another registrar's, another Verifier's, expired
	// or altered. It's not relied on.
	RegistrationInvalid RegistrationStatus = "invalid"
)

// Registration is the Verifier's registration (the registration
// package), from its request's verifier_info (OpenID4VP 1.0 §5.11),
// verified against Config.RegistrarRoots and bound to its client_id.
type Registration struct {
	Status RegistrationStatus
	// Registration is what the registrar attests (Status verified).
	registration.Registration
	// Unregistered is, for each Credential Query ID, the claims the
	// request asks for beyond what this Verifier is registered for — a
	// nil path is a query naming no claims, flagged in full (see
	// registration.Registration.Unregistered: OpenID4VP 1.0 §6.4.1 reads
	// it as asking for no selectively disclosable claims) — then those answering
	// it with a held credential would disclose along with what it asks
	// for, beyond the registration: the plaintext members of a disclosed
	// object or array element, the other elements of an array disclosed
	// as one (wallet.PreviewedCredential.DisclosedAlong), for any of the
	// query's credentials (Status verified). Nothing is refused for it:
	// the holder decides.
	Unregistered map[string][]dcql.Path
}

// checkRegistration verifies the request's registrations: those in this
// library's format (registration.Recognize), against RegistrarRoots,
// for this Verifier. Attestations in other formats are ignored
// (OpenID4VP 1.0 §5.11). A Credential Query no verified registration
// applies to is unregistered in full. It judges what the query's
// credentials (p.queries) would disclose too, not only the paths asked
// for: a registered path within a Disclosure doesn't cover the rest of
// it.
func (p *Presentation) checkRegistration(ctx context.Context, now time.Time) Registration {
	if p.w.cfg.RegistrarRoots == nil {
		return Registration{Status: RegistrationNone}
	}
	out, applies := p.verifyRegistrations(ctx, now)
	if out.Status != RegistrationVerified {
		return out
	}
	out.Unregistered = map[string][]dcql.Path{}
	for i, cq := range p.req.Query.Credentials {
		reg := applies[cq.ID]
		if reg == nil {
			reg = &registration.Registration{}
		}
		over := reg.Unregistered(dcql.Query{Credentials: []dcql.CredentialQuery{cq}})[cq.ID]
		if !slices.ContainsFunc(over, func(path dcql.Path) bool { return path == nil }) {
			for _, c := range p.queries[i].Credentials {
				for _, leaf := range reg.UnregisteredRevealed(cq, disclosedAlong(ctx, cq, c)) {
					if !slices.ContainsFunc(over, func(path dcql.Path) bool { return slices.Equal(path, leaf) }) {
						over = append(over, leaf)
					}
				}
			}
		}
		if len(over) > 0 {
			out.Unregistered[cq.ID] = over
		}
	}
	return out
}

// disclosedAlong is what answering cq with c would disclose along with
// the claims cq asks for (wallet.PreviewedCredential.DisclosedAlong):
// nothing for an mdoc, or a credential the preview can't read.
func disclosedAlong(ctx context.Context, cq dcql.CredentialQuery, c StoredCredential) []dcql.Path {
	preview, err := wallet.PreviewPresentation(ctx, dcql.Query{Credentials: []dcql.CredentialQuery{cq}}, []wallet.HeldCredential{heldCredential(c, nil)}, trustedAuthorities)
	if err != nil || len(preview) != 1 {
		return nil
	}
	return preview[0].DisclosedAlong
}

// verifyRegistrations verifies the request's registrations in this
// library's format, returning the first that verifies (or whether any
// failed), and for each Credential Query ID the first verified one
// applying to it.
func (p *Presentation) verifyRegistrations(ctx context.Context, now time.Time) (Registration, map[string]*registration.Registration) {
	out := Registration{Status: RegistrationNone}
	applies := map[string]*registration.Registration{}
	for _, vi := range p.req.VerifierInfo {
		reg, recognized, err := p.verifyEntry(ctx, vi, now)
		switch {
		case !recognized:
			continue
		case err != nil && out.Status == RegistrationNone:
			out.Status = RegistrationInvalid
		case err == nil && out.Status != RegistrationVerified:
			out.Status, out.Registration = RegistrationVerified, reg
			// The registrar's text, for the holder's screen: as an
			// issuer's display text (displayText).
			out.Name = displayText(reg.Name, maxDisplayName)
			out.Purpose = displayText(reg.Purpose, maxDisplayDescription)
		}
		if err != nil {
			continue
		}
		for _, cq := range p.req.Query.Credentials {
			if vi.AppliesTo(cq.ID) && applies[cq.ID] == nil {
				applies[cq.ID] = &reg
			}
		}
	}
	return out, applies
}

// verifyEntry verifies one verifier_info entry as a registration:
// recognized is false for an attestation in another format, which is
// ignored (OpenID4VP 1.0 §5.11).
func (p *Presentation) verifyEntry(ctx context.Context, vi wallet.VerifierInfo, now time.Time) (reg registration.Registration, recognized bool, err error) {
	data, ok := vi.DataString()
	if !ok || !registration.Recognize(vi.Format, data) {
		return registration.Registration{}, false, nil
	}
	revocation := p.w.cfg.RegistrarRevocation
	if revocation == nil {
		// Development only: New requires a choice otherwise.
		revocation = certrevocation.NoCheck{}
	}
	registrars := registration.Registrars{Roots: p.w.cfg.RegistrarRoots, LeafPolicy: p.w.cfg.RegistrarLeafPolicy, Revocation: revocation}
	reg, err = registrars.Verify(ctx, data, p.req.ClientID, now)
	if err == nil && signedBySelf(reg, p.req.VerifierCertificate) {
		err = errSelfRegistered
	}
	return reg, true, err
}

// errSelfRegistered is a registration signed with the Verifier's own
// request-signing key: a Verifier vouching for itself.
var errSelfRegistered = errors.New("walletflow: the registration is signed by the Verifier itself")

// signedBySelf reports whether reg was signed with the same key as the
// Verifier's request-signing certificate.
func signedBySelf(reg registration.Registration, verifier *x509.Certificate) bool {
	if verifier == nil || reg.RegistrarCertificate == nil {
		return false
	}
	pub, ok := reg.RegistrarCertificate.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(verifier.PublicKey)
}

// Registration is the Verifier's registration, as checked when the
// presentation started.
func (p *Presentation) Registration() Registration { return p.registration }
