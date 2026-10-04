package walletflow

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/registration"
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
	// nil path is every claim of the credential (Status verified).
	// Nothing is refused for it: the holder decides.
	Unregistered map[string][]dcql.Path
}

// checkRegistration verifies the request's registrations: those in this
// library's format (registration.Recognize), against RegistrarRoots,
// for this Verifier. Attestations in other formats are ignored
// (OpenID4VP 1.0 §5.11). A Credential Query no verified registration
// applies to is unregistered in full.
func (p *Presentation) checkRegistration(now time.Time) Registration {
	if p.w.cfg.RegistrarRoots == nil {
		return Registration{Status: RegistrationNone}
	}
	out, applies := p.verifyRegistrations(now)
	if out.Status != RegistrationVerified {
		return out
	}
	out.Unregistered = map[string][]dcql.Path{}
	for _, cq := range p.req.Query.Credentials {
		reg := applies[cq.ID]
		if reg == nil {
			reg = &registration.Registration{}
		}
		if over := reg.Unregistered(dcql.Query{Credentials: []dcql.CredentialQuery{cq}})[cq.ID]; len(over) > 0 {
			out.Unregistered[cq.ID] = over
		}
	}
	return out
}

// verifyRegistrations verifies the request's registrations in this
// library's format, returning the first that verifies (or whether any
// failed), and for each Credential Query ID the first verified one
// applying to it.
func (p *Presentation) verifyRegistrations(now time.Time) (Registration, map[string]*registration.Registration) {
	out := Registration{Status: RegistrationNone}
	applies := map[string]*registration.Registration{}
	for _, vi := range p.req.VerifierInfo {
		data, ok := vi.DataString()
		if !ok || !registration.Recognize(vi.Format, data) {
			continue
		}
		reg, err := registration.VerifyWithPolicy(data, p.w.cfg.RegistrarRoots, p.req.ClientID, now, p.w.cfg.RegistrarLeafPolicy)
		if err == nil && signedBySelf(reg, p.req.VerifierCertificate) {
			err = errSelfRegistered
		}
		switch {
		case err != nil && out.Status == RegistrationNone:
			out.Status = RegistrationInvalid
		case err == nil && out.Status != RegistrationVerified:
			out.Status, out.Registration = RegistrationVerified, reg
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
