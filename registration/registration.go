// Package registration is OID4VCgo's verifier registration attestation:
// a JWT a registrar issues for a relying party, saying who it is, why it
// asks, and which claims it's registered to request. A Verifier carries
// it in its request's verifier_info (OpenID4VP 1.0 §5.11), and a Wallet
// that trusts the registrar can show the holder who is asking and flag a
// request for more than the registration allows.
//
// OpenID4VP leaves verifier_info's formats to ecosystems and profiles;
// this is this library's own, not an ecosystem's (such as the EU's
// relying-party registration certificates). It's claim-bound (§5.11.1):
// its sub is the client_id of the request it's attached to, so a
// Verifier can't present another's registration.
//
// The JWT has typ Type, is signed with ES256, and carries the
// registrar's certificate chain in x5c. Its claims:
//
//	iss             the registrar: a URI subject alternative name of
//	                the signing certificate
//	sub             the relying party's client_id
//	iat, exp        when it was issued, and until when it holds
//	name            the relying party's name
//	purpose         why it asks, in words (optional)
//	privacy_policy  its privacy policy's https URL (optional)
//	claims          the claim paths it's registered to request, as DCQL
//	                claims paths (OpenID4VP 1.0 §7), from any type of
//	                credential (optional)
//	credentials     the claim paths it's registered to request from
//	                given types of credential: each entry's vct_values
//	                (SD-JWT VC) or doctype_value (mdoc), and its claims
//	                (optional)
package registration

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// Format is the verifier_info format a registration is carried as.
const Format = "jwt"

// Type is a registration JWT's typ header.
const Type = "verifier-registration+jwt"

// maxSkew is how far ahead of the Wallet's clock a registration's iat
// may be.
const maxSkew = 5 * time.Minute

// Registration is what a registrar attests about a relying party.
type Registration struct {
	// Registrar is the registrar's identifier (iss).
	Registrar string
	// ClientID is the relying party's client_id, the request's (sub).
	ClientID string
	// Name is the relying party's name; Purpose, why it asks.
	Name, Purpose string
	// PrivacyPolicy is its privacy policy's https URL, if given.
	PrivacyPolicy string
	// Claims are the claim paths it's registered to request, from any
	// type of credential. Prefer Credentials, which ties each to one:
	// a path registered here for a loyalty card is registered for a PID
	// too.
	Claims []dcql.Path
	// Credentials are the claim paths it's registered to request from
	// given types of credential.
	Credentials []RegisteredCredential
	// IssuedAt and Expires bound when the registration holds.
	IssuedAt, Expires time.Time
	// RegistrarCertificate is the certificate that signed it, chained
	// to the Wallet's registrar roots (set by Verify).
	RegistrarCertificate *x509.Certificate
}

// RegisteredCredential is a type of credential a relying party is
// registered to request claims from: an SD-JWT VC of one of VCTValues,
// or an mdoc of DoctypeValue.
type RegisteredCredential struct {
	VCTValues    []string    `json:"vct_values,omitempty"`
	DoctypeValue string      `json:"doctype_value,omitempty"`
	Claims       []dcql.Path `json:"claims"`
}

// covers reports whether rc is cq's type of credential: an mdoc query's
// doctype, or every vct an SD-JWT VC query accepts, since any of them
// may be the one presented.
func (rc RegisteredCredential) covers(cq dcql.CredentialQuery) bool {
	switch cq.Format {
	case "mso_mdoc":
		m, err := cq.MdocMeta()
		return err == nil && rc.DoctypeValue != "" && m.DoctypeValue == rc.DoctypeValue
	case "dc+sd-jwt":
		m, err := cq.SDJWTVCMeta()
		if err != nil || len(m.VCTValues) == 0 {
			return false
		}
		for _, vct := range m.VCTValues {
			if !slices.Contains(rc.VCTValues, vct) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (rc RegisteredCredential) validate() error {
	if (len(rc.VCTValues) == 0) == (rc.DoctypeValue == "") {
		return errors.New("registration: credentials: each entry needs vct_values or doctype_value, not both")
	}
	for _, p := range rc.Claims {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("registration: credentials: %w", err)
		}
	}
	return nil
}

type wireClaims struct {
	Iss           string                 `json:"iss"`
	Sub           string                 `json:"sub"`
	Iat           int64                  `json:"iat"`
	Exp           int64                  `json:"exp"`
	Name          string                 `json:"name"`
	Purpose       string                 `json:"purpose,omitempty"`
	PrivacyPolicy string                 `json:"privacy_policy,omitempty"`
	Claims        []dcql.Path            `json:"claims,omitempty"`
	Credentials   []RegisteredCredential `json:"credentials,omitempty"`
}

// Issue signs r as a registration JWT with key, carrying chain (the
// registrar's certificate first) in x5c. r needs a Registrar, ClientID,
// Name and Expires; IssuedAt defaults to now. r.Registrar must be a URI
// subject alternative name of chain[0], for Verify to accept it.
func Issue(r Registration, key *ecdsa.PrivateKey, chain []*x509.Certificate) (string, error) {
	if r.Registrar == "" || r.ClientID == "" || r.Name == "" || r.Expires.IsZero() || key == nil || len(chain) == 0 {
		return "", errors.New("registration: Registrar, ClientID, Name, Expires, a key and its certificate are required")
	}
	if err := checkPolicyURL(r.PrivacyPolicy); err != nil {
		return "", err
	}
	for _, p := range r.Claims {
		if err := p.Validate(); err != nil {
			return "", fmt.Errorf("registration: claims: %w", err)
		}
	}
	for _, rc := range r.Credentials {
		if err := rc.validate(); err != nil {
			return "", err
		}
	}
	if r.IssuedAt.IsZero() {
		r.IssuedAt = time.Now()
	}
	payload, err := json.Marshal(wireClaims{
		Iss: r.Registrar, Sub: r.ClientID, Iat: r.IssuedAt.Unix(), Exp: r.Expires.Unix(),
		Name: r.Name, Purpose: r.Purpose, PrivacyPolicy: r.PrivacyPolicy, Claims: r.Claims,
		Credentials: r.Credentials,
	})
	if err != nil {
		return "", fmt.Errorf("registration: %w", err)
	}
	x5c := make([]string, len(chain))
	for i, c := range chain {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	token, err := jose.Sign(jose.ES256, key, map[string]any{"typ": Type, "x5c": x5c}, payload)
	if err != nil {
		return "", fmt.Errorf("registration: sign: %w", err)
	}
	return token, nil
}

// Recognize reports whether a verifier_info entry of format, with data
// as a string, claims to be a registration in this format (its typ is
// Type) — so a Wallet can ignore another ecosystem's attestations and
// still tell a registration that fails Verify apart from them.
func Recognize(format, data string) bool {
	if format != Format {
		return false
	}
	header, _, err := jose.DecodeUnverified(data)
	if err != nil {
		return false
	}
	typ, _ := header["typ"].(string)
	return typ == Type
}

// Verify checks token, a registration JWT, as Registrars.Verify does,
// with roots, no revocation check (certrevocation.NoCheck) and
// DefaultRegistrarLeafPolicy.
//
// Deprecated: use Registrars.Verify, which takes a context and needs a
// decision on the registrars' certificates' revocation.
func Verify(token string, roots *x509.CertPool, clientID string, now time.Time) (Registration, error) {
	return VerifyWithPolicy(token, roots, clientID, now, nil)
}

// VerifyWithPolicy is Verify, with policy (if non-nil, in place of
// DefaultRegistrarLeafPolicy) deciding whether the verified signing
// certificate may act as a registrar.
//
// Deprecated: use Registrars.Verify, with LeafPolicy set to policy.
func VerifyWithPolicy(token string, roots *x509.CertPool, clientID string, now time.Time, policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error) (Registration, error) {
	return Registrars{Roots: roots, LeafPolicy: policy, Revocation: certrevocation.NoCheck{}}.Verify(context.Background(), token, clientID, now)
}

// Registrars are the registrars a Wallet recognizes: their trust
// anchors, which of the certificates under them may sign registrations,
// and the revocation check of those certificates.
type Registrars struct {
	// Roots are the trust anchors a registrar's certificate must chain
	// to. REQUIRED. They must anchor only registrars: any end-entity
	// certificate under them that LeafPolicy accepts can register any
	// Verifier, so a root that also issues Verifiers' or Issuers'
	// certificates would let them register themselves.
	Roots *x509.CertPool
	// LeafPolicy, if set, decides whether the verified signing
	// certificate may act as a registrar: an extended key usage or
	// certificate policy the ecosystem defines for registrars, say. nil
	// means DefaultRegistrarLeafPolicy. A LeafPolicy that's set replaces
	// it: one adding a requirement calls DefaultRegistrarLeafPolicy
	// first, so as not to drop its refusals, and AnyRegistrarLeaf opts
	// out of them explicitly.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// Revocation checks the registrar's certificate chain for
	// revocation: only a verified path LeafPolicy approves and
	// Revocation passes is accepted, and a registration signed by a
	// revoked certificate is refused with an error wrapping
	// certrevocation.ErrRevoked. REQUIRED, with no default: pass
	// certrevocation.CRLs{...} with your CAs' current lists, your own
	// certrevocation.Checker, or certrevocation.NoCheck{} to decline.
	Revocation certrevocation.Checker
}

// registrarRole is DefaultRegistrarLeafPolicy's role.
var registrarRole = certchain.LeafRole{
	Name:         "the registrar certificate",
	OtherISOEKUs: []asn1.ObjectIdentifier{certchain.MDLDocumentSignerEKU, certchain.ReaderAuthenticationEKU},
	Strict:       true,
}

// DefaultRegistrarLeafPolicy is the registrar certificate check
// Registrars.Verify makes where no LeafPolicy is set. It refuses a
// certificate whose key usage extension doesn't allow digital
// signatures, that is an OCSP signer, whose extended key usage lists
// any purpose that denotes another role — TLS server or client
// authentication, code signing, email protection, time stamping,
// IPsec, or ISO/IEC 18013-5's mDL document signer or mdoc reader
// authentication (Annex B) — or every verified path in chains (leaf
// first) of which has an intermediate CA whose extended key usage lists
// only such purposes. It accepts a certificate without those
// extensions, or whose extended key usage lists only
// anyExtendedKeyUsage or purposes of its own. It can't tell a
// registrar's certificate from a Verifier's that carries no extended
// key usage: Roots must still anchor only registrars, or LeafPolicy
// require the ecosystem's registrar purpose.
func DefaultRegistrarLeafPolicy(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return registrarRole.Check(leaf, chains)
}

// AnyRegistrarLeaf is a LeafPolicy that accepts every chain-verified
// leaf: the explicit opt-out of DefaultRegistrarLeafPolicy.
func AnyRegistrarLeaf(*x509.Certificate, [][]*x509.Certificate) error { return nil }

// Verify checks token, a registration JWT, and returns what it attests:
// its typ is Type, it's signed with ES256 by an end-entity certificate
// chaining to r.Roots (not self-signed, not a CA, for digital
// signatures) that r.LeafPolicy accepts and r.Revocation passes, its
// iss is one of that certificate's URI subject alternative names, it's
// for clientID (sub), and it holds at now.
func (r Registrars) Verify(ctx context.Context, token, clientID string, now time.Time) (Registration, error) {
	if r.Roots == nil {
		return Registration{}, errors.New("registration: no registrar roots")
	}
	if r.Revocation == nil {
		return Registration{}, fmt.Errorf("registration: Registrars.Revocation is required: %s", certchain.RevocationChoices)
	}
	if err := certchain.ValidateRevocation(r.Revocation); err != nil {
		return Registration{}, fmt.Errorf("registration: Revocation: %w", err)
	}
	if clientID == "" {
		// A registration is of a Client Identifier: a request without one
		// (an unsigned DC API request) has nothing to bind it to.
		return Registration{}, errors.New("registration: no client_id to bind the registration to")
	}
	header, _, err := jose.DecodeUnverified(token)
	if err != nil {
		return Registration{}, fmt.Errorf("registration: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != Type {
		return Registration{}, fmt.Errorf("registration: typ %q, want %q", typ, Type)
	}
	if alg, _ := header["alg"].(string); alg != string(jose.ES256) {
		return Registration{}, fmt.Errorf("registration: alg %q, want ES256", alg)
	}
	ders, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return Registration{}, fmt.Errorf("registration: %w", err)
	}
	policy := r.LeafPolicy
	if policy == nil {
		policy = DefaultRegistrarLeafPolicy
	}
	leaf, _, err := certchain.VerifyTrustedChainsAt(ctx, ders, r.Roots, policy, r.Revocation, now)
	if err != nil {
		return Registration{}, fmt.Errorf("registration: registrar certificate: %w", err)
	}
	_, payload, err := jose.Verify(jose.ES256, leaf.PublicKey, token)
	if err != nil {
		return Registration{}, fmt.Errorf("registration: signature: %w", err)
	}
	var c wireClaims
	if err := strictjson.Unmarshal(payload, &c); err != nil {
		return Registration{}, fmt.Errorf("registration: claims: %w", err)
	}
	issuedAt, iatErr := jwtdate.FromUnix(c.Iat)
	expires, expErr := jwtdate.FromUnix(c.Exp)
	switch {
	case c.Iss == "" || c.Name == "" || c.Exp == 0 || c.Iat == 0:
		return Registration{}, errors.New("registration: iss, name, iat and exp are required")
	case iatErr != nil || expErr != nil:
		return Registration{}, errors.New("registration: iat or exp is out of range")
	case c.Sub != clientID:
		return Registration{}, errors.New("registration: it's for another relying party")
	case !slices.ContainsFunc(leaf.URIs, func(u *url.URL) bool { return u.String() == c.Iss }):
		return Registration{}, errors.New("registration: iss isn't the signing certificate's: it must be one of its URI subject alternative names")
	case !now.Before(expires):
		return Registration{}, errors.New("registration: expired")
	case issuedAt.After(now.Add(maxSkew)):
		return Registration{}, errors.New("registration: issued in the future")
	}
	if err := checkPolicyURL(c.PrivacyPolicy); err != nil {
		return Registration{}, err
	}
	for _, p := range c.Claims {
		if err := p.Validate(); err != nil {
			return Registration{}, fmt.Errorf("registration: claims: %w", err)
		}
	}
	for _, rc := range c.Credentials {
		if err := rc.validate(); err != nil {
			return Registration{}, err
		}
	}
	return Registration{
		Registrar: c.Iss, ClientID: c.Sub, Name: c.Name, Purpose: c.Purpose, PrivacyPolicy: c.PrivacyPolicy,
		Claims: c.Claims, Credentials: c.Credentials, IssuedAt: issuedAt, Expires: expires, RegistrarCertificate: leaf,
	}, nil
}

func checkPolicyURL(raw string) error {
	if raw == "" {
		return nil
	}
	if u, err := url.Parse(raw); err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("registration: privacy_policy must be an https URL")
	}
	return nil
}

// Permits reports whether r registers path for any type of credential:
// a claims path equal to one of r.Claims, element by element. It
// doesn't look at Credentials, which are per type: see PermitsFor.
func (r Registration) Permits(path dcql.Path) bool {
	return slices.ContainsFunc(r.Claims, func(p dcql.Path) bool { return slices.Equal(p, path) })
}

// PermitsFor reports whether r registers path for cq's type of
// credential: in Claims, for any type, or in a Credentials entry for
// cq's.
func (r Registration) PermitsFor(cq dcql.CredentialQuery, path dcql.Path) bool {
	if r.Permits(path) {
		return true
	}
	return slices.ContainsFunc(r.Credentials, func(rc RegisteredCredential) bool {
		return rc.covers(cq) && slices.ContainsFunc(rc.Claims, func(p dcql.Path) bool { return slices.Equal(p, path) })
	})
}

// UnregisteredRevealed is what answering cq with a credential would
// reveal beyond r, of revealed — the claims a presentation for cq sends
// along with those it asks for, such as the plaintext members of a
// disclosed object or array element, or the other elements of an array
// disclosed as one (wallet.PreviewedCredential.DisclosedAlong): each
// that no path r registers for cq's type of credential covers
// (dcql.Path.Covers: the claim itself, or one it sits within), in
// revealed's order. Unregistered judges the request; this, what a
// presentation of a given credential actually discloses for it.
func (r Registration) UnregisteredRevealed(cq dcql.CredentialQuery, revealed []dcql.Path) []dcql.Path {
	registered := slices.Clone(r.Claims)
	for _, rc := range r.Credentials {
		if rc.covers(cq) {
			registered = append(registered, rc.Claims...)
		}
	}
	var out []dcql.Path
	for _, leaf := range revealed {
		if !slices.ContainsFunc(registered, func(p dcql.Path) bool { return p.Covers(leaf) }) {
			out = append(out, leaf)
		}
	}
	return out
}

// Unregistered is what q requests beyond r, by credential query ID: each
// claims path r doesn't register for that query's type of credential
// (PermitsFor), in query order.
//
// A credential query naming no claims is listed with a nil path, as
// unregistered in full. That is this function's convention, not the
// query's meaning: OpenID4VP 1.0 §6.4.1 reads a query without claims as
// asking for no selectively disclosable claims, so a Wallet answering it
// discloses only what the credential always shows. A holder shown the
// nil path is warned of more than the request asks for; what a
// presentation for the query actually reveals beyond r is
// UnregisteredRevealed's to judge.
func (r Registration) Unregistered(q dcql.Query) map[string][]dcql.Path {
	out := map[string][]dcql.Path{}
	for _, cq := range q.Credentials {
		if len(cq.Claims) == 0 {
			out[cq.ID] = []dcql.Path{nil}
			continue
		}
		for _, c := range cq.Claims {
			if !r.PermitsFor(cq, c.Path) {
				out[cq.ID] = append(out[cq.ID], c.Path)
			}
		}
	}
	return out
}
