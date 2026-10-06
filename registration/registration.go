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
//	                claims paths (OpenID4VP 1.0 §7)
package registration

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
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
	// Claims are the claim paths it's registered to request.
	Claims []dcql.Path
	// IssuedAt and Expires bound when the registration holds.
	IssuedAt, Expires time.Time
	// RegistrarCertificate is the certificate that signed it, chained
	// to the Wallet's registrar roots (set by Verify).
	RegistrarCertificate *x509.Certificate
}

type wireClaims struct {
	Iss           string      `json:"iss"`
	Sub           string      `json:"sub"`
	Iat           int64       `json:"iat"`
	Exp           int64       `json:"exp"`
	Name          string      `json:"name"`
	Purpose       string      `json:"purpose,omitempty"`
	PrivacyPolicy string      `json:"privacy_policy,omitempty"`
	Claims        []dcql.Path `json:"claims"`
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
	if r.IssuedAt.IsZero() {
		r.IssuedAt = time.Now()
	}
	payload, err := json.Marshal(wireClaims{
		Iss: r.Registrar, Sub: r.ClientID, Iat: r.IssuedAt.Unix(), Exp: r.Expires.Unix(),
		Name: r.Name, Purpose: r.Purpose, PrivacyPolicy: r.PrivacyPolicy, Claims: r.Claims,
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

// Verify checks token, a registration JWT, and returns what it attests:
// its typ is Type, it's signed with ES256 by an end-entity certificate
// chaining to roots (not self-signed, not a CA, for digital
// signatures), its iss is one of that certificate's URI subject
// alternative names, it's for clientID (sub), and it holds at now.
//
// roots must anchor only registrars: any end-entity certificate under
// them can register any Verifier, so a root that also issues Verifiers'
// or Issuers' certificates would let them register themselves.
// VerifyWithPolicy narrows which certificates may sign.
func Verify(token string, roots *x509.CertPool, clientID string, now time.Time) (Registration, error) {
	return VerifyWithPolicy(token, roots, clientID, now, nil)
}

// VerifyWithPolicy is Verify, with policy (if non-nil) deciding whether
// the verified signing certificate may act as a registrar — an extended
// key usage or certificate policy the ecosystem defines, say.
func VerifyWithPolicy(token string, roots *x509.CertPool, clientID string, now time.Time, policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error) (Registration, error) {
	if roots == nil {
		return Registration{}, errors.New("registration: no registrar roots")
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
	leaf, err := certchain.VerifyLeafWithPolicy(ders, roots, policy)
	if err != nil {
		return Registration{}, fmt.Errorf("registration: registrar certificate: %w", err)
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Registration{}, errors.New("registration: the registrar certificate isn't for digital signatures")
	}
	_, payload, err := jose.Verify(jose.ES256, leaf.PublicKey, token)
	if err != nil {
		return Registration{}, fmt.Errorf("registration: signature: %w", err)
	}
	var c wireClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Registration{}, fmt.Errorf("registration: claims: %w", err)
	}
	switch {
	case c.Iss == "" || c.Name == "" || c.Exp == 0 || c.Iat == 0:
		return Registration{}, errors.New("registration: iss, name, iat and exp are required")
	case c.Sub != clientID:
		return Registration{}, errors.New("registration: it's for another relying party")
	case !slices.ContainsFunc(leaf.URIs, func(u *url.URL) bool { return u.String() == c.Iss }):
		return Registration{}, errors.New("registration: iss isn't the signing certificate's: it must be one of its URI subject alternative names")
	case !now.Before(time.Unix(c.Exp, 0)):
		return Registration{}, errors.New("registration: expired")
	case time.Unix(c.Iat, 0).After(now.Add(maxSkew)):
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
	return Registration{
		Registrar: c.Iss, ClientID: c.Sub, Name: c.Name, Purpose: c.Purpose, PrivacyPolicy: c.PrivacyPolicy,
		Claims: c.Claims, IssuedAt: time.Unix(c.Iat, 0), Expires: time.Unix(c.Exp, 0), RegistrarCertificate: leaf,
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

// Permits reports whether r registers path: a claims path equal to one
// of r.Claims, element by element.
func (r Registration) Permits(path dcql.Path) bool {
	return slices.ContainsFunc(r.Claims, func(p dcql.Path) bool { return slices.Equal(p, path) })
}

// Unregistered is what q requests beyond r, by credential query ID: each
// claims path r doesn't register, in query order. A credential query
// requesting no claims in particular asks for every claim (OpenID4VP 1.0
// §6.1), which no registration covers: it's listed with a nil path.
func (r Registration) Unregistered(q dcql.Query) map[string][]dcql.Path {
	out := map[string][]dcql.Path{}
	for _, cq := range q.Credentials {
		if len(cq.Claims) == 0 {
			out[cq.ID] = []dcql.Path{nil}
			continue
		}
		for _, c := range cq.Claims {
			if !r.Permits(c.Path) {
				out[cq.ID] = append(out[cq.ID], c.Path)
			}
		}
	}
	return out
}
