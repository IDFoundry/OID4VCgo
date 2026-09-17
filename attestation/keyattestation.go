package attestation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// TypHeader is the required JOSE "typ" header of a Key Attestation JWT
// (OID4VCI 1.0 Appendix D.1).
const TypHeader = "key-attestation+jwt"

// AttackPotentialResistance is one of the case-sensitive strings
// key_storage/user_authentication may contain (Appendix D.2). Values
// beyond the four defined here are permitted — an ecosystem may define
// its own, ideally as a URL when it doesn't map to a well-known
// specification (Appendix D.2's own guidance) — so this is a set of
// named constants, not a closed enum.
type AttackPotentialResistance string

const (
	// ISO18045High: resistant to attack potential "High" (ISO/IEC 18045
	// VAN.5).
	ISO18045High AttackPotentialResistance = "iso_18045_high"

	// ISO18045Moderate: resistant to attack potential "Moderate"
	// (ISO/IEC 18045 VAN.4).
	ISO18045Moderate AttackPotentialResistance = "iso_18045_moderate"

	// ISO18045EnhancedBasic: resistant to attack potential
	// "Enhanced-Basic" (ISO/IEC 18045 VAN.3).
	ISO18045EnhancedBasic AttackPotentialResistance = "iso_18045_enhanced-basic"

	// ISO18045Basic: resistant to attack potential "Basic" (ISO/IEC
	// 18045 VAN.2).
	ISO18045Basic AttackPotentialResistance = "iso_18045_basic"
)

// Header carries the optional JOSE header parameters Appendix D.1
// permits for conveying the attestation signer's own public key and
// trust mechanism ("may use x5c, kid or trust_chain"). This package
// takes no position on which mechanism a deployment should use, or how
// to resolve a kid/trust_chain to an actual verification key — that's
// the caller's policy, the same division credential/sdjwtvc leaves to
// its own callers for Issuer Signature Mechanism resolution.
type Header struct {
	KeyID      string
	X5C        []string // base64-encoded DER certificates (RFC 7515 §4.1.6)
	TrustChain []string // OpenID Federation 1.0 trust chain (Appendix F.1)
}

// Claims is a Key Attestation JWT's claims set (Appendix D.1).
type Claims struct {
	// Issuer is the attestation issuer's identifier ("iss") — shown in
	// Appendix D.1's own worked example but not separately itemized as
	// required/optional in its prose; treated as optional here, the
	// generic RFC 7519 claim it is.
	Issuer string

	IssuedAt int64 // REQUIRED

	// ExpiresAt: OPTIONAL, but "MUST be present if the attestation is
	// used with the JWT proof type" (Appendix D.1) — a context this
	// package doesn't know about at Claims-construction time, so that
	// requirement is left to the caller (e.g. the future issuer
	// package, which does know which proof type it's validating
	// against).
	ExpiresAt *int64

	// AttestedKeys is a non-empty array of attested public keys, each a
	// JWK (RFC 7517). REQUIRED.
	AttestedKeys []json.RawMessage

	// KeyStorage/UserAuthentication assert the attack-potential
	// resistance of the key storage component and the user
	// authentication methods gating it, respectively. Both OPTIONAL;
	// non-empty if present.
	KeyStorage         []AttackPotentialResistance
	UserAuthentication []AttackPotentialResistance

	Certification string         // OPTIONAL: URL to the key storage component's certification
	Nonce         string         // OPTIONAL: issuer-provided freshness nonce
	Status        map[string]any // OPTIONAL: see statuslist.StatusListRef.Claim
}

// wireClaims is Claims' JSON wire shape.
type wireClaims struct {
	Issuer             string                      `json:"iss,omitempty"`
	IssuedAt           int64                       `json:"iat"`
	ExpiresAt          *int64                      `json:"exp,omitempty"`
	AttestedKeys       []json.RawMessage           `json:"attested_keys"`
	KeyStorage         []AttackPotentialResistance `json:"key_storage,omitempty"`
	UserAuthentication []AttackPotentialResistance `json:"user_authentication,omitempty"`
	Certification      string                      `json:"certification,omitempty"`
	Nonce              string                      `json:"nonce,omitempty"`
	Status             map[string]any              `json:"status,omitempty"`
}

// Issue builds and signs a Key Attestation JWT.
func Issue(signer crypto.Signer, alg jose.Alg, header Header, claims Claims) (string, error) {
	if claims.IssuedAt == 0 {
		return "", fmt.Errorf("attestation: Claims.IssuedAt is required")
	}
	if len(claims.AttestedKeys) == 0 {
		return "", fmt.Errorf("attestation: Claims.AttestedKeys must not be empty")
	}

	joseHeader := map[string]any{"typ": TypHeader}
	if header.KeyID != "" {
		joseHeader["kid"] = header.KeyID
	}
	if len(header.X5C) > 0 {
		joseHeader["x5c"] = header.X5C
	}
	if len(header.TrustChain) > 0 {
		joseHeader["trust_chain"] = header.TrustChain
	}

	payload, err := json.Marshal(wireClaims(claims))
	if err != nil {
		return "", fmt.Errorf("attestation: marshal claims: %w", err)
	}

	compact, err := jose.Sign(alg, signer, joseHeader, payload)
	if err != nil {
		return "", fmt.Errorf("attestation: sign: %w", err)
	}
	return compact, nil
}

// KeyAttestation is a parsed, but not yet signature-verified, Key
// Attestation JWT.
type KeyAttestation struct {
	header  map[string]any
	compact string
	claims  wireClaims
}

// Parse parses a Key Attestation JWT without verifying its signature.
func Parse(compact string) (KeyAttestation, error) {
	header, payload, err := jose.DecodeUnverified(compact)
	if err != nil {
		return KeyAttestation{}, fmt.Errorf("attestation: %w", err)
	}
	var wire wireClaims
	if err := json.Unmarshal(payload, &wire); err != nil {
		return KeyAttestation{}, fmt.Errorf("attestation: unmarshal claims: %w", err)
	}
	if wire.IssuedAt == 0 {
		return KeyAttestation{}, fmt.Errorf("attestation: claims are missing the required iat")
	}
	if len(wire.AttestedKeys) == 0 {
		return KeyAttestation{}, fmt.Errorf("attestation: claims are missing the required, non-empty attested_keys")
	}
	return KeyAttestation{header: header, compact: compact, claims: wire}, nil
}

// KeyID returns the header's "kid", or "" if absent. Untrusted until
// Verify succeeds; use only to select which key to verify against.
func (a KeyAttestation) KeyID() string {
	kid, _ := a.header["kid"].(string)
	return kid
}

// X5C returns the header's "x5c" certificate chain, or nil if absent.
// Untrusted until Verify succeeds.
func (a KeyAttestation) X5C() []string { return stringSlice(a.header["x5c"]) }

// TrustChain returns the header's "trust_chain", or nil if absent.
// Untrusted until Verify succeeds.
func (a KeyAttestation) TrustChain() []string { return stringSlice(a.header["trust_chain"]) }

func stringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// Now is used to check ExpiresAt, when present. Required only if
	// the parsed attestation actually carries an exp claim.
	Now time.Time

	// ExpectedNonce, if non-empty, must equal the attestation's nonce
	// claim.
	ExpectedNonce string

	// RequireExpiry, if true, rejects an attestation with no exp claim
	// — set this when using the attestation with the jwt proof type,
	// per Appendix D.1's "MUST be present if the attestation is used
	// with the JWT proof type."
	RequireExpiry bool
}

// VerifiedClaims is what remains once a Key Attestation has been
// verified.
type VerifiedClaims struct {
	Issuer             string
	IssuedAt           time.Time
	ExpiresAt          *time.Time
	AttestedKeys       []json.RawMessage
	KeyStorage         []AttackPotentialResistance
	UserAuthentication []AttackPotentialResistance
	Certification      string
	Nonce              string
	Status             map[string]any
}

// KeyAttested reports whether pub is one of v's AttestedKeys — Appendix
// D.1's own requirement: "If used with the jwt proof type, the
// Credential Issuer MUST validate that the JWT used as a proof is
// signed by a key contained in the attestation in the JOSE Header."
func (v VerifiedClaims) KeyAttested(pub crypto.PublicKey) (bool, error) {
	for _, k := range v.AttestedKeys {
		ok, err := matchesPublicKey(k, pub)
		if err != nil {
			continue // an attested key this package can't parse is simply not a match, not a hard error
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// Verify checks a's signature against pub and its claims against opts.
func (a KeyAttestation) Verify(pub crypto.PublicKey, alg jose.Alg, opts VerifyOptions) (VerifiedClaims, error) {
	if typ, _ := a.header["typ"].(string); typ != TypHeader {
		return VerifiedClaims{}, fmt.Errorf("attestation: typ is %q, want %q", typ, TypHeader)
	}
	if _, _, err := jose.Verify(alg, pub, a.compact); err != nil {
		return VerifiedClaims{}, fmt.Errorf("attestation: verify signature: %w", err)
	}
	c := a.claims

	var exp *time.Time
	if c.ExpiresAt != nil {
		t := time.Unix(*c.ExpiresAt, 0)
		exp = &t
		if opts.Now.IsZero() {
			return VerifiedClaims{}, fmt.Errorf("attestation: VerifyOptions.Now is required when the attestation has an exp claim")
		}
		if opts.Now.After(t) {
			return VerifiedClaims{}, fmt.Errorf("attestation: expired")
		}
	} else if opts.RequireExpiry {
		return VerifiedClaims{}, fmt.Errorf("attestation: exp is required but absent")
	}

	if opts.ExpectedNonce != "" && c.Nonce != opts.ExpectedNonce {
		return VerifiedClaims{}, fmt.Errorf("attestation: nonce does not match the expected value")
	}

	return VerifiedClaims{
		Issuer: c.Issuer, IssuedAt: time.Unix(c.IssuedAt, 0), ExpiresAt: exp,
		AttestedKeys: c.AttestedKeys, KeyStorage: c.KeyStorage, UserAuthentication: c.UserAuthentication,
		Certification: c.Certification, Nonce: c.Nonce, Status: c.Status,
	}, nil
}
