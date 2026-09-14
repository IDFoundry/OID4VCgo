package sdjwtvc

import (
	"fmt"
	"strings"
)

// Presentation is a parsed SD-JWT or SD-JWT+KB (RFC 9901 §4): the
// compact Issuer-signed JWT, the Disclosures presented alongside it,
// and the Key Binding JWT, if any.
//
// A Holder selecting which Disclosures to reveal (RFC 9901 §7.2)
// trims Disclosures down to the chosen subset before calling SDJWT,
// SDHash, or Compact — each derives its result from Presentation's
// current fields, not from whatever Parse originally saw, so a
// mutation here always produces a consistent result across all three.
type Presentation struct {
	IssuerJWT     string
	Disclosures   []Disclosure
	KeyBindingJWT string // "" for a bare SD-JWT
}

// HasKeyBinding reports whether the parsed presentation is an SD-JWT+KB.
func (p Presentation) HasKeyBinding() bool { return p.KeyBindingJWT != "" }

// Parse splits a compact SD-JWT or SD-JWT+KB into its parts (RFC 9901
// §4) without verifying anything — the issuer JWT's signature, the
// disclosure/digest matching, and any Key Binding JWT are all checked
// by Verify.
func Parse(s string) (Presentation, error) {
	parts := strings.Split(s, "~")
	if len(parts) < 2 {
		return Presentation{}, fmt.Errorf("sdjwtvc: not a valid SD-JWT (missing '~' separator)")
	}

	p := Presentation{IssuerJWT: parts[0]}
	disclosureParts := parts[1 : len(parts)-1]
	for i, dp := range disclosureParts {
		d, err := ParseDisclosure(dp)
		if err != nil {
			return Presentation{}, fmt.Errorf("sdjwtvc: disclosure %d: %w", i, err)
		}
		p.Disclosures = append(p.Disclosures, d)
	}

	if last := parts[len(parts)-1]; last != "" {
		p.KeyBindingJWT = last
	}
	return p, nil
}

// SDJWT returns the bare SD-JWT compact serialization for p's current
// IssuerJWT and Disclosures (RFC 9901 §4) — the exact bytes a Key
// Binding JWT's sd_hash is computed over (§4.3.1), regardless of
// whether p also carries a KeyBindingJWT.
func (p Presentation) SDJWT() (string, error) {
	s := p.IssuerJWT + "~"
	for _, d := range p.Disclosures {
		enc, err := d.Encode()
		if err != nil {
			return "", err
		}
		s += enc + "~"
	}
	return s, nil
}

// SDHash computes the base64url digest of p's current SD-JWT form
// (RFC 9901 §4.3.1) — the value a Key Binding JWT's sd_hash claim must
// match.
func (p Presentation) SDHash(alg HashAlg) (string, error) {
	sdjwt, err := p.SDJWT()
	if err != nil {
		return "", err
	}
	return hashString(alg, sdjwt)
}

// Compact reassembles p into its full compact serialization, appending
// KeyBindingJWT (if set) to SDJWT's result.
func (p Presentation) Compact() (string, error) {
	sdjwt, err := p.SDJWT()
	if err != nil {
		return "", err
	}
	return sdjwt + p.KeyBindingJWT, nil
}
