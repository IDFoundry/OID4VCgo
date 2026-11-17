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

// MaxBytes bounds a whole compact SD-JWT or SD-JWT+KB — issuer JWT,
// every Disclosure and any Key Binding JWT together — in Parse. It
// deliberately matches credential/mdoc.MaxBytes and oid4vpmdoc.MaxBytes
// rather than the 64 KiB jose.MaxCompactBytes: a Disclosure can
// legitimately carry a sizeable value (a portrait, or raw eMRTD data
// groups), and one over 64 KiB is the SD-JWT counterpart of an mdoc
// data element over it. The two JWTs inside stay bounded at
// jose.MaxCompactBytes on their own — Verify and VerifyKeyBindingJWT
// check them through jose.Verify — since they only ever hold digests
// and claims. Use ParseMax for a caller that needs a different ceiling.
const MaxBytes = 1 << 20 // 1 MiB

// Parse splits a compact SD-JWT or SD-JWT+KB into its parts (RFC 9901
// §4) without verifying anything — the issuer JWT's signature, the
// disclosure/digest matching, and any Key Binding JWT are all checked
// by Verify. It rejects a presentation larger than MaxBytes, but
// decodes every Disclosure of one within it, whether or not a digest
// references it: about half a second of CPU for a mebibyte of minimal
// Disclosures. So don't Parse a presentation or credential someone
// else sent before it's verified: VerifyPresentation verifies the
// Issuer-signed JWT first, then decodes only the Disclosures its
// digests reference, and returns the parsed Presentation too. Parse is
// for what the caller already trusts, such as a credential it holds
// (see wallet.HeldCredential). Use ParseMax for a caller that needs a
// different ceiling.
func Parse(s string) (Presentation, error) {
	return ParseMax(s, MaxBytes)
}

// ParseMax is Parse with an explicit size ceiling, in bytes, instead
// of MaxBytes.
func ParseMax(s string, maxBytes int) (Presentation, error) {
	if len(s) > maxBytes {
		return Presentation{}, fmt.Errorf("sdjwtvc: presentation is %d bytes, exceeds the %d byte limit", len(s), maxBytes)
	}
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
	var b strings.Builder
	b.WriteString(p.IssuerJWT)
	b.WriteByte('~')
	for _, d := range p.Disclosures {
		enc, err := d.Encode()
		if err != nil {
			return "", err
		}
		b.WriteString(enc)
		b.WriteByte('~')
	}
	return b.String(), nil
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
