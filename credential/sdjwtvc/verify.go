package sdjwtvc

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// HashAlg is used only if the payload omits _sd_alg; the payload's
	// own _sd_alg, when present, always takes precedence (RFC 9901
	// §4.1.1). Defaults to DefaultHashAlg.
	HashAlg HashAlg

	// RequireKeyBinding decides whether a Key Binding JWT must be
	// present and valid — per RFC 9901 §7.3 step 1, this MUST be a
	// Verifier policy decision, never inferred from whether the Holder
	// happened to send one.
	RequireKeyBinding bool
	HolderPublicKey   crypto.PublicKey // required if RequireKeyBinding
	KeyBindingAlg     jose.Alg
	ExpectedAudience  string
	ExpectedNonce     string

	// MaxKeyBindingAge becomes KeyBindingCheck.MaxAge. REQUIRED (must
	// be positive) when RequireKeyBinding is true — see that field's
	// own doc comment for why its zero value is rejected rather than
	// silently meaning "no freshness check at all."
	MaxKeyBindingAge time.Duration

	// Now is compared against the Issuer JWT's own exp/nbf claims
	// (when present) and, if RequireKeyBinding, the Key Binding JWT's
	// own iat via MaxKeyBindingAge. Defaults to time.Now.
	Now func() time.Time
}

// Verify fully validates a presented SD-JWT or SD-JWT+KB against the
// Issuer's already-resolved public key and returns the Processed SD-JWT
// Payload (RFC 9901 §7.1's term) plus the Issuer-signed JWT's raw JOSE
// header. Resolving *which* key issuerPub is — draft-11 §3.5's JWT VC
// Issuer Metadata or X.509 Issuer Signature Mechanisms — is the
// caller's job; see the package doc comment.
func Verify(s string, issuerPub crypto.PublicKey, issuerAlg jose.Alg, opts VerifyOptions) (payload map[string]any, header map[string]any, err error) {
	pres, err := Parse(s)
	if err != nil {
		return nil, nil, err
	}
	if opts.RequireKeyBinding && !pres.HasKeyBinding() {
		return nil, nil, fmt.Errorf("sdjwtvc: key binding is required but no Key Binding JWT was presented")
	}

	header, rawPayload, err := jose.Verify(issuerAlg, issuerPub, pres.IssuerJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("sdjwtvc: verify issuer JWT: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != TypHeader && typ != LegacyTypHeader {
		return nil, nil, fmt.Errorf("sdjwtvc: issuer JWT typ is %q, want %q", typ, TypHeader)
	}

	var decoded map[string]any
	if err := json.Unmarshal(rawPayload, &decoded); err != nil {
		return nil, nil, fmt.Errorf("sdjwtvc: unmarshal issuer JWT payload: %w", err)
	}
	if _, ok := decoded["vct"].(string); !ok {
		return nil, nil, fmt.Errorf("sdjwtvc: issuer JWT payload is missing the required vct claim")
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	// exp/nbf (RFC 7519 §4.1.4/§4.1.5, both OPTIONAL) — checked here,
	// not left to the caller: Verify's own name and signature (return
	// a plain payload, no separate "is it still valid" step) make it
	// look like a complete verification, and treating an expired or
	// not-yet-valid credential as fully verified is exactly the kind
	// of silent gap a caller could easily miss (found in a repo-wide
	// security review — credential/mdoc.Verify and
	// statuslist.VerifyToken/VerifyTokenCWT, this repo's own sibling
	// Verify functions, already check their own equivalent validity
	// window unconditionally; this one didn't).
	if expRaw, ok := decoded["exp"]; ok {
		exp, ok := expRaw.(float64)
		if !ok {
			return nil, nil, fmt.Errorf("sdjwtvc: exp claim is not a number")
		}
		if !now().Before(time.Unix(int64(exp), 0)) {
			return nil, nil, fmt.Errorf("sdjwtvc: credential has expired")
		}
	}
	if nbfRaw, ok := decoded["nbf"]; ok {
		nbf, ok := nbfRaw.(float64)
		if !ok {
			return nil, nil, fmt.Errorf("sdjwtvc: nbf claim is not a number")
		}
		if now().Before(time.Unix(int64(nbf), 0)) {
			return nil, nil, fmt.Errorf("sdjwtvc: credential is not yet valid")
		}
	}

	hashAlg := opts.HashAlg
	if hashAlg == "" {
		hashAlg = DefaultHashAlg
	}
	if declared, ok := decoded["_sd_alg"].(string); ok {
		hashAlg = HashAlg(declared)
	}

	resolved, err := ResolveDisclosures(decoded, hashAlg, pres.Disclosures)
	if err != nil {
		return nil, nil, err
	}

	if opts.RequireKeyBinding {
		if opts.HolderPublicKey == nil {
			return nil, nil, fmt.Errorf("sdjwtvc: VerifyOptions.RequireKeyBinding is set but HolderPublicKey is nil")
		}
		sdHash, err := pres.SDHash(hashAlg)
		if err != nil {
			return nil, nil, err
		}
		if _, err := VerifyKeyBindingJWT(pres.KeyBindingJWT, opts.HolderPublicKey, opts.KeyBindingAlg, KeyBindingCheck{
			ExpectedAudience: opts.ExpectedAudience,
			ExpectedNonce:    opts.ExpectedNonce,
			ExpectedSDHash:   sdHash,
			MaxAge:           opts.MaxKeyBindingAge,
			Now:              opts.Now,
		}); err != nil {
			return nil, nil, fmt.Errorf("sdjwtvc: %w", err)
		}
	}

	return resolved, header, nil
}
