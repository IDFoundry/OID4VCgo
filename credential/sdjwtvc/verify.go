package sdjwtvc

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// KeyBindingRequirement decides whether Verify requires a Key Binding
// JWT to be present and valid — per RFC 9901 §7.3 step 1, this MUST be
// an explicit Verifier policy decision, never inferred from whether
// the Holder happened to send one. A bare bool let that decision be
// made by omission (its Go zero value silently meant "not required");
// this type has no valid zero value instead, so Verify rejects a
// VerifyOptions that never set it — found comparing this package's own
// trust-boundary DX against FAPIgo's.
type KeyBindingRequirement uint8

const (
	_ KeyBindingRequirement = iota

	// KeyBindingRequired rejects a presentation with no Key Binding
	// JWT, or with one that fails verification.
	KeyBindingRequired

	// KeyBindingNotRequired accepts a presentation with no Key Binding
	// JWT. It does not verify one even if the Holder sent one anyway —
	// a caller that cares about an opportunistically-presented Key
	// Binding JWT should require it instead.
	KeyBindingNotRequired
)

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// HashAlg is used only if the payload omits _sd_alg; the payload's
	// own _sd_alg, when present, always takes precedence (RFC 9901
	// §4.1.1). Defaults to DefaultHashAlg.
	HashAlg HashAlg

	// RequireKeyBinding is REQUIRED — see KeyBindingRequirement's own
	// doc comment for why Verify rejects the Go zero value rather than
	// defaulting to KeyBindingNotRequired.
	RequireKeyBinding KeyBindingRequirement
	HolderPublicKey   crypto.PublicKey // required if RequireKeyBinding is KeyBindingRequired
	KeyBindingAlg     oid4vci.JOSEAlg
	ExpectedAudience  string
	ExpectedNonce     string

	// MaxKeyBindingAge becomes KeyBindingCheck.MaxAge. REQUIRED (must
	// be positive) when RequireKeyBinding is KeyBindingRequired — see
	// that field's own doc comment for why its zero value is rejected
	// rather than silently meaning "no freshness check at all."
	MaxKeyBindingAge time.Duration

	// Now is compared against the Issuer JWT's own exp/nbf claims
	// (when present) and, if RequireKeyBinding is KeyBindingRequired,
	// the Key Binding JWT's own iat via MaxKeyBindingAge. Defaults to
	// time.Now.
	Now func() time.Time

	// MaxClockSkew is how far Now may be from the issuer's clock: the
	// Issuer JWT is accepted up to MaxClockSkew before its nbf and after
	// its exp. Zero applies them exactly.
	MaxClockSkew time.Duration
}

// Verify checks a presented SD-JWT or SD-JWT+KB against the Issuer's
// already-resolved public key — the Issuer-signed JWT's signature,
// typ, vct and validity, each Disclosure's digest, and, when
// RequireKeyBinding is KeyBindingRequired, the Key Binding JWT against
// HolderPublicKey — and returns the Processed SD-JWT Payload (RFC 9901
// §7.1's term) plus the Issuer-signed JWT's raw JOSE header.
//
// It is one step of verifying a presentation, not all of it. The caller
// still:
//   - resolves which key issuerPub is and whether to trust it —
//     draft-13 §3.5's JWT VC Issuer Metadata or X.509 Issuer Signature
//     Mechanisms (see the package doc comment), with revocation of its
//     certificate;
//   - passes as HolderPublicKey the key the credential's own cnf claim
//     names (RFC 7800, RFC 9901 §7.3): Verify checks the Key Binding
//     JWT against the key it's given, not against cnf;
//   - checks the credential's status.
//
// verifier.Verifier.VerifyResponse does all of these, status through
// its Status policy.
func Verify(s string, issuerPub crypto.PublicKey, issuerAlg oid4vci.JOSEAlg, opts VerifyOptions) (payload map[string]any, header map[string]any, err error) {
	if opts.RequireKeyBinding != KeyBindingRequired && opts.RequireKeyBinding != KeyBindingNotRequired {
		return nil, nil, fmt.Errorf("sdjwtvc: VerifyOptions.RequireKeyBinding is required")
	}
	pres, err := Parse(s)
	if err != nil {
		return nil, nil, err
	}
	if opts.RequireKeyBinding == KeyBindingRequired && !pres.HasKeyBinding() {
		return nil, nil, fmt.Errorf("sdjwtvc: key binding is required but no Key Binding JWT was presented")
	}

	header, rawPayload, err := jose.Verify(issuerAlg, issuerPub, pres.IssuerJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("sdjwtvc: verify issuer JWT: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != TypHeader {
		return nil, nil, fmt.Errorf("sdjwtvc: issuer JWT typ is %q, want %q", typ, TypHeader)
	}

	var decoded map[string]any
	if err := strictjson.Unmarshal(rawPayload, &decoded); err != nil {
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
	if opts.MaxClockSkew < 0 {
		return nil, nil, fmt.Errorf("sdjwtvc: MaxClockSkew must not be negative")
	}
	if err := checkIssuerJWTValidityWindow(decoded, now, opts.MaxClockSkew); err != nil {
		return nil, nil, err
	}

	fallback := opts.HashAlg
	if fallback == "" {
		fallback = DefaultHashAlg
	}
	hashAlg, err := PayloadHashAlg(decoded, fallback)
	if err != nil {
		return nil, nil, err
	}

	if raw, present := decoded["aka_vcts"]; present {
		if err := checkAkaVCTsClaim(decoded["vct"], raw); err != nil {
			return nil, nil, err
		}
	}
	if err := checkNoRegisteredClaimDisclosed(decoded, hashAlg, pres.Disclosures); err != nil {
		return nil, nil, err
	}
	if err := checkNoRegisteredSubClaimDisclosable(decoded); err != nil {
		return nil, nil, err
	}
	resolved, err := ResolveDisclosures(decoded, hashAlg, pres.Disclosures)
	if err != nil {
		return nil, nil, err
	}

	if err := verifyKeyBindingIfRequired(pres, opts, hashAlg); err != nil {
		return nil, nil, err
	}

	return resolved, header, nil
}

// checkIssuerJWTValidityWindow checks decoded's own optional exp/nbf
// claims (RFC 7519 §4.1.4/§4.1.5) against now — split out of Verify
// purely to keep it under the linter's own cognitive complexity
// ceiling.
// nonDisclosableClaims are the registered claims an SD-JWT VC's Issuer
// MUST NOT make selectively disclosable (SD-JWT VC draft-13 §3.2.2,
// unchanged in draft-13): each must be in the Issuer-signed JWT itself.
var nonDisclosableClaims = map[string]bool{
	"iss": true, "nbf": true, "exp": true, "cnf": true, "vct": true, "vct#integrity": true, "status": true,
	"aka_vcts": true, // draft-19 §2.2.2.3
}

// checkNoRegisteredClaimDisclosed refuses an SD-JWT VC whose top-level
// _sd references a disclosure of one of nonDisclosableClaims. Were exp or
// status selectively disclosable, the Holder could withhold them and have
// an expired or revoked credential accepted — Verify checks validity only
// from the Issuer-signed JWT's own claims.
func checkNoRegisteredClaimDisclosed(decoded map[string]any, alg HashAlg, disclosures []Disclosure) error {
	topLevel, _ := decoded["_sd"].([]any)
	if len(topLevel) == 0 {
		return nil
	}
	digests := make(map[string]bool, len(topLevel))
	for _, d := range topLevel {
		if s, ok := d.(string); ok {
			digests[s] = true
		}
	}
	for _, d := range disclosures {
		if d.IsArrayElement() || !nonDisclosableClaims[d.Name] {
			continue
		}
		digest, err := d.Digest(alg)
		if err != nil {
			return err
		}
		if digests[digest] {
			return fmt.Errorf("sdjwtvc: registered claim %q must not be selectively disclosable", d.Name)
		}
	}
	return nil
}

func checkIssuerJWTValidityWindow(decoded map[string]any, now func() time.Time, skew time.Duration) error {
	return checkValidityWindow(decoded, now, skew, "", "credential")
}

// checkValidityWindow checks claims' optional exp and nbf: each, if
// present, a NumericDate (RFC 7519 §2, §4.1.4, §4.1.5), and now within
// them, give or take skew. prefix names the JWT in a claim error ("" or
// "key binding JWT "); subject names it in a validity error.
func checkValidityWindow(claims map[string]any, now func() time.Time, skew time.Duration, prefix, subject string) error {
	if expRaw, ok := claims["exp"]; ok {
		exp, ok := expRaw.(float64)
		if !ok {
			return fmt.Errorf("sdjwtvc: %sexp claim is not a number", prefix)
		}
		expires, err := jwtdate.FromFloat(exp)
		if err != nil {
			return fmt.Errorf("sdjwtvc: %sexp claim: %w", prefix, err)
		}
		if !now().Add(-skew).Before(expires) {
			return fmt.Errorf("sdjwtvc: %s has expired", subject)
		}
	}
	if nbfRaw, ok := claims["nbf"]; ok {
		nbf, ok := nbfRaw.(float64)
		if !ok {
			return fmt.Errorf("sdjwtvc: %snbf claim is not a number", prefix)
		}
		notBefore, err := jwtdate.FromFloat(nbf)
		if err != nil {
			return fmt.Errorf("sdjwtvc: %snbf claim: %w", prefix, err)
		}
		if now().Add(skew).Before(notBefore) {
			return fmt.Errorf("sdjwtvc: %s is not yet valid", subject)
		}
	}
	return nil
}

// verifyKeyBindingIfRequired is Verify's own final RFC 9901 §7.3 step
// — a no-op unless opts.RequireKeyBinding is KeyBindingRequired — split
// out purely to keep Verify under the linter's own cognitive
// complexity ceiling.
func verifyKeyBindingIfRequired(pres Presentation, opts VerifyOptions, hashAlg HashAlg) error {
	if opts.RequireKeyBinding != KeyBindingRequired {
		return nil
	}
	if opts.HolderPublicKey == nil {
		return fmt.Errorf("sdjwtvc: VerifyOptions.RequireKeyBinding is KeyBindingRequired but HolderPublicKey is nil")
	}
	sdHash, err := pres.SDHash(hashAlg)
	if err != nil {
		return err
	}
	if _, err := VerifyKeyBindingJWT(pres.KeyBindingJWT, opts.HolderPublicKey, opts.KeyBindingAlg, KeyBindingCheck{
		ExpectedAudience: opts.ExpectedAudience,
		ExpectedNonce:    opts.ExpectedNonce,
		ExpectedSDHash:   sdHash,
		MaxAge:           opts.MaxKeyBindingAge,
		MaxClockSkew:     opts.MaxClockSkew,
		Now:              opts.Now,
	}); err != nil {
		return fmt.Errorf("sdjwtvc: %w: %w", ErrKeyBinding, err)
	}
	return nil
}

// ErrKeyBinding is wrapped by Verify when the Key Binding JWT fails its
// checks (RFC 9901 §7.3): the presentation's holder binding, not the
// credential itself.
var ErrKeyBinding = errors.New("key binding JWT")

// checkNoRegisteredSubClaimDisclosable refuses an SD-JWT VC that makes
// a sub-claim of one of nonDisclosableClaims selectively disclosable:
// draft-19 §2.2.2.3 forbids them "including any of their sub-claims".
// It looks at the Issuer-signed structure, so a sub-claim the Holder
// withheld is refused too, not just one it disclosed: a status whose
// status_list could be withheld, or a cnf whose key could, isn't the
// claim the Issuer is required to sign.
func checkNoRegisteredSubClaimDisclosable(decoded map[string]any) error {
	for name := range nonDisclosableClaims {
		if v, ok := decoded[name]; ok && hasDisclosureDigest(v) {
			return fmt.Errorf("sdjwtvc: registered claim %q must not have selectively disclosable sub-claims", name)
		}
	}
	return nil
}

// hasDisclosureDigest reports whether v holds an _sd array or an array
// element digest ({"...": digest}) at any depth.
func hasDisclosureDigest(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		if _, ok := v["_sd"]; ok {
			return true
		}
		if _, ok := v["..."]; ok && len(v) == 1 {
			return true
		}
		for _, child := range v {
			if hasDisclosureDigest(child) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, hasDisclosureDigest)
	}
	return false
}
