package sdjwtvc

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// TypHeader is the JOSE "typ" header value for the Issuer-signed JWT
// component of an SD-JWT VC: the one Issue sets, and by default the only
// one Verify accepts. Draft-19 §2.2.1 says "The typ value MUST use
// dc+sd-jwt".
const TypHeader = "dc+sd-jwt"

// LegacyTypHeader is the typ SD-JWT VCs carried before dc+sd-jwt.
// Draft-13 §3.2.1, the version HAIP 1.0 names, recommended that Holders
// and Verifiers accept it too for a transition period; draft-19 dropped
// that. Verify accepts it only when VerifyOptions.AcceptLegacyTyp is
// set.
const LegacyTypHeader = "vc+sd-jwt"

// MediaType is the SD-JWT VC media type (draft-13 §3.1).
const MediaType = "application/dc+sd-jwt"

// CredentialFormat is the OID4VCI 1.0 Credential Format Identifier for
// this format (Appendix A.3.1) — the value a Credential Issuer's
// credential_configurations_supported metadata (§12.2.4) uses in its
// "format" member, and a Wallet's authorization_details/Credential
// Request use to select it.
const CredentialFormat = "dc+sd-jwt" //nolint:gosec // an OID4VCI format identifier, not a credential

// KeyBindingTyp is the required "typ" header of a Key Binding JWT
// (RFC 9901 §4.3).
const KeyBindingTyp = "kb+jwt"

// Claims is the input to Issue. VCT is the only required field
// (draft-13 §3.2.2.1). Iss, Nbf, Exp, VCTIntegrity, Status and CNF are
// the registered claims draft-13 §3.2.2.2 forbids from ever being
// selectively disclosed, so they're always plaintext — putting one of
// their claim names in Additional is rejected. Nbf/Exp/Iat use a Unix
// timestamp (int64), matching JWT's NumericDate (RFC 7519 §2), not
// time.Time — this package does no implicit time-type conversion for
// values inside Additional either, so any caller-supplied claim that
// needs to be a NumericDate must already be an int64 when passed in.
type Claims struct {
	VCT string // REQUIRED
	// AkaVCTs are additional types the credential is also of (SD-JWT VC
	// draft-19 §2.2.2.2): typically the general type VCT is derived
	// from, so a request for that type matches it. Each must be a
	// collision-resistant name, none VCT itself. Always plaintext.
	AkaVCTs []string
	Iss     string
	Nbf     *int64

	// Exp is RFC 9901 §11.2.3's own RECOMMENDED (not required)
	// validity bound. If set, use RoundedExp rather than a raw
	// issuance-instant-plus-lifetime computation — §10.1 separately
	// requires ("MUST") that "iat/exp/nbf... [be] randomized or
	// rounded to prevent linkability": issuing many credentials close
	// together (e.g. one per client in a multi-client flow) with
	// exp/nbf/iat values differing by the real, precise
	// inter-issuance gap lets a party holding more than one correlate
	// them by that gap — confirmed live against the OIDF conformance
	// suite's own oid4vci-1_0-issuer-happy-flow-multiple-clients
	// module, which flags exactly this. RoundedExp closes that
	// channel for Exp; the same rounding-to-a-coarser-granularity
	// technique applies equally to Nbf/Iat if a caller sets either.
	Exp          *int64
	VCTIntegrity string
	Status       map[string]any // see draft-ietf-oauth-status-list
	CNF          map[string]any // REQUIRED if Key Binding is to be supported

	// Additional holds any further public/private claims (draft-13
	// §3.2.2.3), including the registered "sub" and "iat" claims that
	// draft-13 §3.2.2.2 permits (but does not require) to be
	// selectively disclosed. Wrap a value with SD to make its property
	// selectively disclosable, or SDElement for an array element.
	Additional map[string]any
}

// RoundedExp computes an "exp" value for a credential issued at now,
// rounded down to the start of now's own UTC day before adding
// lifetime — see Claims.Exp's own doc comment for why a raw
// issuance-instant-plus-lifetime computation fails RFC 9901 §10.1's
// own anti-linkability MUST. Day-granularity rounding means every
// credential issued on the same calendar day carries an identical
// exp, closing that channel while still bounding validity to
// approximately lifetime.
//
// A credential is valid for lifetime less however much of its UTC day
// had passed when it was issued: one issued just before midnight with
// a lifetime of 24 hours expires minutes later. Pass a day more than
// the shortest validity a credential needs.
func RoundedExp(now time.Time, lifetime time.Duration) int64 {
	dayStart := now.UTC().Truncate(24 * time.Hour)
	return dayStart.Add(lifetime).Unix()
}

// MaxDecoys bounds IssueOptions.Decoys. RFC 9901 §4.2.5 sets no limit,
// but decoys only need to obscure how many claims are really
// selectively disclosable — a handful per credential does that — and
// an unbounded value turns a misconfiguration into a panic or memory
// exhaustion instead of an error.
const MaxDecoys = 1000

// IssueOptions configures Issue.
type IssueOptions struct {
	// HashAlg selects the digest algorithm (RFC 9901 §4.1.1). Defaults
	// to DefaultHashAlg (sha-256) — every implementation MUST support
	// it, so it is always safe as a default.
	HashAlg HashAlg

	// Decoys adds this many decoy digests to the top-level _sd array
	// (RFC 9901 §4.2.5) when the credential has a selectively
	// disclosable claim; one without has no _sd at all (SD-JWT VC
	// draft-13 §3.2.2.4). 0 by default; Issue rejects a negative value
	// or one above MaxDecoys. Nested objects' _sd arrays get theirs
	// from NestedDecoys and WithDecoys.
	Decoys int

	// NestedDecoys, if set, is called once for each _sd array below the
	// top level that Issue produces — in an object of the claims, or of
	// a disclosed value — for how many decoy digests (RFC 9901 §4.2.5)
	// to add to it: 0 to MaxDecoys, or Issue fails. Draw the count
	// afresh each call, from a range, so a Verifier can't subtract a
	// fixed one and learn how many of an object's claims are really
	// selectively disclosable. An object without selectively disclosable
	// claims has no _sd array and gets none, unless WithDecoys gave it
	// one. Nil adds none.
	NestedDecoys func() (int, error)

	// KeyID sets the JOSE "kid" header on the Issuer-signed JWT, if
	// non-empty.
	KeyID string

	// IssuerCertificate, if set, becomes the Issuer-signed JWT's own
	// "x5c" header entry (RFC 7515 §4.1.6, a single-entry chain: just
	// the leaf) — the trust mechanism HAIP's own SD-JWT VC profile
	// expects (confirmed live against the OpenID Foundation
	// conformance suite's own "Credential MUST contain an x5c in the
	// header" check), letting a Verifier chain the credential to a
	// configured trust anchor without a separate out-of-band issuer-key
	// resolution step. Its public key must match signer's own public
	// key: Issue rejects a mismatch, the same check
	// verifier.New(Config.ClientCertificate) already makes.
	IssuerCertificate *x509.Certificate

	// IssuerIntermediates are the CA certificates between
	// IssuerCertificate and the trust anchor, in order, the anchor
	// itself left out: they follow IssuerCertificate in x5c, so a
	// Verifier holding only the anchor can build the path (HAIP 1.0
	// §6.1.1: "the credential issuer's signing certificate along with a
	// trust chain ... The X.509 certificate of the trust anchor MUST NOT
	// be included"). Each must sign the certificate before it. Requires
	// IssuerCertificate.
	IssuerIntermediates []*x509.Certificate

	// TypeMetadata, if set, is the Type Metadata the Issuer publishes
	// for this credential's vct: Issue refuses claims that break its
	// claim metadata (CheckTypeMetadata), so the credential is one a
	// consumer processing that metadata accepts.
	TypeMetadata *TypeMetadata
}

var reservedTopLevelClaims = map[string]bool{
	"vct": true, "aka_vcts": true, "iss": true, "nbf": true, "exp": true,
	"vct#integrity": true, "status": true, "cnf": true,
	"_sd": true, "_sd_alg": true, "...": true,
}

// applyPlaintextClaims sets sealed's own always-plaintext registered
// claims (draft-13 §3.2.2.2's own never-selectively-disclosed set)
// from claims — split out of Issue purely to keep it under the
// linter's own cognitive complexity ceiling.
func applyPlaintextClaims(sealed map[string]any, claims Claims) {
	sealed["vct"] = claims.VCT
	if len(claims.AkaVCTs) > 0 {
		sealed["aka_vcts"] = append([]string(nil), claims.AkaVCTs...)
	}
	if claims.Iss != "" {
		sealed["iss"] = claims.Iss
	}
	if claims.Nbf != nil {
		sealed["nbf"] = *claims.Nbf
	}
	if claims.Exp != nil {
		sealed["exp"] = *claims.Exp
	}
	if claims.VCTIntegrity != "" {
		sealed["vct#integrity"] = claims.VCTIntegrity
	}
	if claims.Status != nil {
		sealed["status"] = claims.Status
	}
	if claims.CNF != nil {
		sealed["cnf"] = claims.CNF
	}
}

// issuerJWTHeader builds Issue's own Issuer-signed JWT header — split
// out purely to keep it under the linter's own cognitive complexity
// ceiling.
func issuerJWTHeader(opts IssueOptions) map[string]any {
	header := map[string]any{"typ": TypHeader}
	if opts.KeyID != "" {
		header["kid"] = opts.KeyID
	}
	if opts.IssuerCertificate != nil {
		x5c := []string{base64.StdEncoding.EncodeToString(opts.IssuerCertificate.Raw)}
		for _, c := range opts.IssuerIntermediates {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
		}
		header["x5c"] = x5c
	}
	return header
}

// Issue builds and signs an SD-JWT VC. An Issuer never produces an
// SD-JWT+KB (only a Holder presents one — RFC 9901 §7.2), so the result
// is always a bare SD-JWT — its compact form ends in "~" per RFC 9901
// §4. The returned Disclosures are every one Issue generated; the
// Holder needs all of them to later choose a subset to present (via
// Presentation/ResolveDisclosures).
func Issue(signer crypto.Signer, alg oid4vci.JOSEAlg, claims Claims, opts IssueOptions) (sdjwt string, disclosures []Disclosure, err error) {
	if err := checkIssueInputs(signer, claims, opts); err != nil {
		return "", nil, err
	}
	if opts.TypeMetadata != nil {
		if err := CheckTypeMetadata(claims, *opts.TypeMetadata); err != nil {
			return "", nil, err
		}
	}
	hashAlg := opts.HashAlg
	if hashAlg == "" {
		hashAlg = DefaultHashAlg
	}

	tree := make(map[string]any, len(claims.Additional))
	for k, v := range claims.Additional {
		if reservedTopLevelClaims[k] {
			return "", nil, fmt.Errorf("sdjwtvc: %q must be set via Claims, not Additional", k)
		}
		tree[k] = v
	}

	sealed, disclosures, err := sealer{alg: hashAlg, nestedDecoys: opts.NestedDecoys}.sealObject(tree, 0, false)
	if err != nil {
		return "", nil, fmt.Errorf("sdjwtvc: seal claims: %w", err)
	}

	applyPlaintextClaims(sealed, claims)

	// Decoys only beside a real disclosure: an SD-JWT VC with no
	// selectively disclosable claims "MUST NOT contain the _sd claim"
	// (draft-13 §3.2.2.4), nor then _sd_alg — unless a WithDecoys
	// object carries digests of its own, which _sd_alg then names the
	// algorithm of.
	if len(disclosures) > 0 && opts.Decoys > 0 {
		if err := addDecoys(sealed, hashAlg, opts.Decoys); err != nil {
			return "", nil, err
		}
	}
	if len(disclosures) > 0 || hasDisclosureDigest(sealed) {
		sealed["_sd_alg"] = string(hashAlg)
	}

	payload, err := json.Marshal(sealed)
	if err != nil {
		return "", nil, fmt.Errorf("sdjwtvc: marshal payload: %w", err)
	}

	header := issuerJWTHeader(opts)

	issuerJWT, err := jose.Sign(alg, signer, header, payload)
	if err != nil {
		return "", nil, fmt.Errorf("sdjwtvc: sign issuer JWT: %w", err)
	}
	// Verify bounds the issuer JWT at jose.MaxCompactBytes, and Parse
	// the whole SD-JWT at MaxBytes: issuing past either would sign a
	// credential no holder or Verifier of this package accepts.
	if len(issuerJWT) > jose.MaxCompactBytes {
		return "", nil, fmt.Errorf("sdjwtvc: the issuer JWT is %d bytes, over the %d Verify accepts: fewer claims or decoys", len(issuerJWT), jose.MaxCompactBytes)
	}

	out := issuerJWT + "~"
	for _, d := range disclosures {
		enc, err := d.Encode()
		if err != nil {
			return "", nil, err
		}
		out += enc + "~"
	}
	if len(out) > MaxBytes {
		return "", nil, fmt.Errorf("sdjwtvc: the SD-JWT is %d bytes, over the %d Parse accepts", len(out), MaxBytes)
	}
	return out, disclosures, nil
}

// checkNoReservedNames refuses a reserved name (isReservedName)
// anywhere in v, the always-plaintext Claims field named field: Issue
// signs it as given, so one there would be an _sd array or digest no
// Verifier accepts (draft-19 §2.2.2.3), or one the Holder could later
// disclose a claim of its own choosing for.
func checkNoReservedNames(field string, v map[string]any) error {
	if v == nil {
		return nil
	}
	generic, err := toGenericJSON(v)
	if err != nil {
		return err
	}
	if name, ok := reservedNameIn(generic); ok {
		return fmt.Errorf("sdjwtvc: claim name %q in Claims.%s is reserved", name, field)
	}
	return nil
}

// checkIssueInputs checks Issue's claims and options: a vct, a decoy
// count in range, and an IssuerCertificate, if given, for signer's key.
func checkIssueInputs(signer crypto.Signer, claims Claims, opts IssueOptions) error {
	if claims.AkaVCTs != nil {
		if err := checkAkaVCTs(claims.VCT, claims.AkaVCTs); err != nil {
			return err
		}
	}
	if hasSDMarker(claims.Status) || hasSDMarker(claims.CNF) {
		return fmt.Errorf("sdjwtvc: Claims.Status and Claims.CNF can't have selectively disclosable sub-claims (SD-JWT VC draft-19 §2.2.2.3)")
	}
	for field, v := range map[string]map[string]any{"Status": claims.Status, "CNF": claims.CNF} {
		if err := checkNoReservedNames(field, v); err != nil {
			return err
		}
	}
	if claims.VCT == "" {
		return fmt.Errorf("sdjwtvc: Claims.VCT is required")
	}
	if claims.VCTIntegrity != "" {
		if err := validateIntegrity(claims.VCTIntegrity); err != nil {
			return fmt.Errorf("sdjwtvc: Claims.VCTIntegrity: %w", err)
		}
	}
	if opts.Decoys < 0 || opts.Decoys > MaxDecoys {
		return fmt.Errorf("sdjwtvc: IssueOptions.Decoys must be between 0 and %d, got %d", MaxDecoys, opts.Decoys)
	}
	if len(opts.IssuerIntermediates) > 0 && opts.IssuerCertificate == nil {
		return fmt.Errorf("sdjwtvc: IssueOptions.IssuerIntermediates needs IssuerCertificate")
	}
	if opts.IssuerCertificate != nil {
		// Alone or with intermediates: an x5c leaf mustn't be
		// self-signed (HAIP 1.0 §6.1.1).
		if err := certchain.CheckPresentedChain(opts.IssuerCertificate, opts.IssuerIntermediates); err != nil {
			return fmt.Errorf("sdjwtvc: issuer certificate chain: %w", err)
		}
	}
	if opts.IssuerCertificate != nil {
		// A two-value assertion, not a direct one: signer.Public() is
		// every stdlib key type's own crypto.PublicKey, all of which
		// implement Equal, but a custom Signer (an HSM/KMS-backed one)
		// may not — a direct assertion would panic instead of
		// returning this func's own documented config-mismatch error,
		// the same "Signer may not be comparable" risk verifier.New's
		// own equivalent check already guards against. Found in a
		// repo-wide spec-comprehensiveness review, as a side effect of
		// adding the analogous check to credential/mdoc.Issue.
		comparableKey, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok {
			return fmt.Errorf("sdjwtvc: signer's own public key type %T does not implement Equal(crypto.PublicKey) bool", signer.Public())
		}
		if !comparableKey.Equal(opts.IssuerCertificate.PublicKey) {
			return fmt.Errorf("sdjwtvc: IssuerCertificate's public key does not match signer's public key")
		}
	}
	return nil
}
