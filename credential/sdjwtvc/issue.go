package sdjwtvc

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// TypHeader is the JOSE "typ" header value for the Issuer-signed JWT
// component of an SD-JWT VC (draft-11 §3.2.1). A Verifier/Holder
// SHOULD also accept LegacyTypHeader during a transitional period.
const TypHeader = "dc+sd-jwt"

// LegacyTypHeader is the "typ" value this draft used from its inception
// in July 2023 until November 2024 (draft-11 §3.2.1) — accepted here
// for interop with issuers/wallets that haven't migrated yet.
const LegacyTypHeader = "vc+sd-jwt"

// MediaType is the SD-JWT VC media type (draft-11 §3.1).
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
// (draft-11 §3.2.2.1). Iss, Nbf, Exp, VCTIntegrity, Status and CNF are
// the registered claims draft-11 §3.2.2.2 forbids from ever being
// selectively disclosed, so they're always plaintext — putting one of
// their claim names in Additional is rejected. Nbf/Exp/Iat use a Unix
// timestamp (int64), matching JWT's NumericDate (RFC 7519 §2), not
// time.Time — this package does no implicit time-type conversion for
// values inside Additional either, so any caller-supplied claim that
// needs to be a NumericDate must already be an int64 when passed in.
type Claims struct {
	VCT          string // REQUIRED
	Iss          string
	Nbf          *int64
	Exp          *int64
	VCTIntegrity string
	Status       map[string]any // see draft-ietf-oauth-status-list
	CNF          map[string]any // REQUIRED if Key Binding is to be supported

	// Additional holds any further public/private claims (draft-11
	// §3.2.2.3), including the registered "sub" and "iat" claims that
	// draft-11 §3.2.2.2 permits (but does not require) to be
	// selectively disclosed. Wrap a value with SD to make its property
	// selectively disclosable, or SDElement for an array element.
	Additional map[string]any
}

// IssueOptions configures Issue.
type IssueOptions struct {
	// HashAlg selects the digest algorithm (RFC 9901 §4.1.1). Defaults
	// to DefaultHashAlg (sha-256) — every implementation MUST support
	// it, so it is always safe as a default.
	HashAlg HashAlg

	// Decoys adds this many decoy digests to the top-level _sd array
	// (RFC 9901 §4.2.5). 0 by default.
	Decoys int

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
}

var reservedTopLevelClaims = map[string]bool{
	"vct": true, "iss": true, "nbf": true, "exp": true,
	"vct#integrity": true, "status": true, "cnf": true,
	"_sd": true, "_sd_alg": true, "...": true,
}

// applyPlaintextClaims sets sealed's own always-plaintext registered
// claims (draft-11 §3.2.2.2's own never-selectively-disclosed set)
// from claims — split out of Issue purely to keep it under the
// linter's own cognitive complexity ceiling.
func applyPlaintextClaims(sealed map[string]any, claims Claims) {
	sealed["vct"] = claims.VCT
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
		header["x5c"] = []string{base64.StdEncoding.EncodeToString(opts.IssuerCertificate.Raw)}
	}
	return header
}

// Issue builds and signs an SD-JWT VC. An Issuer never produces an
// SD-JWT+KB (only a Holder presents one — RFC 9901 §7.2), so the result
// is always a bare SD-JWT — its compact form ends in "~" per RFC 9901
// §4. The returned Disclosures are every one Issue generated; the
// Holder needs all of them to later choose a subset to present (via
// Presentation/ResolveDisclosures).
func Issue(signer crypto.Signer, alg jose.Alg, claims Claims, opts IssueOptions) (sdjwt string, disclosures []Disclosure, err error) {
	if claims.VCT == "" {
		return "", nil, fmt.Errorf("sdjwtvc: Claims.VCT is required")
	}
	if opts.IssuerCertificate != nil {
		if !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(opts.IssuerCertificate.PublicKey) {
			return "", nil, fmt.Errorf("sdjwtvc: IssuerCertificate's public key does not match signer's public key")
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

	sealed, disclosures, err := sealMap(tree, hashAlg)
	if err != nil {
		return "", nil, fmt.Errorf("sdjwtvc: seal claims: %w", err)
	}

	applyPlaintextClaims(sealed, claims)

	if opts.Decoys > 0 {
		if err := addDecoys(sealed, hashAlg, opts.Decoys); err != nil {
			return "", nil, err
		}
	}
	if len(disclosures) > 0 || opts.Decoys > 0 {
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

	out := issuerJWT + "~"
	for _, d := range disclosures {
		enc, err := d.Encode()
		if err != nil {
			return "", nil, err
		}
		out += enc + "~"
	}
	return out, disclosures, nil
}
