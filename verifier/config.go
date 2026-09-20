package verifier

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// Config is this Verifier's immutable configuration.
type Config struct {
	// ClientCertificate is the leaf X.509 certificate whose SHA-256
	// hash forms this Verifier's own "x509_hash" Client Identifier
	// (§5.9.3) — HAIP §5's own mandated Client Identifier Prefix for
	// a signed redirect-flow Authorization Request — and whose DER
	// encoding becomes the Request Object JWS's own "x5c" header
	// entry. Its public key must match Dependencies.Signer's own
	// public key: New rejects a mismatch. REQUIRED.
	ClientCertificate *x509.Certificate

	// ResponseURI is where a Wallet POSTs its (encrypted) response —
	// the Authorization Request's own "response_uri" (§8.3.1). This
	// package always builds a direct_post.jwt request (HAIP §5.1's
	// own mandatory encryption), so ResponseURI is always required,
	// never "redirect_uri" (§8.2's own unencrypted mode, which HAIP's
	// redirect flow doesn't permit). REQUIRED.
	ResponseURI fapi.URL

	// SigningAlg is the JOSE algorithm the Request Object is signed
	// with — HAIP §7 requires ES256 support from every entity for
	// "signed presentation requests", so ES256 is the natural
	// default; internal/jose also supports EdDSA if a deployment
	// needs it. REQUIRED.
	SigningAlg jose.Alg

	// EncValuesSupported is this Verifier's own
	// "encrypted_response_enc_values_supported" (§5.1) — the JWE
	// "enc" values it advertises it can decrypt a direct_post.jwt
	// response with. HAIP §5 requires both jwe.A128GCM and
	// jwe.A256GCM be supported by Verifiers. REQUIRED, non-empty.
	EncValuesSupported []jwe.Enc

	// VPFormatsSupported is this Verifier's own "client_metadata"
	// "vp_formats_supported" value (§10, §11.1) — a map from Credential
	// Format Identifier (e.g. "dc+sd-jwt") to that format's own
	// format-specific parameters (e.g. its own supported signature
	// algorithms), describing what this Verifier can actually verify.
	// §5.10 marks it "REQUIRED when not available to the Wallet via
	// another mechanism" — this package has no such other mechanism
	// (no separate Verifier metadata endpoint), so it's always included
	// once set. REQUIRED, non-empty: a caller must state what it can
	// actually verify, not leave the Wallet guessing.
	VPFormatsSupported map[string]any
}

// SDJWTVCFormatSupport builds Config.VPFormatsSupported's own
// "dc+sd-jwt" entry (§10, §11.1): sdJWTAlgs/kbJWTAlgs are the JOSE
// algorithms this Verifier accepts for the Issuer-signed SD-JWT and
// the Key Binding JWT respectively (that format's own
// "sd-jwt_alg_values"/"kb-jwt_alg_values" members).
func SDJWTVCFormatSupport(sdJWTAlgs, kbJWTAlgs []jose.Alg) map[string]any {
	return map[string]any{
		"dc+sd-jwt": map[string]any{
			"sd-jwt_alg_values": sdJWTAlgs,
			"kb-jwt_alg_values": kbJWTAlgs,
		},
	}
}

// MdocFormatSupport builds Config.VPFormatsSupported's own "mso_mdoc"
// entry (§10, §11.1). No established convention for "mso_mdoc"'s own
// inner vp_formats_supported shape is verified against the OIDF
// conformance suite yet — left empty rather than guessing unverified
// field names; the suite's own compatibility check is expected to key
// on the "mso_mdoc" member's presence, not its contents.
func MdocFormatSupport() map[string]any {
	return map[string]any{"mso_mdoc": map[string]any{}}
}

// Dependencies are this Verifier's external collaborators.
type Dependencies struct {
	// Signer signs the Request Object; its public key must match
	// Config.ClientCertificate's own public key — the x509_hash
	// Client Identifier binds the two together, so New rejects a
	// mismatch rather than letting a Wallet later reject a
	// self-inconsistent request. REQUIRED.
	Signer crypto.Signer

	// Random is this Verifier's source of cryptographically secure
	// randomness — for the Authorization Request's own "nonce"
	// (§5.2/§14.1.2) and the ephemeral P-256 key pair generated per
	// request for response encryption (HAIP §5's own "fresh
	// ephemeral encryption key per Authorization Request" MUST).
	// REQUIRED.
	Random io.Reader
}

// Verifier is this Verifier's own role implementation — the
// OID4VCgo analog of issuer.Issuer/wallet.Wallet, built on this
// repo's own JOSE primitives rather than FAPIgo (see the package doc
// comment for why).
type Verifier struct {
	cfg      Config
	deps     Dependencies
	clientID string
}

// New validates cfg and deps, computes this Verifier's own
// "x509_hash:..." Client Identifier from cfg.ClientCertificate, and
// returns a ready-to-use Verifier.
func New(cfg Config, deps Dependencies) (*Verifier, error) {
	if cfg.ClientCertificate == nil {
		return nil, fmt.Errorf("verifier: config: client_certificate is required")
	}
	if cfg.ResponseURI.IsZero() {
		return nil, fmt.Errorf("verifier: config: response_uri is required")
	}
	if cfg.SigningAlg == "" {
		return nil, fmt.Errorf("verifier: config: signing_alg is required")
	}
	if len(cfg.EncValuesSupported) == 0 {
		return nil, fmt.Errorf("verifier: config: enc_values_supported must be non-empty")
	}
	if len(cfg.VPFormatsSupported) == 0 {
		return nil, fmt.Errorf("verifier: config: vp_formats_supported must be non-empty")
	}
	if deps.Signer == nil {
		return nil, fmt.Errorf("verifier: dependencies: signer is required")
	}
	if deps.Random == nil {
		return nil, fmt.Errorf("verifier: dependencies: random is required")
	}
	// A two-value assertion, not a direct one: deps.Signer.Public() is
	// every stdlib key type's own crypto.PublicKey, all of which
	// implement Equal, but a custom Signer (an HSM/KMS-backed one, a
	// common choice for exactly the security-conscious integrators
	// this package targets) may not — a direct assertion would panic
	// instead of returning this func's own documented config-mismatch
	// error. Found in a repo-wide security review.
	comparableKey, ok := deps.Signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("verifier: dependencies: signer's own public key type %T does not implement Equal(crypto.PublicKey) bool", deps.Signer.Public())
	}
	if !comparableKey.Equal(cfg.ClientCertificate.PublicKey) {
		return nil, fmt.Errorf("verifier: config: client_certificate's public key does not match dependencies.signer")
	}

	hash := sha256.Sum256(cfg.ClientCertificate.Raw)
	clientID := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])

	return &Verifier{cfg: cfg, deps: deps, clientID: clientID}, nil
}

// ClientID is this Verifier's own "x509_hash:..." Client Identifier
// (§5.9.3), computed once in New from Config.ClientCertificate.
func (v *Verifier) ClientID() string { return v.clientID }
