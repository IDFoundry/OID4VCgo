package issuer

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Endpoints are this Credential Issuer's own endpoint URLs — what
// Metadata advertises. Credential is required even though there is no
// RequestCredential method yet — §12.2.4 requires credential_endpoint
// in every Credential Issuer's metadata unconditionally, independent
// of which endpoints this package itself has wired up an HTTP handler
// for so far.
type Endpoints struct {
	// Credential is this issuer's Credential Endpoint (§8). Required.
	Credential fapi.URL

	// Nonce is this issuer's Nonce Endpoint (§7). Zero means this
	// issuer has no Nonce Endpoint at all — Metadata then omits
	// nonce_endpoint, and RequestNonce always fails.
	Nonce fapi.URL

	// DeferredCredential is this issuer's Deferred Credential Endpoint
	// (§9). Zero means this issuer never defers issuance — Metadata
	// then omits deferred_credential_endpoint, and
	// RequestDeferredCredential always fails.
	DeferredCredential fapi.URL

	// Notification is this issuer's Notification Endpoint (§11). Zero
	// means this issuer never accepts notifications — Metadata then
	// omits notification_endpoint, RequestCredential never sets
	// oid4vci.CredentialResponse.NotificationID, and RequestNotification
	// always fails.
	Notification fapi.URL
}

// Limits bounds durations this issuer enforces. None have an implicit
// default — New rejects a zero value, the same "no implicit defaults"
// stance FAPIgo's own server.Limits takes.
type Limits struct {
	// NonceLifetime bounds how long an issued c_nonce remains valid.
	// Required only when Endpoints.Nonce is set.
	NonceLifetime time.Duration

	// CredentialOfferLifetime bounds how long a by-reference Credential
	// Offer (§4.1.3) remains fetchable. Required only when
	// CredentialOfferEndpoint is set.
	CredentialOfferLifetime time.Duration

	// DeferredIssuancePollInterval is the minimum time this issuer asks
	// a Wallet to wait before polling the Deferred Credential Endpoint
	// again (§9.2's own "interval" member). Required only when
	// Endpoints.DeferredCredential is set.
	DeferredIssuancePollInterval time.Duration

	// AccessTokenLifetime bounds how long an access token
	// ExchangePreAuthorizedCode issues remains valid. Required only
	// when Dependencies.PreAuthorizedCodes is set.
	AccessTokenLifetime time.Duration

	// MaxDPoPProofAge bounds how old (relative to Now) a DPoP proof's
	// own "iat" may be before ExchangePreAuthorizedCode rejects it
	// (RFC 9449 §4.3). Required only when Dependencies.PreAuthorizedCodes
	// is set.
	MaxDPoPProofAge time.Duration

	// MaxDPoPClockSkew bounds how far in the future (relative to Now) a
	// DPoP proof's own "iat" may be before ExchangePreAuthorizedCode
	// rejects it. Zero means no tolerance for a future-dated proof —
	// matching internal/dpop.VerifyRequest's own zero-value meaning, no
	// separate "required" check.
	MaxDPoPClockSkew time.Duration

	// DPoPNonceLifetime bounds how long a DPoP nonce
	// ExchangePreAuthorizedCode issues (RFC 9449 §8) remains valid.
	// Required only when Dependencies.DPoPNonces is set.
	DPoPNonceLifetime time.Duration
}

// Config is this issuer's immutable configuration.
type Config struct {
	// Assurance gates how strict New's own validation is — see
	// AssuranceLevel's own doc comment. REQUIRED: New rejects the Go
	// zero value, forcing every caller to make an explicit choice
	// rather than silently getting AssuranceDevelopment's weaker
	// checks by omission.
	Assurance AssuranceLevel

	// Issuer is this Credential Issuer's identifier (§12.2.1) — the
	// value Metadata's own credential_issuer member echoes.
	Issuer fapi.URL

	Endpoints Endpoints
	Limits    Limits

	// CredentialConfigurationsSupported describes every Credential this
	// issuer supports issuing (§12.2.4's credential_configurations_supported),
	// keyed by its Credential Configuration ID. Required — Metadata has
	// no meaningful default for this.
	CredentialConfigurationsSupported map[string]CredentialConfiguration

	// CredentialOfferEndpoint is the base URL this issuer hosts
	// by-reference Credential Offers under (§4.1.3): GetCredentialOffer's
	// caller serves each offer at this URL plus "/" plus the reference
	// CreateCredentialOffer returned. Unlike Endpoints, this is never
	// advertised in Credential Issuer Metadata — §12.2.4 defines no such
	// member, since the Wallet learns a specific offer's URL only from
	// the credential_offer_uri value itself, never from discovery. Zero
	// means this issuer never issues Credential Offers by reference;
	// CreateCredentialOffer then only supports embedding the offer by
	// value.
	CredentialOfferEndpoint fapi.URL

	// RequestEncryption declares this issuer's own support for
	// encrypted Credential/Deferred Credential Requests (§10, published
	// as Metadata's own credential_request_encryption). Nil means this
	// issuer never accepts one — DecryptRequestBody then rejects any
	// request claiming to be encrypted.
	RequestEncryption *RequestEncryptionSupport

	// ResponseEncryption declares this issuer's own support for
	// encrypting Credential/Deferred Credential Responses (§10,
	// published as Metadata's own credential_response_encryption). Nil
	// means this issuer never encrypts a Response, even if a Wallet
	// asks — EncryptResponseBody then rejects the request.
	ResponseEncryption *ResponseEncryptionSupport

	// Display is this Credential Issuer's own OPTIONAL display metadata
	// (§12.2.4's top-level "display"), one entry per locale. Empty means
	// Metadata omits display entirely.
	Display []oid4vci.Display

	// BatchCredentialIssuance declares this issuer's own OPTIONAL
	// support for batch issuance (§12.2.4's "batch_credential_issuance")
	// — see oid4vci.BatchCredentialIssuance's own doc comment for what
	// setting this does and doesn't change. Nil means Metadata omits
	// batch_credential_issuance entirely.
	BatchCredentialIssuance *oid4vci.BatchCredentialIssuance
}

// Clock supplies the current time — a plain function value satisfies
// it (e.g. Clock(time.Now)), or a fixed-time fake in tests.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

// Now implements Clock.
func (f ClockFunc) Now() time.Time { return f() }

// SDJWTSigner configures how this issuer signs
// credential/sdjwtvc.CredentialFormat ("dc+sd-jwt") credentials.
type SDJWTSigner struct {
	Signer crypto.Signer
	Alg    jose.Alg

	// KeyID optionally sets the JOSE "kid" header on issued credentials.
	KeyID string

	// IssuerCertificate, if set, becomes the issued credential's own
	// "x5c" header entry — see
	// credential/sdjwtvc.IssueOptions.IssuerCertificate's own doc
	// comment for why HAIP's SD-JWT VC trust model needs this (a CA-
	// signed leaf, not a self-signed one — confirmed live against the
	// OpenID Foundation conformance suite's own two checks on this
	// exact requirement). Optional: MdocSigner's own X5Chain has always
	// been required-in-practice for "mso_mdoc"; this field brings
	// "dc+sd-jwt" issuance to the same standing, added once a real
	// need (this conformance suite check) confirmed it, matching this
	// package's own "extend only when a real need arises" discipline.
	IssuerCertificate *x509.Certificate
}

func (s *SDJWTSigner) validate() error {
	if s == nil {
		return fmt.Errorf("sdjwt_signer is required when a credential_configurations_supported entry uses format %q", sdjwtvc.CredentialFormat)
	}
	if s.Signer == nil {
		return fmt.Errorf("sdjwt_signer.signer is required")
	}
	if s.Alg == "" {
		return fmt.Errorf("sdjwt_signer.alg is required")
	}
	return nil
}

// MdocSigner configures how this issuer signs
// credential/mdoc.CredentialFormat ("mso_mdoc") credentials.
type MdocSigner struct {
	Signer crypto.Signer
	Alg    cose.Alg

	// X5Chain is the issuer's certificate (DER), followed by any
	// intermediates, leaf first — see credential/mdoc.IssueOptions.X5Chain.
	X5Chain [][]byte

	// KeyID optionally sets the COSE "kid" header on issued credentials.
	KeyID []byte
}

func (s *MdocSigner) validate() error {
	if s == nil {
		return fmt.Errorf("mdoc_signer is required when a credential_configurations_supported entry uses format %q", mdoc.CredentialFormat)
	}
	if s.Signer == nil {
		return fmt.Errorf("mdoc_signer.signer is required")
	}
	if s.Alg == 0 {
		return fmt.Errorf("mdoc_signer.alg is required")
	}
	if len(s.X5Chain) == 0 {
		return fmt.Errorf("mdoc_signer.x5chain must include at least one certificate")
	}
	return nil
}

// AttestationVerifier resolves the trusted public key (and its JOSE
// algorithm) to verify a parsed Key Attestation JWT's signature with —
// entirely this issuer's own trust policy for which attestation
// providers it accepts, the same "resolving trust is the caller's job"
// split attestation.Verify itself draws.
type AttestationVerifier interface {
	ResolveAttestationKey(ctx context.Context, a attestation.KeyAttestation) (crypto.PublicKey, jose.Alg, error)
}

// ProofBindingKeyResolver resolves a jwt-type key proof's own "kid" or
// "x5c" JOSE header (Appendix F.1) to the public key it identifies —
// entirely this issuer's own trust policy for what either one means
// (a DID URL into a DID Document for kid; an x5c chain's own trust
// anchor for x5c; a private key registry; ...), the same "resolving
// trust is the caller's job" split AttestationVerifier already draws
// for a Key Attestation's own kid/x5c/trust_chain. header is the proof
// JWT's raw decoded JOSE header (jose.DecodeUnverified's own return
// shape) — exactly one of its "kid"/"x5c" entries is present, whichever
// this proof actually conveys.
type ProofBindingKeyResolver interface {
	ResolveProofBindingKey(ctx context.Context, header map[string]any) (crypto.PublicKey, error)
}

// Dependencies are this issuer's external collaborators.
type Dependencies struct {
	// Nonces persists issued c_nonce values. Required when
	// Config.Endpoints.Nonce is set.
	Nonces NonceStore

	// Clock supplies the current time.
	Clock Clock

	// Random is the source of cryptographically secure randomness for
	// generating c_nonce values — ordinarily crypto/rand.Reader.
	Random io.Reader

	// SDJWTSigner signs issued dc+sd-jwt credentials. Required when any
	// Config.CredentialConfigurationsSupported entry uses
	// credential/sdjwtvc.CredentialFormat.
	SDJWTSigner *SDJWTSigner

	// MdocSigner signs issued mso_mdoc credentials. Required when any
	// Config.CredentialConfigurationsSupported entry uses
	// credential/mdoc.CredentialFormat.
	MdocSigner *MdocSigner

	// AttestationVerifier resolves the trust key for a Key Attestation
	// JWT's signature. Required when any
	// Config.CredentialConfigurationsSupported entry supports the
	// "attestation" proof type.
	AttestationVerifier AttestationVerifier

	// ProofBindingKeys resolves a jwt-type key proof's own "kid" or
	// "x5c" header to a public key (Appendix F.1). Optional: a jwt-type
	// proof conveying "jwk" (the common case) never needs it; required
	// only when a Credential Request actually presents a kid- or
	// x5c-conveyed proof, which is otherwise rejected as unsupported.
	ProofBindingKeys ProofBindingKeyResolver

	// CredentialOffers persists Credential Offers issued by reference
	// (§4.1.3). Required when Config.CredentialOfferEndpoint is set.
	CredentialOffers CredentialOfferStore

	// DeferredTransactions persists Deferred Issuance transactions
	// (§9). Required when Config.Endpoints.DeferredCredential is set.
	DeferredTransactions DeferredTransactionStore

	// Notifications persists notification_id values issued to Wallets
	// (§11). Required when Config.Endpoints.Notification is set.
	Notifications NotificationStore

	// NotificationHandler reacts to a validated Notification Request's
	// event — entirely this deployment's own business logic; this
	// package has none of its own (§11: "These events enable the
	// Credential Issuer to take subsequent actions after issuance").
	// OPTIONAL even when Config.Endpoints.Notification is set:
	// RequestNotification still succeeds with a nil NotificationHandler,
	// since a Wallet is never guaranteed to send a notification at all.
	NotificationHandler NotificationHandler

	// PreAuthorizedCodes persists pre-authorized_code values issued as
	// part of a Credential Offer and lets ExchangePreAuthorizedCode
	// redeem one exactly once. Setting this is what opts an Issuer into
	// the Pre-Authorized Code Flow's own Token Request/Response
	// (§6.1/§6.2) at all — there's no Config.Endpoints field for it,
	// since (unlike the Credential/Nonce/Deferred Credential/Notification
	// Endpoints) the Token Endpoint itself belongs to whichever
	// Authorization Server this issuer is paired with, not to this
	// package. Required, along with DPoPReplay and AccessTokens below,
	// exactly when a caller wants to call ExchangePreAuthorizedCode.
	PreAuthorizedCodes PreAuthorizedCodeStore

	// DPoPReplay detects DPoP proof replay by "jti" for
	// ExchangePreAuthorizedCode's own Token Request (RFC 9449 §11.1).
	// Required when PreAuthorizedCodes is set.
	DPoPReplay DPoPReplayChecker

	// AccessTokens mints the access token ExchangePreAuthorizedCode
	// returns on success. Required when PreAuthorizedCodes is set.
	AccessTokens AccessTokenIssuer

	// DPoPNonces enables RFC 9449 §8's own DPoP nonce-challenge flow for
	// ExchangePreAuthorizedCode — see DPoPNonceStore's own doc comment.
	// Optional: nil (the default) disables it entirely, regardless of
	// whether PreAuthorizedCodes is set. Config.Limits.DPoPNonceLifetime
	// is required whenever this is non-nil.
	DPoPNonces DPoPNonceStore
}

// Issuer is this Credential Issuer's own role implementation — the
// OID4VCgo analog of fapigo/server.Server, built on top of it.
type Issuer struct {
	cfg  Config
	deps Dependencies
}

// New validates cfg and deps and returns a ready-to-use Issuer.
func New(cfg Config, deps Dependencies) (*Issuer, error) {
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return nil, fmt.Errorf("issuer: config: assurance level is invalid")
	}
	if cfg.Issuer.IsZero() {
		return nil, fmt.Errorf("issuer: config: issuer is required")
	}
	if cfg.Endpoints.Credential.IsZero() {
		return nil, fmt.Errorf("issuer: config: endpoints.credential is required")
	}
	if len(cfg.CredentialConfigurationsSupported) == 0 {
		return nil, fmt.Errorf("issuer: config: credential_configurations_supported must not be empty")
	}
	for id, c := range cfg.CredentialConfigurationsSupported {
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("issuer: config: credential_configurations_supported[%q]: %w", id, err)
		}
	}
	for i, d := range cfg.Display {
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("issuer: config: display[%d]: %w", i, err)
		}
	}
	if cfg.BatchCredentialIssuance != nil {
		if err := cfg.BatchCredentialIssuance.Validate(); err != nil {
			return nil, fmt.Errorf("issuer: config: batch_credential_issuance: %w", err)
		}
	}

	nonceEnabled := !cfg.Endpoints.Nonce.IsZero()
	if nonceEnabled {
		if cfg.Limits.NonceLifetime <= 0 {
			return nil, fmt.Errorf("issuer: config: limits.nonce_lifetime must be positive when endpoints.nonce is set")
		}
		if deps.Nonces == nil {
			return nil, fmt.Errorf("issuer: dependencies: nonces is required when endpoints.nonce is set")
		}
	}

	credentialOfferEndpointEnabled := !cfg.CredentialOfferEndpoint.IsZero()
	if credentialOfferEndpointEnabled {
		if cfg.Limits.CredentialOfferLifetime <= 0 {
			return nil, fmt.Errorf("issuer: config: limits.credential_offer_lifetime must be positive when credential_offer_endpoint is set")
		}
		if deps.CredentialOffers == nil {
			return nil, fmt.Errorf("issuer: dependencies: credential_offers is required when credential_offer_endpoint is set")
		}
	}

	deferredCredentialEndpointEnabled := !cfg.Endpoints.DeferredCredential.IsZero()
	if deferredCredentialEndpointEnabled {
		if cfg.Limits.DeferredIssuancePollInterval <= 0 {
			return nil, fmt.Errorf("issuer: config: limits.deferred_issuance_poll_interval must be positive when endpoints.deferred_credential is set")
		}
		if deps.DeferredTransactions == nil {
			return nil, fmt.Errorf("issuer: dependencies: deferred_transactions is required when endpoints.deferred_credential is set")
		}
	}

	if !cfg.Endpoints.Notification.IsZero() && deps.Notifications == nil {
		return nil, fmt.Errorf("issuer: dependencies: notifications is required when endpoints.notification is set")
	}

	if deps.PreAuthorizedCodes != nil {
		if cfg.Limits.AccessTokenLifetime <= 0 {
			return nil, fmt.Errorf("issuer: config: limits.access_token_lifetime must be positive when dependencies.pre_authorized_codes is set")
		}
		if cfg.Limits.MaxDPoPProofAge <= 0 {
			return nil, fmt.Errorf("issuer: config: limits.max_dpop_proof_age must be positive when dependencies.pre_authorized_codes is set")
		}
		if deps.DPoPReplay == nil {
			return nil, fmt.Errorf("issuer: dependencies: dpop_replay is required when dependencies.pre_authorized_codes is set")
		}
		if deps.AccessTokens == nil {
			return nil, fmt.Errorf("issuer: dependencies: access_tokens is required when dependencies.pre_authorized_codes is set")
		}
	}

	if deps.DPoPNonces != nil && cfg.Limits.DPoPNonceLifetime <= 0 {
		return nil, fmt.Errorf("issuer: config: limits.dpop_nonce_lifetime must be positive when dependencies.dpop_nonces is set")
	}

	if deps.Clock == nil {
		return nil, fmt.Errorf("issuer: dependencies: clock is required")
	}
	if deps.Random == nil {
		return nil, fmt.Errorf("issuer: dependencies: random is required")
	}

	if err := validateSignerDependencies(cfg, deps); err != nil {
		return nil, fmt.Errorf("issuer: dependencies: %w", err)
	}

	if err := cfg.RequestEncryption.validate(); err != nil {
		return nil, fmt.Errorf("issuer: config: request_encryption: %w", err)
	}
	if err := cfg.ResponseEncryption.validate(); err != nil {
		return nil, fmt.Errorf("issuer: config: response_encryption: %w", err)
	}

	if cfg.Assurance == AssuranceProduction {
		if err := checkProductionStoreAssurance(cfg, deps); err != nil {
			return nil, fmt.Errorf("issuer: %w", err)
		}
	}

	return &Issuer{cfg: cfg, deps: deps}, nil
}

// validateSignerDependencies checks that Dependencies carries whichever
// of SDJWTSigner/MdocSigner/AttestationVerifier the configured
// credentials actually need — each is otherwise optional, so an issuer
// that only issues one format doesn't have to configure the other.
func validateSignerDependencies(cfg Config, deps Dependencies) error {
	for id, c := range cfg.CredentialConfigurationsSupported {
		switch c.Format {
		case sdjwtvc.CredentialFormat:
			if err := deps.SDJWTSigner.validate(); err != nil {
				return fmt.Errorf("credential_configurations_supported[%q]: %w", id, err)
			}
		case mdoc.CredentialFormat:
			if err := deps.MdocSigner.validate(); err != nil {
				return fmt.Errorf("credential_configurations_supported[%q]: %w", id, err)
			}
		}
		if _, ok := c.ProofTypesSupported[oid4vci.ProofTypeAttestation]; ok && deps.AttestationVerifier == nil {
			return fmt.Errorf("credential_configurations_supported[%q]: attestation_verifier is required when proof_types_supported includes %q", id, oid4vci.ProofTypeAttestation)
		}
	}
	return nil
}
