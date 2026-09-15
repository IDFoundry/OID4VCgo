package issuer

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
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
}

// Config is this issuer's immutable configuration.
type Config struct {
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
}

// Issuer is this Credential Issuer's own role implementation — the
// OID4VCIgo analog of fapigo/server.Server, built on top of it.
type Issuer struct {
	cfg  Config
	deps Dependencies
}

// New validates cfg and deps and returns a ready-to-use Issuer.
func New(cfg Config, deps Dependencies) (*Issuer, error) {
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

	if deps.Clock == nil {
		return nil, fmt.Errorf("issuer: dependencies: clock is required")
	}
	if deps.Random == nil {
		return nil, fmt.Errorf("issuer: dependencies: random is required")
	}

	if err := validateSignerDependencies(cfg, deps); err != nil {
		return nil, fmt.Errorf("issuer: dependencies: %w", err)
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
