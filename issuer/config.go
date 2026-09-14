package issuer

import (
	"fmt"
	"io"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// Endpoints are this Credential Issuer's own endpoint URLs — what
// Metadata advertises. DeferredCredential and Notification will join
// Credential and Nonce as those endpoints land (see ARCHITECTURE.md).
// Credential is required even though there is no RequestCredential
// method yet — §12.2.4 requires credential_endpoint in every Credential
// Issuer's metadata unconditionally, independent of which endpoints
// this package itself has wired up an HTTP handler for so far.
type Endpoints struct {
	// Credential is this issuer's Credential Endpoint (§8). Required.
	Credential fapi.URL

	// Nonce is this issuer's Nonce Endpoint (§7). Zero means this
	// issuer has no Nonce Endpoint at all — Metadata then omits
	// nonce_endpoint, and RequestNonce always fails.
	Nonce fapi.URL
}

// Limits bounds durations this issuer enforces. None have an implicit
// default — New rejects a zero value, the same "no implicit defaults"
// stance FAPIgo's own server.Limits takes.
type Limits struct {
	// NonceLifetime bounds how long an issued c_nonce remains valid.
	// Required only when Endpoints.Nonce is set.
	NonceLifetime time.Duration
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

	if deps.Clock == nil {
		return nil, fmt.Errorf("issuer: dependencies: clock is required")
	}
	if deps.Random == nil {
		return nil, fmt.Errorf("issuer: dependencies: random is required")
	}

	return &Issuer{cfg: cfg, deps: deps}, nil
}
