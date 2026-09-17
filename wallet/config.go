package wallet

import (
	"fmt"
	"io"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Config bounds this Wallet's own behavior. None of these have an
// implicit default — New rejects a zero value, the same "no implicit
// defaults" stance issuer.Config takes.
type Config struct {
	// ProofSigningAlg is the JOSE algorithm this Wallet signs jwt-type
	// key proofs with (Appendix F.1). REQUIRED.
	ProofSigningAlg jose.Alg

	// Fetch bounds this Wallet's own unauthenticated HTTP calls — a
	// by-reference Credential Offer's GET fetch (§4.1.3) and the Nonce
	// Endpoint's POST (§7.1), neither of which carries an access token
	// — passed directly to fapihttp.New. REQUIRED.
	Fetch fapihttp.Config
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

// Dependencies are this Wallet's external collaborators.
type Dependencies struct {
	// HTTP performs this Wallet's own unauthenticated calls: the Nonce
	// Endpoint (wrapped in a fapihttp.Client, see Config.Fetch, for
	// SSRF/size/redirect hardening), a by-reference Credential Offer's
	// fetch (same wrapping), and the pre-authorized_code Token Request
	// (§6.1) — called directly, unwrapped, since that request's own
	// DPoP proof header has no equivalent in fapihttp.Client's fixed
	// GET/POST shapes. It does not perform Credential Endpoint calls
	// itself — see RequestCredential's own ProtectedResourceClient
	// parameter for why that one is sender-constrained per request,
	// not a Dependencies-level HTTP client.
	HTTP fapihttp.HTTPClient

	// Clock supplies the current time — the jwt-type key proof's own
	// iat claim, and a DPoP proof's own iat claim.
	Clock Clock

	// Random is the source of cryptographically secure randomness for
	// a DPoP proof's own jti claim (RFC 9449 §4.2) — required only for
	// RequestPreAuthorizedCodeToken.
	Random io.Reader
}

// Wallet is this Wallet's own role implementation — the OID4VCgo
// analog of issuer.Issuer, built on fapigo/client.
type Wallet struct {
	cfg     Config
	deps    Dependencies
	fetcher *fapihttp.Client
}

// New validates cfg and deps and returns a ready-to-use Wallet.
func New(cfg Config, deps Dependencies) (*Wallet, error) {
	if cfg.ProofSigningAlg == "" {
		return nil, fmt.Errorf("wallet: config: proof_signing_alg is required")
	}
	if deps.HTTP == nil {
		return nil, fmt.Errorf("wallet: dependencies: http is required")
	}
	if deps.Clock == nil {
		return nil, fmt.Errorf("wallet: dependencies: clock is required")
	}

	fetcher, err := fapihttp.New(deps.HTTP, cfg.Fetch)
	if err != nil {
		return nil, fmt.Errorf("wallet: config: fetch: %w", err)
	}
	return &Wallet{cfg: cfg, deps: deps, fetcher: fetcher}, nil
}
