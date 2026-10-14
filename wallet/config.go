package wallet

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Config bounds this Wallet's own behavior. None of these have an
// implicit default — New rejects a zero value, the same "no implicit
// defaults" stance issuer.Config takes.
type Config struct {
	// Assurance gates how strict New's own validation is — see
	// AssuranceLevel's own doc comment. REQUIRED: New rejects the Go
	// zero value, forcing every caller to make an explicit choice
	// rather than silently getting AssuranceDevelopment's weaker
	// checks by omission.
	Assurance AssuranceLevel

	// ProofSigningAlg is the JOSE algorithm this Wallet signs jwt-type
	// key proofs with (Appendix F.1). REQUIRED. Set it from the root
	// oid4vci package's own ES256/EdDSA constants rather than a bare
	// string literal — jose.Alg itself lives in an unexported internal
	// package, so those are the only named, typo-checked values an
	// external caller has to reference.
	ProofSigningAlg oid4vci.JOSEAlg

	// Fetch bounds this Wallet's own unauthenticated HTTP calls — a
	// by-reference Credential Offer's GET fetch (§4.1.3) and the Nonce
	// Endpoint's POST (§7.1), neither of which carries an access token
	// — passed directly to fapihttp.New. REQUIRED.
	Fetch fapihttp.Config

	// VerifierTrust decides which Verifiers' Request Objects this
	// Wallet accepts (OID4VP §5.9.3) — see VerifierTrust's own doc
	// comment. Required by FetchAuthorizationRequest, so optional for a
	// Wallet that only receives credentials. NoVerifierTrust{} is
	// rejected under AssuranceProduction.
	VerifierTrust VerifierTrust

	// RequireSignedDCAPIRequests refuses unsigned OpenID4VP requests over
	// the Digital Credentials API (ParseDCAPIRequestData's
	// DCAPIProtocolUnsigned) with ErrUntrustedVerifier: their only
	// identity is the origin the platform reports, which VerifierTrust
	// can't judge. HAIP 1.0 §5.2 requires a Wallet to support them, so
	// set it only where every Verifier must be one VerifierTrust accepts.
	RequireSignedDCAPIRequests bool

	// IssuerMetadataRoots are the trust anchors for signed Credential
	// Issuer Metadata (OpenID4VCI §12.2.3, HAIP 1.0 §4.1). When set,
	// FetchCredentialIssuerMetadata asks for the signed form, and uses
	// a signed response only once its x5c chains to one of these and
	// its sub names the issuer. An issuer that answers with plain JSON
	// is still used, unless RequireSignedIssuerMetadata is set. When
	// unset, a signed response is refused, since it can't be verified.
	IssuerMetadataRoots *x509.CertPool

	// RequireSignedIssuerMetadata refuses Credential Issuer Metadata
	// that isn't signed by a certificate chaining to
	// IssuerMetadataRoots, which it requires.
	RequireSignedIssuerMetadata bool
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
	//
	// nil (recommended) means fapihttp's hardened client
	// (fapihttp.NewClient): it dials only public addresses, unless
	// Config.Fetch allows loopback or named private hosts, so an offer
	// or metadata can't aim the Wallet at internal hosts. Set one only
	// to change that, and build it with fapihttp.NewClient too: a plain
	// http.Client has no such guard. An *http.Client is used through a
	// copy that follows no redirect, so a DPoP proof, access token or
	// client attestation is never resent to a host the Wallet didn't
	// choose; another HTTPClient (a wrapper) must not follow redirects
	// itself.
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
	// metadataFetcher fetches Credential Issuer Metadata: fetcher, or
	// with IssuerMetadataRoots one that also asks for signed metadata.
	metadataFetcher *fapihttp.Client
}

// New validates cfg and deps and returns a ready-to-use Wallet.
func New(cfg Config, deps Dependencies) (*Wallet, error) {
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return nil, fmt.Errorf("wallet: config: assurance level is invalid")
	}
	if cfg.Assurance == AssuranceProduction && cfg.Fetch.AllowLoopbackHTTP {
		return nil, fmt.Errorf("wallet: config: fetch.allow_loopback_http is not permitted under AssuranceProduction")
	}
	if cfg.Assurance == AssuranceProduction && cfg.Fetch.AllowLoopbackHosts {
		return nil, fmt.Errorf("wallet: config: fetch.allow_loopback_hosts is not permitted under AssuranceProduction")
	}
	if cfg.Assurance == AssuranceProduction && isNoVerifierTrust(cfg.VerifierTrust) {
		return nil, fmt.Errorf("wallet: config: verifier_trust NoVerifierTrust is not permitted under AssuranceProduction")
	}
	if cfg.ProofSigningAlg == "" {
		return nil, fmt.Errorf("wallet: config: proof_signing_alg is required")
	}
	if !jose.IsSupported(cfg.ProofSigningAlg) {
		return nil, fmt.Errorf("wallet: config: proof_signing_alg %q is not supported", cfg.ProofSigningAlg)
	}
	httpClient, err := walletHTTPClient(cfg, deps.HTTP)
	if err != nil {
		return nil, err
	}
	deps.HTTP = httpClient
	if deps.Clock == nil {
		return nil, fmt.Errorf("wallet: dependencies: clock is required")
	}

	if cfg.RequireSignedIssuerMetadata && cfg.IssuerMetadataRoots == nil {
		return nil, fmt.Errorf("wallet: config: require_signed_issuer_metadata needs issuer_metadata_roots")
	}

	fetcher, err := fapihttp.New(deps.HTTP, cfg.Fetch)
	if err != nil {
		return nil, fmt.Errorf("wallet: config: fetch: %w", err)
	}
	w := &Wallet{cfg: cfg, deps: deps, fetcher: fetcher, metadataFetcher: fetcher}
	if cfg.IssuerMetadataRoots != nil {
		if w.metadataFetcher, err = newSignedMetadataFetcher(deps.HTTP, cfg.Fetch); err != nil {
			return nil, fmt.Errorf("wallet: config: fetch: %w", err)
		}
	}
	return w, nil
}

// defaultHTTPTimeout bounds each request of the HTTP client New builds
// when Dependencies.HTTP is nil and Config.Fetch sets no RequestTimeout.
const defaultHTTPTimeout = 30 * time.Second

// walletHTTPClient is the HTTP client the Wallet uses: with none given,
// fapihttp's hardened one, its loopback and private-host allowances
// those of cfg.Fetch; with an *http.Client, a copy that follows no
// redirect, so a token request's or a Credential Request's DPoP proof,
// access token or client attestation is never resent to a host the
// Wallet didn't choose. Another HTTPClient is used as it is.
func walletHTTPClient(cfg Config, given fapihttp.HTTPClient) (fapihttp.HTTPClient, error) {
	switch c := given.(type) {
	case nil:
		client, err := fapihttp.NewClient(fapihttp.TransportConfig{
			DialTimeout: defaultHTTPTimeout, TLSHandshakeTimeout: defaultHTTPTimeout,
			AllowLoopbackHosts: cfg.Fetch.AllowLoopbackHosts, AllowLoopbackHTTP: cfg.Fetch.AllowLoopbackHTTP,
			AllowedLoopbackHosts: cfg.Fetch.AllowedLoopbackHosts, AllowedPrivateHosts: cfg.Fetch.AllowedPrivateHosts,
		})
		if err != nil {
			return nil, fmt.Errorf("wallet: dependencies: http: %w", err)
		}
		client.Timeout = cfg.Fetch.RequestTimeout
		if client.Timeout <= 0 {
			client.Timeout = defaultHTTPTimeout
		}
		return client, nil
	case *http.Client:
		if c == nil {
			return nil, fmt.Errorf("wallet: dependencies: http is a nil *http.Client")
		}
		noRedirects := *c
		noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &noRedirects, nil
	default:
		return given, nil
	}
}
