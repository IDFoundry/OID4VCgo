package wallet

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
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

	// Locales are the holder's preferred languages (BCP 47 tags, most
	// preferred first). FetchCredentialIssuerMetadata sends them as
	// Accept-Language, as OpenID4VCI 1.0 §12.2.2 recommends, so display
	// metadata comes in them. A tag that isn't letters, digits and
	// hyphens is left out. None sends no Accept-Language.
	Locales []string

	// VerifierTrust decides which Verifiers' Request Objects this
	// Wallet accepts (OID4VP §5.9.3) — see VerifierTrust's own doc
	// comment. Required by FetchAuthorizationRequest, so optional for a
	// Wallet that only receives credentials. NoVerifierTrust{} is
	// rejected under AssuranceProduction.
	VerifierTrust VerifierTrust

	// AcceptX509SANDNS also accepts Request Objects whose client_id has
	// the x509_san_dns Client Identifier Prefix (OpenID4VP 1.0 §5.9.3),
	// besides x509_hash: "x509_san_dns:<DNS name>", where the DNS name
	// is a dNSName subject alternative name of the x5c leaf that signed
	// the request, and, outside the DC API, response_uri's host. HAIP
	// 1.0 §5 has Verifiers use x509_hash for signed requests, and asks
	// Wallets to accept that; it doesn't forbid a Wallet accepting
	// another prefix, which the Verifiers of some deployments use. Off,
	// an x509_san_dns client_id is refused as one that isn't the leaf's
	// x509_hash.
	//
	// The name binds the request to the Verifier only through the chain
	// to VerifierTrust's anchors, so New refuses it without a
	// VerifierTrust that verifies one: none, NoVerifierTrust, or an
	// X5CVerifierRoots without Roots. Those anchors then vouch for every
	// name in the certificates under them: anchor only Verifiers, or
	// tell their certificates apart with X5CVerifierRoots.LeafPolicy.
	AcceptX509SANDNS bool

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
	// IssuerMetadataLeafPolicy, if set, decides whether a certificate
	// under IssuerMetadataRoots may sign issuer metadata: an extended key
	// usage or certificate policy the ecosystem marks those signers'
	// certificates with, so one issued under the same roots for another
	// role, such as a Verifier's, can't vouch for an issuer.
	IssuerMetadataLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// IssuerMetadataRevocation checks the metadata signer's certificate
	// chain for revocation: signed metadata is used only through a path
	// that passes it, and one signed by a revoked certificate is refused
	// with an error wrapping certrevocation.ErrRevoked. Under
	// AssuranceProduction, New requires it with IssuerMetadataRoots:
	// certrevocation.NoCheck{} declines. Under AssuranceDevelopment, nil
	// checks no revocation; see certrevocation.
	IssuerMetadataRevocation certrevocation.Checker

	// RequireSignedIssuerMetadata refuses Credential Issuer Metadata
	// that isn't signed by a certificate chaining to
	// IssuerMetadataRoots, which it requires.
	RequireSignedIssuerMetadata bool

	// RequireIssuerMetadataName refuses signed Credential Issuer
	// Metadata whose signing certificate doesn't name the Credential
	// Issuer, its sub: as a uniformResourceIdentifier subject
	// alternative name, or for a "dns:" identifier a dNSName. Without
	// it, any certificate under IssuerMetadataRoots can sign any
	// issuer's metadata; set it where those roots certify several
	// parties. Requires IssuerMetadataRoots.
	RequireIssuerMetadataName bool

	// MaxIssuerMetadataAge, when positive, refuses signed Credential
	// Issuer Metadata issued (iat) longer ago than this: a signed
	// document without exp would otherwise stay usable indefinitely,
	// after the issuer has changed its endpoints.
	MaxIssuerMetadataAge time.Duration
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
	// http.Client has no such guard. Under AssuranceProduction New
	// refuses any other (fapihttp.HardeningOf), one whose transport was
	// changed after NewClient built it, and one allowing loopback. An *http.Client is used through a
	// copy that follows no redirect, so a DPoP proof, access token or
	// client attestation is never resent to a host the Wallet didn't
	// choose, and whose Timeout, if zero (as NewClient leaves it), is
	// Config.Fetch.RequestTimeout; another HTTPClient (a wrapper) must
	// not follow redirects itself, and must bound each request's time.
	HTTP fapihttp.HTTPClient

	// Clock supplies the current time — the jwt-type key proof's own
	// iat claim, and a DPoP proof's own iat claim.
	Clock Clock

	// Random is the source of cryptographically secure randomness for
	// a DPoP proof's own jti claim (RFC 9449 §4.2) — required only for
	// RequestPreAuthorizedCodeToken and GenerateDPoPProof. Under
	// AssuranceProduction it must be crypto/rand.Reader, which nil
	// then means, as issuer and verifier require.
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
	if err := checkAssuranceConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.ProofSigningAlg == "" {
		return nil, fmt.Errorf("wallet: config: proof_signing_alg is required")
	}
	if !jose.IsSupported(cfg.ProofSigningAlg) {
		return nil, fmt.Errorf("wallet: config: proof_signing_alg %q is not supported", cfg.ProofSigningAlg)
	}
	if err := checkProductionHTTP(cfg.Assurance, deps.HTTP); err != nil {
		return nil, err
	}
	httpClient, err := walletHTTPClient(cfg, deps.HTTP)
	if err != nil {
		return nil, err
	}
	deps.HTTP = httpClient
	if deps.Clock == nil {
		return nil, fmt.Errorf("wallet: dependencies: clock is required")
	}
	if cfg.Assurance == AssuranceProduction {
		if deps.Random == nil {
			deps.Random = rand.Reader
		}
		if deps.Random != rand.Reader {
			return nil, fmt.Errorf("wallet: dependencies: random must be crypto/rand.Reader, or nil, under AssuranceProduction")
		}
	}

	if err := checkIssuerMetadataConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateVerifierTrust(cfg.Assurance, cfg.VerifierTrust); err != nil {
		return nil, err
	}
	if err := checkAcceptX509SANDNS(cfg); err != nil {
		return nil, err
	}

	fetcher, err := fapihttp.New(deps.HTTP, cfg.Fetch)
	if err != nil {
		return nil, fmt.Errorf("wallet: config: fetch: %w", err)
	}
	return &Wallet{cfg: cfg, deps: deps, fetcher: fetcher}, nil
}

// checkAssuranceConfig refuses an invalid assurance level, and the
// loopback and verifier-trust allowances AssuranceProduction forbids.
func checkAssuranceConfig(cfg Config) error {
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return fmt.Errorf("wallet: config: assurance level is invalid")
	}
	if cfg.Assurance == AssuranceProduction && cfg.Fetch.AllowLoopbackHTTP {
		return fmt.Errorf("wallet: config: fetch.allow_loopback_http is not permitted under AssuranceProduction")
	}
	if cfg.Assurance == AssuranceProduction && cfg.Fetch.AllowLoopbackHosts {
		return fmt.Errorf("wallet: config: fetch.allow_loopback_hosts is not permitted under AssuranceProduction")
	}
	// fapihttp's own rule: every loopback exception is for local
	// development, and the transport New builds dials loopback for a
	// host AllowedLoopbackHosts lists.
	if cfg.Assurance == AssuranceProduction && cfg.Fetch.AllowsLoopback() {
		return fmt.Errorf("wallet: config: fetch.allowed_loopback_hosts is not permitted under AssuranceProduction")
	}
	if cfg.Assurance == AssuranceProduction && isNoVerifierTrust(cfg.VerifierTrust) {
		return fmt.Errorf("wallet: config: verifier_trust NoVerifierTrust is not permitted under AssuranceProduction")
	}
	return nil
}

// checkIssuerMetadataConfig refuses an issuer metadata requirement
// without the roots to check it, and a negative maximum age.
func checkIssuerMetadataConfig(cfg Config) error {
	if cfg.RequireSignedIssuerMetadata && cfg.IssuerMetadataRoots == nil {
		return fmt.Errorf("wallet: config: require_signed_issuer_metadata needs issuer_metadata_roots")
	}
	if cfg.RequireIssuerMetadataName && cfg.IssuerMetadataRoots == nil {
		return fmt.Errorf("wallet: config: require_issuer_metadata_name needs issuer_metadata_roots")
	}
	if cfg.MaxIssuerMetadataAge < 0 {
		return fmt.Errorf("wallet: config: max_issuer_metadata_age must not be negative")
	}
	if cfg.Assurance == AssuranceProduction && cfg.IssuerMetadataRoots != nil && cfg.IssuerMetadataRevocation == nil {
		return fmt.Errorf("wallet: config: issuer_metadata_revocation is required with issuer_metadata_roots under AssuranceProduction: %s", certchain.RevocationChoices)
	}
	if err := certchain.ValidateRevocation(cfg.IssuerMetadataRevocation); err != nil {
		return fmt.Errorf("wallet: config: issuer_metadata_revocation: %w", err)
	}
	return nil
}

// defaultHTTPTimeout bounds each request of the HTTP client New builds
// when Dependencies.HTTP is nil and Config.Fetch sets no RequestTimeout.
const defaultHTTPTimeout = 30 * time.Second

// requestTimeout is the per-request timeout of the Wallet's HTTP
// client: cfg.Fetch.RequestTimeout, or defaultHTTPTimeout.
func requestTimeout(cfg Config) time.Duration {
	if cfg.Fetch.RequestTimeout > 0 {
		return cfg.Fetch.RequestTimeout
	}
	return defaultHTTPTimeout
}

// walletHTTPClient is the HTTP client the Wallet uses: with none given,
// fapihttp's hardened one, its loopback and private-host allowances
// those of cfg.Fetch; with an *http.Client, a copy that follows no
// redirect, so a token request's or a Credential Request's DPoP proof,
// access token or client attestation is never resent to a host the
// Wallet didn't choose, and that times out after requestTimeout when
// it has no Timeout of its own. Another HTTPClient is used as it is.
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
		client.Timeout = requestTimeout(cfg)
		return client, nil
	case *http.Client:
		if c == nil {
			return nil, fmt.Errorf("wallet: dependencies: http is a nil *http.Client")
		}
		noRedirects := *c
		noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		// fapihttp.NewClient sets no Timeout. The fetcher bounds its own
		// calls, but the token, Credential and direct_post requests go
		// through this client directly, so without one a stalled server
		// holds them until ctx ends.
		if noRedirects.Timeout <= 0 {
			noRedirects.Timeout = requestTimeout(cfg)
		}
		return &noRedirects, nil
	default:
		return given, nil
	}
}

// checkProductionHTTP refuses, under AssuranceProduction, an HTTP client
// other than fapihttp.NewClient's with its transport intact and no
// loopback exception: only that transport refuses private and loopback
// addresses when it dials, which is what keeps an offer's or a
// Verifier's URLs from reaching into the Wallet's own network, DNS
// rebinding included. nil is fine: New then builds that client itself.
func checkProductionHTTP(assurance AssuranceLevel, given fapihttp.HTTPClient) error {
	if assurance != AssuranceProduction || given == nil {
		return nil
	}
	c, ok := given.(*http.Client)
	if !ok {
		return errors.New("wallet: dependencies: http must be fapihttp.NewClient's *http.Client under AssuranceProduction, or nil")
	}
	h, ok := fapihttp.HardeningOf(c)
	switch {
	case !ok:
		return errors.New("wallet: dependencies: http must be fapihttp.NewClient's client, its transport unchanged, under AssuranceProduction")
	case h.AllowsLoopback():
		return errors.New("wallet: dependencies: http allows loopback addresses, which AssuranceProduction refuses")
	}
	return nil
}
