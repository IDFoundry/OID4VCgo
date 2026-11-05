package walletprovider

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"slices"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Defaults for Config's durations and sizes, used when they're zero.
const (
	DefaultWalletAttestationTTL = time.Hour
	// DefaultKeyAttestationTTL outlasts a deferred issuance review: an
	// issuer checks a Key Attestation's exp again when it issues a
	// credential it deferred (OID4VCI 1.0 Appendix D.1: exp is when the
	// attested keys expire too).
	DefaultKeyAttestationTTL  = 2 * time.Hour
	DefaultChallengeTTL       = 5 * time.Minute
	DefaultStatusListSize     = 1 << 16
	DefaultStatusListLifetime = time.Hour
	DefaultStatusListTTL      = 5 * time.Minute
)

// Upper bounds New enforces on Config's durations.
const (
	// MaxAttestationTTL bounds both attestations' lifetimes: a provider
	// re-issues them while the instance stays active, and an issuer that
	// doesn't check status trusts one until it expires.
	MaxAttestationTTL = 24 * time.Hour

	// MaxChallengeTTL bounds a challenge's lifetime.
	MaxChallengeTTL = 15 * time.Minute

	// MaxStatusListSize bounds Config.StatusListSize: 4 MiB packed,
	// which every Relying Party fetches whole.
	MaxStatusListSize = 1 << 24
)

// Config is a Provider's configuration.
type Config struct {
	// Identifier is the provider's identifier: an absolute https URI,
	// every attestation's iss, which the signing certificate names as a
	// URI subject alternative name (an issuer's
	// X5CAttesterChain.IssuerBinding, or AttesterIssuerBoundToAnchor,
	// relies on it). REQUIRED.
	Identifier string

	// ClientIDs are the OAuth client IDs the provider issues Wallet
	// Attestations for: their sub. At least one is REQUIRED.
	ClientIDs []string

	// WalletName and WalletLink are the Wallet Attestation's
	// wallet_name and wallet_link (OID4VCI 1.0 Appendix E), left out
	// when empty. WalletLink is an https URL.
	WalletName string
	WalletLink string

	// StatusListURI is the provider's status list's uri: where
	// StatusList is served, and what every attestation's status claim
	// names. An absolute https URI. REQUIRED.
	StatusListURI string

	// StatusListSize is how many indices the list has; zero means
	// DefaultStatusListSize. It must be a multiple of 4 (two bits per
	// status, so SUSPENDED fits). Each instance key holds one, for good,
	// and at most half are handed out (statuslist.DefaultFillLimit), so
	// a Wallet Attestation for a new instance key fails once half as
	// many instance keys as it has have been recorded: size it for the
	// issuances the provider will vouch for, not the instances.
	StatusListSize int

	// StatusListLifetime and StatusListTTL are the served Status List
	// Token's lifetime (exp) and the time a Relying Party may cache it
	// (ttl, Cache-Control): statuslist.Publisher's Lifetime and TTL.
	// Zero means DefaultStatusListLifetime and DefaultStatusListTTL. A
	// revocation reaches issuers within the TTL, plus their own cache
	// bounds.
	StatusListLifetime time.Duration
	StatusListTTL      time.Duration

	// WalletAttestationTTL and KeyAttestationTTL are the attestations'
	// lifetimes, at most MaxAttestationTTL; zero means
	// DefaultWalletAttestationTTL and DefaultKeyAttestationTTL.
	WalletAttestationTTL time.Duration
	KeyAttestationTTL    time.Duration

	// ChallengeTTL is how long a challenge may be used, at most
	// MaxChallengeTTL; zero means DefaultChallengeTTL.
	ChallengeTTL time.Duration

	// Policy decides what verified evidence is attested. REQUIRED.
	Policy Policy
}

// Dependencies are a Provider's collaborators.
type Dependencies struct {
	// Signer signs every attestation and the status list. Its key is
	// P-256 (ES256) or Ed25519 (EdDSA). REQUIRED.
	Signer crypto.Signer

	// Chain is Signer's certificate chain, its own certificate first and
	// the trust anchor left out, carried as every attestation's x5c
	// (HAIP 1.0 §4.4.1, §4.5.1). The signing certificate isn't
	// self-signed, may sign (no key usage or digitalSignature), lists no
	// extended key usage of another role, is valid now, and names
	// Config.Identifier as a URI subject alternative name. REQUIRED.
	Chain []*x509.Certificate

	// Instances keeps registered instances. REQUIRED.
	Instances InstanceStore

	// InstanceKeys keeps the instances' instance keys. REQUIRED.
	InstanceKeys InstanceKeyStore

	// Challenges keeps issued challenges. REQUIRED.
	Challenges ChallengeStore

	// StatusIndices keeps the status list's reserved indices and their
	// statuses (statuslist.Allocator's Store). Durable in production:
	// an index handed out twice links two instance keys' statuses.
	// REQUIRED.
	StatusIndices statuslist.IndexStore

	// Evidence are the verifiers of the evidence kinds the provider
	// accepts, each Kind once. At least one is REQUIRED.
	Evidence []EvidenceVerifier

	// Clock returns the current time; nil means time.Now.
	Clock func() time.Time

	// Random is the source of challenges and instance IDs — ordinarily
	// crypto/rand.Reader. REQUIRED.
	Random io.Reader

	// Logger receives Handler's record of each request it refuses, with
	// the internal error the response leaves out: at error level for
	// the provider's own failures, info for refusals. nil means
	// slog.Default().
	Logger *slog.Logger
}

// Provider is a Wallet Provider. Create one with New; it is safe for
// concurrent use.
type Provider struct {
	cfg       Config
	deps      Dependencies
	alg       oid4vci.JOSEAlg
	header    attestation.Header
	verifiers map[string]EvidenceVerifier
	allocator *statuslist.Allocator
	publisher *statuslist.Publisher
}

// New returns a Provider, refusing configuration that is incomplete or
// that would issue attestations an issuer refuses.
func New(cfg Config, deps Dependencies) (*Provider, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("walletprovider: config: %w", err)
	}
	if err := deps.validate(); err != nil {
		return nil, fmt.Errorf("walletprovider: dependencies: %w", err)
	}
	p := &Provider{cfg: cfg, deps: deps, verifiers: make(map[string]EvidenceVerifier, len(deps.Evidence))}
	for i, v := range deps.Evidence {
		kind := v.Kind()
		if kind == "" {
			return nil, fmt.Errorf("walletprovider: dependencies: Evidence[%d] has an empty Kind", i)
		}
		if _, ok := p.verifiers[kind]; ok {
			return nil, fmt.Errorf("walletprovider: dependencies: Evidence[%d]'s Kind %q appears more than once", i, kind)
		}
		p.verifiers[kind] = v
	}
	if err := p.checkSigner(); err != nil {
		return nil, fmt.Errorf("walletprovider: dependencies: %w", err)
	}
	p.allocator = &statuslist.Allocator{
		Lists: []statuslist.AllocatorList{{URI: cfg.StatusListURI, Size: cfg.StatusListSize}},
		Store: deps.StatusIndices, Bits: statuslist.Bits2,
	}
	p.publisher = &statuslist.Publisher{
		URI: cfg.StatusListURI, Signer: deps.Signer, Chain: deps.Chain,
		Statuses: p.allocator.Statuses(cfg.StatusListURI), Bits: statuslist.Bits2,
		Lifetime: cfg.StatusListLifetime, TTL: cfg.StatusListTTL, Now: p.now,
	}
	return p, nil
}

func (c Config) withDefaults() Config {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&c.WalletAttestationTTL, DefaultWalletAttestationTTL)
	def(&c.KeyAttestationTTL, DefaultKeyAttestationTTL)
	def(&c.ChallengeTTL, DefaultChallengeTTL)
	def(&c.StatusListLifetime, DefaultStatusListLifetime)
	def(&c.StatusListTTL, DefaultStatusListTTL)
	if c.StatusListSize == 0 {
		c.StatusListSize = DefaultStatusListSize
	}
	return c
}

func (c Config) validate() error {
	if err := httpsURI("Identifier", c.Identifier); err != nil {
		return err
	}
	if err := httpsURI("StatusListURI", c.StatusListURI); err != nil {
		return err
	}
	if c.WalletLink != "" {
		if err := httpsURI("WalletLink", c.WalletLink); err != nil {
			return err
		}
	}
	if len(c.ClientIDs) == 0 {
		return errors.New("ClientIDs needs at least one client ID")
	}
	if slices.Contains(c.ClientIDs, "") {
		return errors.New("ClientIDs has an empty client ID")
	}
	for name, d := range map[string]time.Duration{"WalletAttestationTTL": c.WalletAttestationTTL, "KeyAttestationTTL": c.KeyAttestationTTL} {
		if d < time.Minute || d > MaxAttestationTTL {
			return fmt.Errorf("%s is %v, not between a minute and %v", name, d, MaxAttestationTTL)
		}
	}
	if c.ChallengeTTL < time.Second || c.ChallengeTTL > MaxChallengeTTL {
		return fmt.Errorf("ChallengeTTL is %v, not between a second and %v", c.ChallengeTTL, MaxChallengeTTL)
	}
	if c.StatusListSize <= 0 || c.StatusListSize%4 != 0 || c.StatusListSize > MaxStatusListSize {
		return fmt.Errorf("StatusListSize is %d, not a positive multiple of 4 up to %d", c.StatusListSize, MaxStatusListSize)
	}
	if c.StatusListTTL < time.Second || c.StatusListTTL > c.StatusListLifetime {
		return fmt.Errorf("StatusListTTL is %v, not between a second and StatusListLifetime (%v)", c.StatusListTTL, c.StatusListLifetime)
	}
	return c.Policy.validate()
}

// httpsURI refuses v unless it's an absolute https URI with a host and
// no userinfo or fragment.
func httpsURI(name, v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%s %q isn't an absolute https URI without userinfo or fragment", name, v)
	}
	return nil
}

func (d Dependencies) validate() error {
	required := []struct {
		name string
		v    any
	}{
		{"Signer", d.Signer}, {"Instances", d.Instances}, {"InstanceKeys", d.InstanceKeys}, {"Challenges", d.Challenges},
		{"StatusIndices", d.StatusIndices}, {"Random", d.Random},
	}
	for _, r := range required {
		if isNil(r.v) {
			return fmt.Errorf("%s is required", r.name)
		}
	}
	if len(d.Evidence) == 0 {
		return errors.New("Evidence needs at least one EvidenceVerifier: nothing is attested without platform evidence")
	}
	for i, v := range d.Evidence {
		if isNil(v) {
			return fmt.Errorf("the EvidenceVerifier at Evidence[%d] is nil", i)
		}
	}
	return nil
}

// isNil reports whether v is nil, or an interface holding a nil
// pointer, map, slice, func or channel.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// checkSigner checks Signer and Chain as an issuer will check the
// attestations' x5c, and sets p's alg and header.
func (p *Provider) checkSigner() error {
	ders, err := certchain.SignerChainDERs(p.deps.Signer, p.deps.Chain)
	if err != nil {
		return fmt.Errorf("the certificate chain (Chain): %w", err)
	}
	leaf := p.deps.Chain[0]
	if err := certchain.CheckSigningLeaf("the signing certificate (Chain[0])", leaf); err != nil {
		return err
	}
	if slices.ContainsFunc(leaf.ExtKeyUsage, func(u x509.ExtKeyUsage) bool { return u != x509.ExtKeyUsageAny }) {
		return errors.New("the signing certificate (Chain[0]) lists an extended key usage of another role, which an issuer's attester leaf policy refuses")
	}
	if err := certchain.CheckIssuerName(leaf, p.cfg.Identifier); err != nil {
		return fmt.Errorf("the signing certificate (Chain[0]) doesn't name Config.Identifier as a URI subject alternative name: %w", err)
	}
	now := p.now()
	for i, c := range p.deps.Chain {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return fmt.Errorf("the certificate Chain[%d] isn't valid now (%v to %v)", i, c.NotBefore, c.NotAfter)
		}
	}
	if p.alg, err = keyAlg(p.deps.Signer.Public()); err != nil {
		return fmt.Errorf("the signing key (Signer): %w", err)
	}
	x5c := make([]string, len(ders))
	for i, der := range ders {
		x5c[i] = base64.StdEncoding.EncodeToString(der)
	}
	p.header = attestation.Header{X5C: x5c}
	return nil
}

func (p *Provider) now() time.Time {
	if p.deps.Clock == nil {
		return time.Now()
	}
	return p.deps.Clock()
}

// StatusList is the provider's status list: an http.Handler to serve
// at Config.StatusListURI, answering in the JWT form
// (application/statuslist+jwt) by default and the CWT form when the
// request's Accept header asks for it (draft-ietf-oauth-status-list-14
// §8.1), signed with Signer and carrying Chain. Each instance key's
// status is two bits: VALID, INVALID (revoked) or SUSPENDED. The
// provider invalidates its cached token whenever it changes a status.
func (p *Provider) StatusList() *statuslist.Publisher { return p.publisher }

// keyAlg is the JWS algorithm for pub: ES256 for P-256, EdDSA for
// Ed25519.
func keyAlg(pub crypto.PublicKey) (oid4vci.JOSEAlg, error) {
	eddsa, err := certchain.SignerKeyIsEdDSA(pub)
	if err != nil {
		return "", err
	}
	if eddsa {
		return oid4vci.EdDSA, nil
	}
	return oid4vci.ES256, nil
}
