package walletprovider

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/sealing"
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
	DefaultStatusListSize     = 1 << 20
	DefaultStatusListPeriod   = 7 * 24 * time.Hour
	DefaultStatusListLifetime = time.Hour
	DefaultStatusListTTL      = 5 * time.Minute
	// DefaultInstanceKeyRetention is the least Config.InstanceKeyRetention
	// zero means: three StatusListPeriods when they're longer.
	DefaultInstanceKeyRetention = 90 * 24 * time.Hour
	// DefaultMaxInstanceKeysPerPeriod is Config.MaxInstanceKeysPerPeriod's
	// default: room for a wallet issuing or refreshing a credential
	// every hour or two through a week-long period.
	DefaultMaxInstanceKeysPerPeriod = 128
	// DefaultRecentInstanceStatusLists is
	// Config.RecentInstanceStatusLists's default: a quarter of a
	// period's lists.
	DefaultRecentInstanceStatusLists = MaxStatusListsPerPeriod / 4
)

// Upper bounds New enforces on Config's durations.
const (
	// MaxAttestationTTL bounds both attestations' lifetimes: a provider
	// re-issues them while the instance stays active, and an issuer that
	// doesn't check status trusts one until it expires.
	MaxAttestationTTL = 24 * time.Hour

	// MaxChallengeTTL bounds a challenge's lifetime.
	MaxChallengeTTL = 15 * time.Minute

	// MaxStatusListSize bounds Config.StatusListSize: 4 MiB packed
	// (two bits an index), which every Relying Party fetches whole. A
	// list compresses well while few of its statuses are set, but a
	// Relying Party refuses a token larger than its own limit — 1 MiB by
	// default (statuslist.DefaultMaxTokenBytes) — so a list near this
	// size with more than a few percent of its keys suspended or revoked
	// fails every issuer's check: keep StatusListSize to 2^22 or below
	// unless the issuers checking it raise their limit.
	MaxStatusListSize = 1 << 24

	// MaxStatusListPeriod bounds Config.StatusListPeriod.
	MaxStatusListPeriod = 365 * 24 * time.Hour

	// MaxInstanceKeyRetention bounds Config.InstanceKeyRetention.
	MaxInstanceKeyRetention = 10 * 365 * 24 * time.Hour
)

// MaxStatusListsPerPeriod is how many status lists a period has, each
// of Config.StatusListSize indices, filled one after another within
// the two shares Config.RecentInstanceStatusLists divides them into.
const MaxStatusListsPerPeriod = 64

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

	// StatusListBaseURI is where the provider's status lists are: an
	// absolute https URI without query or fragment, not ending in "/".
	// The lists of a period are at StatusListBaseURI/{start}/{n} (the
	// period's start in seconds since the Unix epoch, and n from 0 to
	// MaxStatusListsPerPeriod-1), served by StatusLists, and every
	// attestation's status claim names one. REQUIRED.
	StatusListBaseURI string

	// StatusListPeriod is how long the provider hands out indices of
	// one period's lists. Periods start at multiples of it since the
	// Unix epoch, and every attestation names an index of the current
	// period's lists: an instance key used in a new period gets an index
	// there first. Zero means DefaultStatusListPeriod. It's a whole
	// number of seconds, at least WalletAttestationTTL and
	// KeyAttestationTTL, so an attestation outlives its period by less
	// than another one, and at most MaxStatusListPeriod. Changing it
	// stops serving the lists of the old one at once: attestations
	// naming them fail an issuer's status check until they expire.
	StatusListPeriod time.Duration

	// StatusListSize is how many indices each list has; zero means
	// DefaultStatusListSize. It must be a multiple of 4 (two bits per
	// status, so SUSPENDED fits). At most half of a list is handed out
	// (statuslist.DefaultFillLimit), so a period holds
	// MaxStatusListsPerPeriod × StatusListSize/2 instance keys used in
	// it, and an attestation for one more fails until the next period:
	// size it for the instance keys used in a period. Every issuance
	// uses a new instance key, and a key used again in a later period
	// takes an index there too, so a period needs about the fleet's
	// issuances and refreshes in that period. The default, 2^20, holds
	// 64 × 2^20/2 ≈ 33.5M a period (a week): 5M wallets each issuing or
	// refreshing twice a week use about 10M, which leaves a margin of
	// about three times against many instances filling the lists
	// (MaxInstanceKeysPerPeriod). The keys of recently registered
	// instances have a quarter of that, the RecentInstanceStatusLists
	// share (about 8.4M), less the established instances' keys on it:
	// these take it only while it's no fuller than the rest, so when
	// both kinds of key are used throughout the period, recent ones are
	// refused only once they alone fill it, but established keys used
	// early in a period, recent ones late, take a part of it first.
	// Where r of a period's keys are recent instances', they all fit
	// at worst while the period uses no more than 1/(1+3r) of its
	// capacity: count an Android wallet that registers again when its
	// Remote Key Provisioning certificates expire, every few weeks, as
	// recent, as each new registration is a new instance (about half
	// the capacity, 16.7M at the default, at r = 1/3). A list of 2^20
	// two-bit statuses packs
	// to 256 KiB, so its token stays within a Relying Party's default
	// limit (statuslist.DefaultMaxTokenBytes) whatever its statuses; its
	// store holds a row per index handed out, not per index. It may be
	// raised at any time, the lists of the current period growing with
	// it, but not lowered while a served list holds an index past the
	// new size: that list can't be published until it retires.
	StatusListSize int

	// MaxInstanceKeysPerPeriod bounds the status list indices one
	// instance's instance keys take in a period: one each time a key is
	// recorded (its first Wallet Attestation) and each time a recorded
	// key is first used in the period (moving to its lists). A request
	// that would take one more is refused with ErrTooManyInstanceKeys
	// until the next period, so no one instance can fill a period's
	// lists and leave none for the others. Since each recorded key took
	// one, it also bounds the keys an instance records: at most this
	// many a period, kept for InstanceKeyRetention. Size it for one
	// wallet's issuances and refreshes in a period, with room to spare;
	// a period's lists then take StatusListSize × MaxStatusListsPerPeriod
	// / 2 / MaxInstanceKeysPerPeriod instances at that bound before they
	// fill. It bounds one instance, not someone holding many: each
	// instance costs one piece of registration evidence, and its
	// recorded keys move to each new period's lists without any, so
	// enough instances can fill a period's lists between them.
	// RecentInstanceStatusLists keeps instances registered lately to a
	// share of the lists; size StatusListSize with a margin against
	// older ones, and watch StatusListFill. A
	// recorded key last used in the previous period keeps its index
	// there once the current period's lists are full, taking none of
	// this bound, even once the instance has used it up, so a wallet that moved its keys in the previous period
	// keeps its Wallet Attestations through one full period; new
	// instance keys, and keys whose index is older, are refused until a
	// period's lists have room. Lists filled again period after period
	// refuse established wallets too from the second full period on.
	// Zero means DefaultMaxInstanceKeysPerPeriod.
	MaxInstanceKeysPerPeriod int

	// RecentInstanceStatusLists is how many of a period's
	// MaxStatusListsPerPeriod lists, from the first, the instance keys
	// of an instance registered in the current or previous period
	// (Instance.CreatedAt) take indices from: a quarter of the period's
	// capacity by default. Other instances' keys take indices from any
	// list: from this share with a chance in proportion to its size
	// while it's no fuller than the rest, otherwise from the rest, the
	// share only once they're full. So these lists hold established
	// instances' keys about as densely as the rest do, the recent
	// instances' own keys aren't refused while established ones could
	// have gone elsewhere, and
	// instances registered in a burst, each costing a piece of
	// registration evidence, can fill no more than this share of a
	// period's lists between them, and leave the rest to the wallets
	// registered before. Once the share is full, a Wallet Attestation
	// for a recent instance's new instance key fails until the next
	// period, as one does when every list is full: answered HTTP 500
	// server_error, and logged as the recent instances' share being
	// full; a recorded key on the previous period's lists keeps its
	// index there, as on full lists. Nothing is revoked or forgotten.
	// A burst that filled the share fills it again in the next period,
	// its instances still recent then and their recorded keys moving
	// without evidence, so it refuses new wallets' first keys for two
	// periods, not one.
	// A key on one of the other lists tells an issuer its instance was
	// registered before the previous period. One on this share is a
	// recent or an established instance's: about four times as likely
	// a recent one's as a key across all lists is, as the share is a
	// quarter of the lists, and certainly one once recent instances'
	// keys alone fill it. Zero means
	// DefaultRecentInstanceStatusLists; MaxStatusListsPerPeriod turns
	// the share off, every instance taking indices from every list in
	// turn.
	RecentInstanceStatusLists int

	// StatusListLifetime and StatusListTTL are the served Status List
	// Token's lifetime (exp) and the time a Relying Party may cache it
	// (ttl, Cache-Control): statuslist.Publisher's Lifetime and TTL.
	// Zero means DefaultStatusListLifetime and DefaultStatusListTTL. A
	// revocation reaches issuers within the TTL, plus their own cache
	// bounds.
	StatusListLifetime time.Duration
	StatusListTTL      time.Duration

	// InstanceKeyRetention is how long an instance key's record is kept
	// after the start of the period it was last used in: its
	// InstanceKey.RetainUntil, after which the InstanceKeyStore may
	// delete it. Size it for the longest a wallet may go without using
	// an issuance's instance key and still use it again — the lifetime
	// of the refresh tokens of the issuers the wallet uses, say, since a
	// refresh asks for a Wallet Attestation for the key. Once it's
	// deleted, a Wallet Attestation for the key needs a challenge and
	// evidence again, as a new key's does, and gets a fresh status
	// index, and a Key Attestation naming it is refused with
	// ErrUnknownInstanceKey. Zero means DefaultInstanceKeyRetention, or
	// three StatusListPeriods when they're longer. It's at least three
	// StatusListPeriods — while a list is served, and a period more —
	// and at most MaxInstanceKeyRetention.
	InstanceKeyRetention time.Duration

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

	// OnRecheckRefused, if set, is called each time an
	// EvidenceRechecker refuses an instance, or an InstanceKeyRechecker
	// one of its recorded instance keys, before a Wallet or Key
	// Attestation — or the Policy, as it is now, refuses either, or the
	// instance's evidence Kind has no configured verifier (both
	// ErrPolicy), or an EvidenceVerifier refuses fresh evidence the
	// instance sent (an instance key's or holder key's) as revoked or
	// suspended by its issuer. It's called once per request, with the refusal the
	// request fails with: when both the Policy and the rechecker refuse,
	// that's the rechecker's if it wraps ErrEvidenceRevoked or
	// ErrEvidenceSuspended, and the Policy's otherwise, the rechecker's
	// then going unreported. A revocation or suspension of the instance
	// key the request names wins over the instance's other refusals
	// too. It's called with the refusal and the instance as stored once the
	// provider has acted on it: StateRevoked or StateSuspended when the
	// refusal wraps ErrEvidenceRevoked or ErrEvidenceSuspended (the
	// provider revoked or suspended it, with a Reason naming the
	// recheck), StateActive otherwise (a policy refusal, a root no
	// longer trusted, a certificate past its validity period, or a
	// record too old to judge: the request is refused, the instance and its live
	// attestations left as they are). Use it to alert, or to revoke from
	// your own logic. It's called on the request's path, before the
	// refusal is answered: keep it quick, and hand anything slow to
	// another goroutine. A recheck that couldn't check (a status list
	// that can't be fetched: ErrUnavailable, answered 503), or a
	// refusal the provider couldn't revoke or suspend the instance for
	// (a store failure), fails the request as the provider's own
	// failure without calling it; the next request rechecks.
	OnRecheckRefused func(ctx context.Context, in Instance, err error)

	// RequireSealedStore makes New refuse Instances, InstanceKeys and
	// Challenges stores that don't seal their records at rest
	// (sealing.Store): an instance's record holds its keys, its
	// registration evidence's facts and its App Attest counter, which
	// sealing keeps a database writer from altering unnoticed. sqlstore's
	// stores seal when their DB has an Options.Sealer. Set it in
	// production, where the stores are a shared database; an in-memory
	// store, which nothing else can write, doesn't seal.
	RequireSealedStore bool
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

	// StatusListTokens, if set, shares the status lists' signed tokens
	// between the replicas serving them (statuslist.Publisher.Tokens):
	// one replica signs a list's token at a time and the others serve
	// it, rather than each reading the list's statuses and signing its
	// own. sqlstore's DB.StatusListTokens is one, over the database its
	// StatusIndices are in, whose Delete of a retired list (from
	// Provider.SweepStatusLists) deletes the list's tokens too. nil
	// means each replica signs its own.
	StatusListTokens statuslist.TokenStore

	// Evidence are the verifiers of the evidence kinds the provider
	// accepts, each Kind once. At least one is REQUIRED.
	Evidence []EvidenceVerifier

	// Clock returns the current time; nil means time.Now.
	Clock func() time.Time

	// Random is the source of challenges and instance IDs, and of the
	// random choice of the lists an established instance's key takes
	// an index on (Config.RecentInstanceStatusLists), which hides
	// recent instances' keys among established ones only while it's
	// unpredictable. Ordinarily crypto/rand.Reader. REQUIRED.
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
	lists     statusLists
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
	if cfg.RequireSealedStore {
		if err := deps.checkSealed(); err != nil {
			return nil, fmt.Errorf("walletprovider: dependencies: %w", err)
		}
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
	p.lists.handler = http.NewServeMux()
	p.lists.handler.HandleFunc("GET /{start}/{n}", p.serveStatusList)
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
	def(&c.StatusListPeriod, DefaultStatusListPeriod)
	def(&c.InstanceKeyRetention, max(DefaultInstanceKeyRetention, 3*c.StatusListPeriod))
	if c.StatusListSize == 0 {
		c.StatusListSize = DefaultStatusListSize
	}
	if c.MaxInstanceKeysPerPeriod == 0 {
		c.MaxInstanceKeysPerPeriod = DefaultMaxInstanceKeysPerPeriod
	}
	if c.RecentInstanceStatusLists == 0 {
		c.RecentInstanceStatusLists = DefaultRecentInstanceStatusLists
	}
	return c
}

func (c Config) validate() error {
	if err := c.validateIdentifiers(); err != nil {
		return err
	}
	if err := c.validateLimits(); err != nil {
		return err
	}
	if err := c.validateStatusListTiming(); err != nil {
		return err
	}
	return c.Policy.validate()
}

// validateIdentifiers refuses c's Identifier, StatusListBaseURI or
// WalletLink unless each is a usable https URI, and its ClientIDs if
// there are none or one is empty.
func (c Config) validateIdentifiers() error {
	if err := httpsURI("Identifier", c.Identifier); err != nil {
		return err
	}
	if err := statusListBaseURI(c.StatusListBaseURI); err != nil {
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
	return nil
}

// validateLimits refuses c's attestation and challenge TTLs, status
// list size, MaxInstanceKeysPerPeriod and RecentInstanceStatusLists
// unless each is within its bounds.
func (c Config) validateLimits() error {
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
	if c.MaxInstanceKeysPerPeriod < 0 {
		return fmt.Errorf("MaxInstanceKeysPerPeriod is %d, not positive", c.MaxInstanceKeysPerPeriod)
	}
	if c.RecentInstanceStatusLists < 0 || c.RecentInstanceStatusLists > MaxStatusListsPerPeriod {
		return fmt.Errorf("RecentInstanceStatusLists is %d, not between 1 and MaxStatusListsPerPeriod (%d)", c.RecentInstanceStatusLists, MaxStatusListsPerPeriod)
	}
	return nil
}

// validateStatusListTiming refuses c's StatusListPeriod,
// InstanceKeyRetention and StatusListTTL unless each is within its
// bounds, which depend on the attestation TTLs and on each other.
func (c Config) validateStatusListTiming() error {
	if longest := max(c.WalletAttestationTTL, c.KeyAttestationTTL); c.StatusListPeriod < longest || c.StatusListPeriod > MaxStatusListPeriod {
		return fmt.Errorf("StatusListPeriod is %v, not between the longest attestation TTL (%v) and %v", c.StatusListPeriod, longest, MaxStatusListPeriod)
	}
	if c.StatusListPeriod%time.Second != 0 {
		return fmt.Errorf("StatusListPeriod is %v, not a whole number of seconds", c.StatusListPeriod)
	}
	if least := 3 * c.StatusListPeriod; c.InstanceKeyRetention < least || c.InstanceKeyRetention > MaxInstanceKeyRetention {
		return fmt.Errorf("InstanceKeyRetention is %v, not between three StatusListPeriods (%v) and %v", c.InstanceKeyRetention, least, MaxInstanceKeyRetention)
	}
	if c.StatusListTTL < time.Second || c.StatusListTTL > c.StatusListLifetime {
		return fmt.Errorf("StatusListTTL is %v, not between a second and StatusListLifetime (%v)", c.StatusListTTL, c.StatusListLifetime)
	}
	return nil
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

// statusListBaseURI refuses v unless it's an absolute https URI that
// lists can be under: no userinfo, query or fragment, and no trailing
// "/".
func statusListBaseURI(v string) error {
	if err := httpsURI("StatusListBaseURI", v); err != nil {
		return err
	}
	if u, _ := url.Parse(v); u.RawQuery != "" || u.ForceQuery || strings.HasSuffix(v, "/") {
		return fmt.Errorf("StatusListBaseURI %q has a query or ends in \"/\"", v)
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

// checkSealed refuses stores that don't seal their records
// (Config.RequireSealedStore).
func (d Dependencies) checkSealed() error {
	for _, s := range []struct {
		name  string
		store any
	}{{"Instances", d.Instances}, {"InstanceKeys", d.InstanceKeys}, {"Challenges", d.Challenges}} {
		if sealed, ok := s.store.(sealing.Store); !ok || !sealed.SealsRecords() {
			return fmt.Errorf("RequireSealedStore is set, and %s doesn't seal its records (sealing.Store: sqlstore's stores do with an Options.Sealer)", s.name)
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
