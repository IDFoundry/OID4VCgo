package issuer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
)

// AssuranceLevel gates how strict New's validation of Config and
// Dependencies is — the same mechanism FAPIgo's own server.New/client.New
// use (fapigo/server.AssuranceLevel), mirrored here since this package
// has its own store dependencies FAPIgo's own assurance gate never sees.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development only — most importantly, it does not require any
	// configured store to declare StoreAssurance capabilities.
	AssuranceDevelopment

	// AssuranceProduction rejects a configuration whose configured
	// stores or key sources don't declare themselves adequate: every
	// store Dependencies actually needs (Nonces, CredentialOffers,
	// DeferredTransactions, Notifications, PreAuthorizedCodes,
	// DPoPReplay, DPoPNonces — each checked only when its own feature
	// is enabled, matching New's own existing conditional-required
	// pattern) must implement StoreAssurance and assert at least
	// Durable, plus AtomicConsume for whichever of those expose a
	// Consume/UseOnce-style operation (Nonces, PreAuthorizedCodes,
	// DPoPReplay), or an Update and Invalidate that must each happen at
	// most once (DeferredTransactions) — CredentialOffers/Notifications
	// are plain store/get operations, and DPoPNonces a plain lookup,
	// with nothing to assert atomicity for). Where this issuer verifies
	// the Token Request's DPoP proof itself (PreAuthorizedCodes set,
	// PreAuthorizedCodeClientAuthentication not VerifiedPreAuthorizedCode),
	// DPoPNonces is required, as a store or the explicit NoDPoPNonces{}
	// decline, Limits.MaxDPoPProofAge must be at most
	// MaxProductionDPoPProofAge, and a store's Limits.DPoPNonceLifetime
	// must be at most 15 minutes; DPoPReplay is checked only there, since
	// otherwise the Authorization Server keeps the replay records.
	// Without a Nonce Endpoint, Limits.MaxProofAge must be at most
	// MaxProductionProofAge; with one, Limits.NonceLifetime at most an
	// hour. A store that doesn't implement
	// StoreAssurance at all is rejected rather than assumed adequate —
	// declaring capabilities is not optional under this level. This
	// does not verify any declaration; a store should still be tested
	// against its own documented contract before being trusted with an
	// honest one.
	//
	// The same "declaring capabilities is not optional" stance applies
	// to AttestationVerifier and ProofBindingKeys, whichever is
	// actually configured: each must implement KeySourceAssurance and
	// declare LiveFetchHardened — the same check FAPIgo's own
	// server.AssuranceProduction/client.AssuranceProduction run against
	// a configured ClientKeySource/IssuerKeySource, extended here to
	// this package's own analogous resolvers (a real production Signer
	// carries no equivalent "did I fetch this key over the network"
	// question, so SDJWTSigner.Signer/MdocSigner.Signer aren't gated
	// this way — there's nothing this package could meaningfully ask a
	// bare crypto.Signer to self-declare). An X5CAttestationVerifier or
	// X5CProofBindingKeyResolver must also set Revocation, to
	// certrevocation.NoCheck{} to decline checking certificate
	// revocation, and an X5CAttestationVerifier an IssuerBinding other
	// than AttestationIssuerUnbound, or SingleWalletProvider to declare
	// that its roots certify one Wallet Provider alone.
	//
	// Also requires Dependencies.Audit to be configured — the same
	// requirement FAPIgo's own server.AssuranceProduction places on
	// server.Dependencies.Audit — and Dependencies.Clock to be nil, the
	// system clock, or a Clock declaring ClockAssurance.
	AssuranceProduction
)

// StoreAssurance lets a store declare its own operational guarantees
// so New can refuse an inadequate one under AssuranceProduction — this
// package has no way to inspect a store's actual implementation, only
// what it claims about itself.
type StoreAssurance interface {
	Capabilities() StoreCapabilities
}

// StoreCapabilities describes what a store implementer asserts about
// its operational guarantees.
type StoreCapabilities struct {
	// Durable means state survives a process restart — an in-memory
	// map (e.g. everything in this repo's own storage package) is not
	// durable.
	Durable bool

	// AtomicConsume means a consume-once-style operation (a
	// NonceStore/PreAuthorizedCodeStore's own Consume, a
	// DPoPReplayChecker's own UseOnce) is a single atomic
	// check-and-retire: two concurrent calls for the same key can
	// never both succeed.
	AtomicConsume bool
}

// checkStoreAssurance requires store to implement StoreAssurance and
// to assert Durable (always) and AtomicConsume (when
// requireAtomicConsume is true).
func checkStoreAssurance(name string, store any, requireAtomicConsume bool) error {
	asserter, ok := store.(StoreAssurance)
	if !ok {
		return fmt.Errorf("dependencies.%s must implement issuer.StoreAssurance under AssuranceProduction", name)
	}
	caps := asserter.Capabilities()
	if !caps.Durable {
		return fmt.Errorf("dependencies.%s must declare Durable capability under AssuranceProduction", name)
	}
	if requireAtomicConsume && !caps.AtomicConsume {
		return fmt.Errorf("dependencies.%s must declare AtomicConsume capability under AssuranceProduction", name)
	}
	return nil
}

// KeySourceCapabilities is what an AttestationVerifier or
// ProofBindingKeyResolver implementation self-declares about its own
// safety properties — the same shape and rationale as FAPIgo's own
// keys.KeySourceCapabilities, mirrored here for this package's own two
// analogous resolvers.
type KeySourceCapabilities struct {
	// LiveFetchHardened is true iff every live network fetch this
	// resolver performs (DID resolution, an OCSP/CRL check, a private
	// key-registry lookup, ...) goes through fapihttp's own
	// SSRF/size-limit/redirect protections, or the implementation
	// performs no live fetch at all — X5CAttestationVerifier and
	// X5CProofBindingKeyResolver both declare this unconditionally
	// true, since validating an already-presented x5c chain against an
	// in-memory CertPool never touches the network.
	LiveFetchHardened bool
}

// KeySourceAssurance is the optional interface an AttestationVerifier
// or ProofBindingKeyResolver implementation can declare its own
// KeySourceCapabilities through. There is no default: an
// implementation that doesn't implement this interface at all is
// rejected under AssuranceProduction, the same "declaring capabilities
// is not optional" stance StoreAssurance takes.
type KeySourceAssurance interface {
	Capabilities() KeySourceCapabilities
}

// checkKeySourceAssurance requires source to implement
// KeySourceAssurance and declare LiveFetchHardened.
func checkKeySourceAssurance(name string, source any) error {
	asserter, ok := source.(KeySourceAssurance)
	if !ok {
		return fmt.Errorf("dependencies.%s must implement issuer.KeySourceAssurance under AssuranceProduction", name)
	}
	if !asserter.Capabilities().LiveFetchHardened {
		return fmt.Errorf("dependencies.%s must declare LiveFetchHardened capability under AssuranceProduction", name)
	}
	return nil
}

// checkProductionAttestationProofType refuses the attestation proof
// type unless Config.AllowAttestationProofType takes it, and then
// without a Nonce Endpoint: without a c_nonce, such a proof has no
// freshness. Even with one it isn't bound to this issuer, since anyone
// can fetch a c_nonce (see AllowAttestationProofType).
func checkProductionAttestationProofType(cfg Config) error {
	for _, id := range slices.Sorted(maps.Keys(cfg.CredentialConfigurationsSupported)) {
		if _, ok := cfg.CredentialConfigurationsSupported[id].ProofTypesSupported[oid4vci.ProofTypeAttestation]; !ok {
			continue
		}
		switch {
		case !cfg.AllowAttestationProofType:
			return fmt.Errorf("credential_configurations_supported[%q]: the %q proof type names no audience, so another issuer can relay a Wallet's key attestation here; under AssuranceProduction take jwt proofs with a key_attestation header instead (haip.RecommendedJWTKeyAttestationProofType), or set config.allow_attestation_proof_type", id, oid4vci.ProofTypeAttestation)
		case cfg.Endpoints.Nonce.IsZero():
			return fmt.Errorf("credential_configurations_supported[%q]: the %q proof type requires endpoints.nonce under AssuranceProduction (without a c_nonce an attestation-type proof has no freshness)", id, oid4vci.ProofTypeAttestation)
		}
	}
	return nil
}

// checkProductionAssurance runs checkStoreAssurance/checkKeySourceAssurance
// against every store or key source New's own existing
// conditional-required checks have already confirmed is actually
// configured — called only once cfg.Assurance is known to be
// AssuranceProduction. declinedDPoPNonces is whether
// Dependencies.DPoPNonces was NoDPoPNonces{}, which New has already
// turned into nil. It returns every problem it finds, for New to report
// together. Split out of New purely to keep its own cognitive
// complexity manageable.
func checkProductionAssurance(cfg Config, deps Dependencies, declinedDPoPNonces bool) []error {
	var errs []error
	// Nonces, transaction IDs, notification IDs, Credential Offer
	// references and access tokens all come from it: a predictable
	// source makes them guessable.
	if deps.Random != rand.Reader {
		errs = append(errs, fmt.Errorf("dependencies.random must be crypto/rand.Reader under AssuranceProduction"))
	}
	if !readsSystemTime(deps.Clock) {
		errs = append(errs, fmt.Errorf("dependencies.clock must be nil, the system clock, or declare issuer.ClockAssurance under AssuranceProduction"))
	}
	if deps.PreAuthorizedCodes != nil && cfg.PreAuthorizedCodeClientAuthentication == nil {
		errs = append(errs, fmt.Errorf("config.pre_authorized_code_client_authentication is required under AssuranceProduction when dependencies.pre_authorized_codes is set (issuer.AnonymousPreAuthorizedCode{} accepts the redemption without client authentication, which HAIP 1.0 §4.4.1 doesn't allow)"))
	}
	if deps.PreAuthorizedCodes != nil && cfg.Limits.MaxTxCodeAttempts > MaxProductionTxCodeAttempts {
		errs = append(errs, fmt.Errorf("config: limits.max_tx_code_attempts is %d; under AssuranceProduction it must be at most %d", cfg.Limits.MaxTxCodeAttempts, MaxProductionTxCodeAttempts))
	}
	if deps.Audit == nil {
		errs = append(errs, fmt.Errorf("dependencies.audit is required under AssuranceProduction"))
	}
	errs = append(errs,
		checkProductionHTTPS(cfg),
		checkProductionAttestationProofType(cfg),
		checkProductionProofFreshness(cfg),
		checkProductionDPoPProof(cfg, deps),
		checkProductionDPoPNonces(cfg, deps, declinedDPoPNonces),
		checkProductionX5CRevocation(deps),
		checkProductionAttestationBinding(deps),
	)
	errs = append(errs, checkProductionKeySources(cfg, deps)...)
	return append(errs, checkProductionStores(cfg, deps)...)
}

// checkProductionStores runs checkStoreAssurance on each store a
// configured feature uses.
func checkProductionStores(cfg Config, deps Dependencies) []error {
	// Each store a configured feature uses, and whether consuming from
	// it must be atomic.
	stores := []struct {
		used          bool
		name          string
		store         any
		atomicConsume bool
	}{
		{!cfg.Endpoints.Nonce.IsZero(), "nonces", deps.Nonces, true},
		{!cfg.CredentialOfferEndpoint.IsZero(), "credential_offers", deps.CredentialOffers, false},
		{!cfg.Endpoints.DeferredCredential.IsZero(), "deferred_transactions", deps.DeferredTransactions, true},
		{!cfg.Endpoints.Notification.IsZero(), "notifications", deps.Notifications, false},
		{deps.PreAuthorizedCodes != nil, "pre_authorized_codes", deps.PreAuthorizedCodes, true},
		// Under VerifiedPreAuthorizedCode the Authorization Server
		// verifies the DPoP proof and keeps its replay records.
		{verifiesDPoPProofs(cfg, deps), "dpop_replay", deps.DPoPReplay, true},
		{deps.DPoPNonces != nil, "dpop_nonces", deps.DPoPNonces, false},
	}
	var errs []error
	for _, st := range stores {
		if st.used {
			errs = append(errs, checkStoreAssurance(st.name, st.store, st.atomicConsume))
		}
	}
	return errs
}

// checkProductionKeySources runs checkKeySourceAssurance on the
// configured AttestationVerifier and ProofBindingKeys, and requires a
// key attestation status decision with the former.
func checkProductionKeySources(cfg Config, deps Dependencies) []error {
	var errs []error
	if deps.AttestationVerifier != nil {
		errs = append(errs, checkKeySourceAssurance("attestation_verifier", deps.AttestationVerifier))
		if deps.AttestationStatus == nil && !cfg.NoAttestationStatusCheck {
			errs = append(errs, fmt.Errorf("dependencies.attestation_status is required under AssuranceProduction when dependencies.attestation_verifier is set, unless config.no_attestation_status_check: without it, a revoked key attestation is accepted until it expires"))
		}
	}
	if deps.ProofBindingKeys != nil {
		errs = append(errs, checkKeySourceAssurance("proof_binding_keys", deps.ProofBindingKeys))
	}
	return errs
}

// Production bounds on the skew this issuer allows a DPoP proof's iat
// into the future: FAPI 2.0 has an authorization server accept a JWT up
// to 10 seconds in the future and refuse one more than 60, the bounds
// fapigo/server enforces under its own production assurance.
const (
	minProductionDPoPClockSkew = 10 * time.Second
	maxProductionDPoPClockSkew = 60 * time.Second
)

// maxProductionNonceLifetime is the longest Limits.NonceLifetime
// AssuranceProduction takes: a c_nonce is a proof's only freshness, so
// one valid much longer lets a Wallet's proofs be made well before
// they're sent.
const maxProductionNonceLifetime = time.Hour

// MaxProductionProofAge is the longest Limits.MaxProofAge
// AssuranceProduction takes when there is no Nonce Endpoint: a jwt
// proof's iat is then its only freshness, and nothing records that a
// proof was used, so one captured proof is good for another Credential
// bound to the Wallet's key until it ages out (OpenID4VCI 1.0 §13.8).
// A Nonce Endpoint (Endpoints.Nonce), which HAIP 1.0 §4.1 requires,
// makes each proof single-use instead.
const MaxProductionProofAge = 5 * time.Minute

// MaxProductionDPoPProofAge is the longest Limits.MaxDPoPProofAge
// AssuranceProduction takes where this issuer verifies the Token
// Request's DPoP proof itself, the bound fapigo/server enforces on its
// own: a proof is fresh (RFC 9449 §11.1) only while it's young.
const MaxProductionDPoPProofAge = 5 * time.Minute

// checkProductionProofFreshness bounds how long a key proof stays
// usable: a c_nonce's lifetime with a Nonce Endpoint, and the proof's
// own age without one.
func checkProductionProofFreshness(cfg Config) error {
	if !cfg.Endpoints.Nonce.IsZero() {
		if cfg.Limits.NonceLifetime > maxProductionNonceLifetime {
			return fmt.Errorf("config: limits.nonce_lifetime is %s; under AssuranceProduction it must be at most %s", cfg.Limits.NonceLifetime, maxProductionNonceLifetime)
		}
		return nil
	}
	if cfg.Limits.MaxProofAge > MaxProductionProofAge {
		return fmt.Errorf("config: limits.max_proof_age is %s; without endpoints.nonce, under AssuranceProduction it must be at most %s (a proof's iat is then its only freshness: set endpoints.nonce, as HAIP 1.0 §4.1 requires, to make each proof single-use)", cfg.Limits.MaxProofAge, MaxProductionProofAge)
	}
	return nil
}

// verifiesDPoPProofs reports whether this issuer verifies the Token
// Request's DPoP proof itself: it redeems pre-authorized codes
// (Dependencies.PreAuthorizedCodes), and the Authorization Server
// hasn't verified the redemption (VerifiedPreAuthorizedCode).
func verifiesDPoPProofs(cfg Config, deps Dependencies) bool {
	if deps.PreAuthorizedCodes == nil {
		return false
	}
	_, verified := cfg.PreAuthorizedCodeClientAuthentication.(VerifiedPreAuthorizedCode)
	return !verified
}

// maxProductionDPoPNonceLifetime is the longest Limits.DPoPNonceLifetime
// AssuranceProduction takes, the bound fapigo/server enforces on its
// own: a nonce is a DPoP proof's freshness, valid for any number of
// proofs until it expires.
const maxProductionDPoPNonceLifetime = 15 * time.Minute

// errProductionDPoPNoncesRequired is AssuranceProduction's refusal of a
// nil Dependencies.DPoPNonces where this issuer verifies the Token
// Request's DPoP proof itself.
var errProductionDPoPNoncesRequired = errors.New("dependencies.dpop_nonces is required under AssuranceProduction when dependencies.pre_authorized_codes is set and this issuer verifies the token request's DPoP proof (pass a durable issuer.DPoPNonceStore, with limits.dpop_nonce_lifetime, to challenge DPoP proofs for a nonce, or issuer.NoDPoPNonces{} to explicitly decline)")

// checkProductionDPoPNonces requires a DPoP nonce choice where this
// issuer verifies the Token Request's DPoP proof itself
// (verifiesDPoPProofs). A configured store's lifetime is bounded
// wherever it is used.
func checkProductionDPoPNonces(cfg Config, deps Dependencies, declined bool) error {
	if deps.DPoPNonces != nil && cfg.Limits.DPoPNonceLifetime > maxProductionDPoPNonceLifetime {
		return fmt.Errorf("config: limits.dpop_nonce_lifetime is %s; under AssuranceProduction it must be at most %s", cfg.Limits.DPoPNonceLifetime, maxProductionDPoPNonceLifetime)
	}
	if deps.DPoPNonces != nil || declined || !verifiesDPoPProofs(cfg, deps) {
		return nil
	}
	return errProductionDPoPNoncesRequired
}

// checkProductionDPoPProof holds Limits.MaxDPoPClockSkew to FAPI 2.0's
// bounds, and Limits.MaxDPoPProofAge to MaxProductionDPoPProofAge,
// where this issuer verifies the Token Request's DPoP proof itself
// (verifiesDPoPProofs).
func checkProductionDPoPProof(cfg Config, deps Dependencies) error {
	if !verifiesDPoPProofs(cfg, deps) {
		return nil
	}
	if skew := cfg.Limits.MaxDPoPClockSkew; skew < minProductionDPoPClockSkew || skew > maxProductionDPoPClockSkew {
		return fmt.Errorf("config: limits.max_dpop_clock_skew is %s; under AssuranceProduction it must be from %s to %s (FAPI 2.0)", skew, minProductionDPoPClockSkew, maxProductionDPoPClockSkew)
	}
	if age := cfg.Limits.MaxDPoPProofAge; age > MaxProductionDPoPProofAge {
		return fmt.Errorf("config: limits.max_dpop_proof_age is %s; under AssuranceProduction it must be at most %s (RFC 9449 §11.1)", age, MaxProductionDPoPProofAge)
	}
	return nil
}

// checkProductionHTTPS refuses, under AssuranceProduction, a published
// URL that isn't https: the identifier, every endpoint, the Credential
// Offer base and the Authorization Servers. fapi.URL admits http only
// for loopback development (fapi.AllowLoopbackHTTP).
func checkProductionHTTPS(cfg Config) error {
	urls := []struct {
		name string
		u    fapi.URL
	}{
		{"issuer", cfg.Issuer},
		{"endpoints.credential", cfg.Endpoints.Credential},
		{"endpoints.nonce", cfg.Endpoints.Nonce},
		{"endpoints.deferred_credential", cfg.Endpoints.DeferredCredential},
		{"endpoints.notification", cfg.Endpoints.Notification},
		{"credential_offer_endpoint", cfg.CredentialOfferEndpoint},
	}
	for i, as := range cfg.AuthorizationServers {
		urls = append(urls, struct {
			name string
			u    fapi.URL
		}{fmt.Sprintf("authorization_servers[%d]", i), as})
	}
	for _, x := range urls {
		if !x.u.IsZero() && x.u.URL().Scheme != "https" {
			return fmt.Errorf("config.%s must be https under AssuranceProduction", x.name)
		}
	}
	return nil
}
