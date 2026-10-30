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
	// decline, and a store's Limits.DPoPNonceLifetime must be at most
	// 15 minutes. A store that doesn't implement
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
	// server.Dependencies.Audit.
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
// turned into nil. Split out of New purely to keep its own cognitive
// complexity manageable.
func checkProductionAssurance(cfg Config, deps Dependencies, declinedDPoPNonces bool) error {
	// Nonces, transaction IDs, notification IDs, Credential Offer
	// references and access tokens all come from it: a predictable
	// source makes them guessable.
	if deps.Random != rand.Reader {
		return fmt.Errorf("dependencies.random must be crypto/rand.Reader under AssuranceProduction")
	}
	if err := checkProductionHTTPS(cfg); err != nil {
		return err
	}
	if err := checkProductionAttestationProofType(cfg); err != nil {
		return err
	}
	if !cfg.Endpoints.Nonce.IsZero() && cfg.Limits.NonceLifetime > maxProductionNonceLifetime {
		return fmt.Errorf("config: limits.nonce_lifetime is %s; under AssuranceProduction it must be at most %s", cfg.Limits.NonceLifetime, maxProductionNonceLifetime)
	}
	if deps.PreAuthorizedCodes != nil && cfg.PreAuthorizedCodeClientAuthentication == nil {
		return fmt.Errorf("config.pre_authorized_code_client_authentication is required under AssuranceProduction when dependencies.pre_authorized_codes is set (issuer.AnonymousPreAuthorizedCode{} accepts the redemption without client authentication, which HAIP 1.0 §4.4.1 doesn't allow)")
	}
	if err := checkProductionDPoPClockSkew(cfg, deps); err != nil {
		return err
	}
	if err := checkProductionDPoPNonces(cfg, deps, declinedDPoPNonces); err != nil {
		return err
	}
	if deps.PreAuthorizedCodes != nil && cfg.Limits.MaxTxCodeAttempts > MaxProductionTxCodeAttempts {
		return fmt.Errorf("config: limits.max_tx_code_attempts is %d; under AssuranceProduction it must be at most %d", cfg.Limits.MaxTxCodeAttempts, MaxProductionTxCodeAttempts)
	}
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
		{deps.PreAuthorizedCodes != nil, "dpop_replay", deps.DPoPReplay, true},
		{deps.DPoPNonces != nil, "dpop_nonces", deps.DPoPNonces, false},
	}
	for _, st := range stores {
		if !st.used {
			continue
		}
		if err := checkStoreAssurance(st.name, st.store, st.atomicConsume); err != nil {
			return err
		}
	}
	if deps.AttestationVerifier != nil {
		if err := checkKeySourceAssurance("attestation_verifier", deps.AttestationVerifier); err != nil {
			return err
		}
		if deps.AttestationStatus == nil && !cfg.NoAttestationStatusCheck {
			return fmt.Errorf("dependencies.attestation_status is required under AssuranceProduction when dependencies.attestation_verifier is set, unless config.no_attestation_status_check: without it, a revoked key attestation is accepted until it expires")
		}
	}
	if deps.ProofBindingKeys != nil {
		if err := checkKeySourceAssurance("proof_binding_keys", deps.ProofBindingKeys); err != nil {
			return err
		}
	}
	if err := checkProductionX5CRevocation(deps); err != nil {
		return err
	}
	if err := checkProductionAttestationBinding(deps); err != nil {
		return err
	}
	if deps.Audit == nil {
		return fmt.Errorf("dependencies.audit is required under AssuranceProduction")
	}
	return nil
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
// issuer verifies the Token Request's DPoP proof itself: with
// dependencies.pre_authorized_codes set, unless the Authorization Server
// verified the redemption (VerifiedPreAuthorizedCode). A configured
// store's lifetime is bounded wherever it is used.
func checkProductionDPoPNonces(cfg Config, deps Dependencies, declined bool) error {
	if deps.DPoPNonces != nil && cfg.Limits.DPoPNonceLifetime > maxProductionDPoPNonceLifetime {
		return fmt.Errorf("config: limits.dpop_nonce_lifetime is %s; under AssuranceProduction it must be at most %s", cfg.Limits.DPoPNonceLifetime, maxProductionDPoPNonceLifetime)
	}
	if deps.PreAuthorizedCodes == nil || deps.DPoPNonces != nil || declined {
		return nil
	}
	if _, ok := cfg.PreAuthorizedCodeClientAuthentication.(VerifiedPreAuthorizedCode); ok {
		return nil
	}
	return errProductionDPoPNoncesRequired
}

// checkProductionDPoPClockSkew holds Limits.MaxDPoPClockSkew to FAPI
// 2.0's bounds where this issuer verifies the token request's DPoP
// proof itself: with dependencies.pre_authorized_codes set, unless the
// Authorization Server verified the redemption (VerifiedPreAuthorizedCode).
func checkProductionDPoPClockSkew(cfg Config, deps Dependencies) error {
	if deps.PreAuthorizedCodes == nil {
		return nil
	}
	if _, ok := cfg.PreAuthorizedCodeClientAuthentication.(VerifiedPreAuthorizedCode); ok {
		return nil
	}
	if skew := cfg.Limits.MaxDPoPClockSkew; skew < minProductionDPoPClockSkew || skew > maxProductionDPoPClockSkew {
		return fmt.Errorf("config: limits.max_dpop_clock_skew is %s; under AssuranceProduction it must be from %s to %s (FAPI 2.0)", skew, minProductionDPoPClockSkew, maxProductionDPoPClockSkew)
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
