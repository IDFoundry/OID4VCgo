package issuer_test

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The assured* wrapper types below each pair one of the store
// interfaces New actually calls checkStoreAssurance against with a
// declared issuer.StoreCapabilities, for testing that logic without
// needing a real durable backend — the wrapped interface's own methods
// are promoted by embedding, so e.g. assuredNonceStore{store, caps}
// implements issuer.NonceStore (whatever store itself does) plus
// issuer.StoreAssurance.

type assuredNonceStore struct {
	issuer.NonceStore
	caps issuer.StoreCapabilities
}

func (a assuredNonceStore) Capabilities() issuer.StoreCapabilities { return a.caps }

type assuredCredentialOfferStore struct {
	issuer.CredentialOfferStore
	caps issuer.StoreCapabilities
}

func (a assuredCredentialOfferStore) Capabilities() issuer.StoreCapabilities { return a.caps }

type assuredDeferredTransactionStore struct {
	issuer.DeferredTransactionStore
	caps issuer.StoreCapabilities
}

func (a assuredDeferredTransactionStore) Capabilities() issuer.StoreCapabilities { return a.caps }

type assuredNotificationStore struct {
	issuer.NotificationStore
	caps issuer.StoreCapabilities
}

func (a assuredNotificationStore) Capabilities() issuer.StoreCapabilities { return a.caps }

type assuredPreAuthorizedCodeStore struct {
	issuer.PreAuthorizedCodeStore
	caps issuer.StoreCapabilities
}

func (a assuredPreAuthorizedCodeStore) Capabilities() issuer.StoreCapabilities { return a.caps }

// Each assured* store also declares it seals its records
// (sealing.Store), as a production store holding holders' data must;
// unsealed wraps one to declare it doesn't.
func (assuredNonceStore) SealsRecords() bool               { return true }
func (assuredCredentialOfferStore) SealsRecords() bool     { return true }
func (assuredDeferredTransactionStore) SealsRecords() bool { return true }
func (assuredNotificationStore) SealsRecords() bool        { return true }
func (assuredPreAuthorizedCodeStore) SealsRecords() bool   { return true }

type (
	unsealedNonceStore               struct{ assuredNonceStore }
	unsealedCredentialOfferStore     struct{ assuredCredentialOfferStore }
	unsealedDeferredTransactionStore struct{ assuredDeferredTransactionStore }
	unsealedNotificationStore        struct{ assuredNotificationStore }
	unsealedPreAuthorizedCodeStore   struct{ assuredPreAuthorizedCodeStore }
)

func (unsealedNonceStore) SealsRecords() bool               { return false }
func (unsealedCredentialOfferStore) SealsRecords() bool     { return false }
func (unsealedDeferredTransactionStore) SealsRecords() bool { return false }
func (unsealedNotificationStore) SealsRecords() bool        { return false }
func (unsealedPreAuthorizedCodeStore) SealsRecords() bool   { return false }

// assuredAttestationVerifier mirrors the assured* store wrappers
// above, but for AttestationVerifier — pairing
// fixedAttestationVerifier (already defined in
// credential_endpoint_test.go) with a declared
// issuer.KeySourceCapabilities. ProofBindingKeys has no equivalent
// wrapper: its own positive-path test uses
// issuer.X5CProofBindingKeyResolver directly, which already declares
// Capabilities itself.

type assuredAttestationVerifier struct {
	issuer.AttestationVerifier
	caps issuer.KeySourceCapabilities
}

func (a assuredAttestationVerifier) Capabilities() issuer.KeySourceCapabilities { return a.caps }

// productionAssuredConfigAndDeps returns validConfig/validDependencies
// with every store AssuranceProduction already requires
// (Nonces/CredentialOffers/DeferredTransactions/Notifications) and
// Audit declared adequate, plus an "attestation" proof type entry
// added to the SD-JWT VC credential configuration — the fixture the
// key-source assurance tests below build on, so a failure in any of
// them is attributable specifically to AttestationVerifier/
// ProofBindingKeys, not an unrelated store/audit check. It sets
// AllowAttestationProofType, which production requires for that entry.
func productionAssuredConfigAndDeps(t *testing.T) (issuer.Config, issuer.Dependencies) {
	t.Helper()
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	cfg.AllowAttestationProofType = true
	sdjwtConfig := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	sdjwtConfig.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
		oid4vci.ProofTypeJWT:         {ProofSigningAlgValuesSupported: []string{"ES256"}},
		oid4vci.ProofTypeAttestation: {ProofSigningAlgValuesSupported: []string{"ES256"}},
	}
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = sdjwtConfig

	deps := validDependencies(t)
	deps.Nonces = assuredNonceStore{newFakeNonceStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.CredentialOffers = assuredCredentialOfferStore{newFakeCredentialOfferStore(), issuer.StoreCapabilities{Durable: true}}
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}
	deps.Audit = newFakeAuditSink()
	return cfg, deps
}

// TestNewRejectsInadequateKeySourcesUnderProduction proves
// AttestationVerifier/ProofBindingKeys are held to the same
// "declaring capabilities is not optional" standard as every store —
// a plain fake implementing neither is rejected under
// AssuranceProduction even once every store/audit check already
// passes.
func TestNewRejectsInadequateKeySourcesUnderProduction(t *testing.T) {
	t.Run("attestation_verifier", func(t *testing.T) {
		cfg, deps := productionAssuredConfigAndDeps(t)
		deps.AttestationVerifier = fixedAttestationVerifier{}
		if _, err := issuer.New(cfg, deps); err == nil {
			t.Fatal("New = nil error, want error (attestation_verifier declares no KeySourceAssurance)")
		}
	})
	t.Run("proof_binding_keys", func(t *testing.T) {
		cfg, deps := productionAssuredConfigAndDeps(t)
		deps.AttestationVerifier = assuredAttestationVerifier{
			fixedAttestationVerifier{}, issuer.KeySourceCapabilities{LiveFetchHardened: true},
		}
		deps.ProofBindingKeys = fixedProofBindingKeyResolver{}
		if _, err := issuer.New(cfg, deps); err == nil {
			t.Fatal("New = nil error, want error (proof_binding_keys declares no KeySourceAssurance)")
		}
	})
}

// TestNewAcceptsAdequateKeySourcesUnderProduction is
// TestNewRejectsInadequateKeySourcesUnderProduction's positive
// counterpart: once AttestationVerifier and ProofBindingKeys both
// declare LiveFetchHardened, New accepts the same configuration under
// AssuranceProduction. Also covers X5CAttestationVerifier/
// X5CProofBindingKeyResolver's own Capabilities declarations directly,
// proving this repo's own reference implementations — not just a test
// fake — satisfy KeySourceAssurance.
func TestNewAcceptsAdequateKeySourcesUnderProduction(t *testing.T) {
	cfg, deps := productionAssuredConfigAndDeps(t)
	deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}, SingleWalletProvider: true}
	deps.ProofBindingKeys = issuer.X5CProofBindingKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}
	cfg.NoAttestationStatusCheck = true

	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidAssurance(t *testing.T) {
	cases := map[string]issuer.AssuranceLevel{
		"zero value":   0,
		"out-of-range": issuer.AssuranceProduction + 1,
	}
	for name, level := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = level
			if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
				t.Fatalf("New(assurance=%v) = nil error, want error", level)
			}
		})
	}
}

// TestNewRejectsInadequateStoresUnderProduction proves the exact
// stores validConfig/validDependencies wire in (each backed by a plain
// fake with no StoreAssurance declaration) — already accepted under
// AssuranceDevelopment by TestNewAcceptsValidConfig — are rejected the
// moment the same configuration asks for AssuranceProduction instead.
func TestNewRejectsInadequateStoresUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
		t.Fatal("New = nil error, want error (no configured store declares StoreAssurance)")
	}
}

// TestNewAcceptsAdequateStoresUnderProduction is
// TestNewRejectsInadequateStoresUnderProduction's positive
// counterpart: once every store validConfig's own enabled endpoints
// require (nonces, credential_offers, deferred_transactions,
// notifications) declares adequate capabilities, New accepts the same
// configuration under AssuranceProduction.
func TestNewAcceptsAdequateStoresUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	deps := validDependencies(t)
	deps.Nonces = assuredNonceStore{newFakeNonceStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.CredentialOffers = assuredCredentialOfferStore{newFakeCredentialOfferStore(), issuer.StoreCapabilities{Durable: true}}
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}
	deps.Audit = newFakeAuditSink()

	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// TestNewRejectsMissingAuditUnderProduction proves the Audit-specific
// half of AssuranceProduction actually runs: a configuration whose
// every store declares adequate capabilities is still rejected if
// Dependencies.Audit is nil.
func TestNewRejectsMissingAuditUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	deps := validDependencies(t)
	deps.Nonces = assuredNonceStore{newFakeNonceStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.CredentialOffers = assuredCredentialOfferStore{newFakeCredentialOfferStore(), issuer.StoreCapabilities{Durable: true}}
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}
	// deps.Audit deliberately left nil.

	if _, err := issuer.New(cfg, deps); err == nil {
		t.Fatal("New = nil error, want error (dependencies.audit is nil under AssuranceProduction)")
	}
}

// TestNewRejectsMissingAtomicConsumeUnderProduction proves the
// AtomicConsume-specific half of checkStoreAssurance actually runs: a
// store that declares Durable but not AtomicConsume is still rejected
// for a store New calls Consume on (Nonces), even though the same
// declaration would be enough for a plain store/get one
// (CredentialOffers).
func TestNewRejectsMissingAtomicConsumeUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	deps := validDependencies(t)
	deps.Nonces = assuredNonceStore{newFakeNonceStore(), issuer.StoreCapabilities{Durable: true}} // AtomicConsume missing
	deps.CredentialOffers = assuredCredentialOfferStore{newFakeCredentialOfferStore(), issuer.StoreCapabilities{Durable: true}}
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}

	if _, err := issuer.New(cfg, deps); err == nil {
		t.Fatal("New = nil error, want error (nonces declares Durable but not AtomicConsume)")
	}
}

// TestNewRejectsPreAuthorizedCodeStoresUnderProduction covers the
// pre-authorized_code flow's own conditionally-required store
// (PreAuthorizedCodes, gated on it being set at all) — a configuration
// validConfig/validDependencies never wires in by default, so this
// builds its own minimal one.
func TestNewRejectsPreAuthorizedCodeStoresUnderProduction(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	deps.PreAuthorizedCodes = newFakePreAuthorizedCodeStore()

	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "pre_authorized_codes") {
		t.Fatalf("New = %v, want error (pre_authorized_codes declares no StoreAssurance)", err)
	}
}

// TestNewProductionRefusesAttestationProofType: a key attestation names
// no audience, so a production issuer takes the attestation proof type
// only with AllowAttestationProofType.
func TestNewProductionRefusesAttestationProofType(t *testing.T) {
	cfg, deps := productionIssuer(t)
	cfg.AllowAttestationProofType = false
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "allow_attestation_proof_type") {
		t.Fatalf("New without AllowAttestationProofType = %v, want the attestation proof type refused", err)
	}
	cfg.AllowAttestationProofType = true
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with AllowAttestationProofType: %v", err)
	}
	cfg.AllowAttestationProofType = false
	sdjwtConfig := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	delete(sdjwtConfig.ProofTypesSupported, oid4vci.ProofTypeAttestation)
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = sdjwtConfig
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with jwt proofs only: %v", err)
	}
}

// TestNewProductionBoundsNonceLifetime: a c_nonce is a proof's only
// freshness, so a production issuer keeps one at most an hour.
func TestNewProductionBoundsNonceLifetime(t *testing.T) {
	cfg, deps := productionIssuer(t)
	cfg.Limits.NonceLifetime = time.Hour
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with an hour's nonce lifetime: %v", err)
	}
	cfg.Limits.NonceLifetime = 365 * 24 * time.Hour
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "nonce_lifetime") {
		t.Fatalf("New with a year's nonce lifetime = %v, want it refused", err)
	}
}

// TestNewRequiresNonceEndpointForAttestationProofsUnderProduction: an
// attestation-type proof's only freshness is its c_nonce, so a
// production issuer supporting it must run a Nonce Endpoint.
func TestNewRequiresNonceEndpointForAttestationProofsUnderProduction(t *testing.T) {
	cfg, deps := productionAssuredConfigAndDeps(t)
	cfg.NoAttestationStatusCheck = true
	deps.AttestationVerifier = assuredAttestationVerifier{
		fixedAttestationVerifier{}, issuer.KeySourceCapabilities{LiveFetchHardened: true},
	}
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with a Nonce Endpoint: %v", err)
	}

	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.MaxProofAge = time.Minute // what a Nonce-Endpoint-less issuer needs for jwt proofs
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "proof type requires endpoints.nonce") {
		t.Fatalf("New without a Nonce Endpoint = %v, want the attestation proof type refused", err)
	}

	cfg.Assurance = issuer.AssuranceDevelopment
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New under AssuranceDevelopment without a Nonce Endpoint: %v", err)
	}
}

// TestNewRequiresPreAuthorizedCodeClientAuthenticationUnderProduction:
// with every pre-authorized_code store assured, a production issuer
// still has to opt into anonymous redemption explicitly — it departs
// from HAIP 1.0 §4.4.1.
func TestNewRequiresPreAuthorizedCodeClientAuthenticationUnderProduction(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	cfg.PreAuthorizedCodeClientAuthentication = nil
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "issuer.VerifiedPreAuthorizedCode{}") {
		t.Fatalf("New = %v, want an error naming issuer.VerifiedPreAuthorizedCode{} (no explicit pre-authorized_code client authentication choice)", err)
	}

	cfg.PreAuthorizedCodeClientAuthentication = issuer.AnonymousPreAuthorizedCode{}
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with AnonymousPreAuthorizedCode{}: %v", err)
	}

	cfg.Assurance = issuer.AssuranceDevelopment
	cfg.PreAuthorizedCodeClientAuthentication = nil
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New under AssuranceDevelopment without a choice: %v", err)
	}
}

// TestNewCapsTxCodeAttemptsUnderProduction: a production issuer
// tolerates at most MaxProductionTxCodeAttempts wrong Transaction Codes
// per pre-authorized code, so a six-digit code stays hard to guess;
// development assurance takes any positive number.
func TestNewCapsTxCodeAttemptsUnderProduction(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	cfg.Limits.MaxTxCodeAttempts = issuer.MaxProductionTxCodeAttempts
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with max_tx_code_attempts %d: %v", cfg.Limits.MaxTxCodeAttempts, err)
	}
	cfg.Limits.MaxTxCodeAttempts = issuer.MaxProductionTxCodeAttempts + 1
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "max_tx_code_attempts") {
		t.Fatalf("New with max_tx_code_attempts %d = %v, want it refused", cfg.Limits.MaxTxCodeAttempts, err)
	}
	cfg.Assurance = issuer.AssuranceDevelopment
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New under AssuranceDevelopment: %v", err)
	}
}

// preAuthorizedCodeProductionConfig is a production configuration with
// every store assured and the pre-authorized_code flow wired in, its
// client authentication choice made.
func preAuthorizedCodeProductionConfig(t *testing.T) (issuer.Config, issuer.Dependencies) {
	t.Helper()
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	cfg.Limits.AccessTokenLifetime = time.Hour
	cfg.Limits.MaxTxCodeAttempts = 3
	cfg.PreAuthorizedCodeClientAuthentication = issuer.AnonymousPreAuthorizedCode{}
	deps := validDependencies(t)
	deps.Nonces = assuredNonceStore{newFakeNonceStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.CredentialOffers = assuredCredentialOfferStore{newFakeCredentialOfferStore(), issuer.StoreCapabilities{Durable: true}}
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}
	deps.PreAuthorizedCodes = assuredPreAuthorizedCodeStore{newFakePreAuthorizedCodeStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.AccessTokens = &fakeAccessTokenIssuer{}
	deps.Audit = newFakeAuditSink()
	return cfg, deps
}

// productionIssuer is a production configuration New accepts, as
// productionAssuredConfigAndDeps with the key attestation verifier its
// attestation proof type needs.
func productionIssuer(t *testing.T) (issuer.Config, issuer.Dependencies) {
	t.Helper()
	cfg, deps := productionAssuredConfigAndDeps(t)
	deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}, SingleWalletProvider: true}
	cfg.NoAttestationStatusCheck = true
	return cfg, deps
}

// TestNewProductionRequiresCryptoRand: nonces, transaction IDs, offer
// references and access tokens come from Dependencies.Random, so a
// production issuer takes only crypto/rand.Reader.
func TestNewProductionRequiresCryptoRand(t *testing.T) {
	cfg, deps := productionIssuer(t)
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with crypto/rand.Reader: %v", err)
	}
	deps.Random = bytes.NewReader(make([]byte, 1<<16))
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "crypto/rand") {
		t.Fatalf("New with a predictable random source = %v, want a crypto/rand error", err)
	}
}

// TestNewProductionRequiresHTTPS: every URL a production issuer
// publishes is https, though fapi.AllowLoopbackHTTP admits http ones
// for development.
func TestNewProductionRequiresHTTPS(t *testing.T) {
	loopback := func(raw string) fapi.URL {
		u, err := fapi.ParseEndpointURL(raw, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	for name, set := range map[string]func(*issuer.Config){
		"credential":            func(c *issuer.Config) { c.Endpoints.Credential = loopback("http://127.0.0.1/credential") },
		"nonce":                 func(c *issuer.Config) { c.Endpoints.Nonce = loopback("http://127.0.0.1/nonce") },
		"authorization_servers": func(c *issuer.Config) { c.AuthorizationServers = []fapi.URL{loopback("http://127.0.0.1/as")} },
	} {
		cfg, deps := productionIssuer(t)
		set(&cfg)
		if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "must be https") {
			t.Errorf("%s: New = %v, want an https error", name, err)
		}
	}
}

// TestNewProductionRequiresAttestationStatus: a production issuer that
// verifies key attestations checks their revocation status, or says
// it deliberately doesn't.
func TestNewProductionRequiresAttestationStatus(t *testing.T) {
	cfg, deps := productionAssuredConfigAndDeps(t)
	deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}, SingleWalletProvider: true}
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "attestation_status") {
		t.Fatalf("New without an attestation status check = %v, want an attestation_status error", err)
	}
	cfg.NoAttestationStatusCheck = true
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Errorf("New with no_attestation_status_check: %v", err)
	}
}

// TestNewProductionRequiresX5CRevocation: a production issuer's
// X5CAttestationVerifier and X5CProofBindingKeyResolver, by value or
// by pointer, say how they check certificate revocation, if only by
// declining with certrevocation.NoCheck{}.
func TestNewProductionRequiresX5CRevocation(t *testing.T) {
	roots := x509.NewCertPool()
	for name, tc := range map[string]struct {
		set  func(deps *issuer.Dependencies, revocation certrevocation.Checker)
		want string
	}{
		"attestation verifier": {func(deps *issuer.Dependencies, revocation certrevocation.Checker) {
			deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: roots, Revocation: revocation, SingleWalletProvider: true}
		}, "X5CAttestationVerifier.Revocation"},
		"attestation verifier, by pointer": {func(deps *issuer.Dependencies, revocation certrevocation.Checker) {
			deps.AttestationVerifier = &issuer.X5CAttestationVerifier{Roots: roots, Revocation: revocation, SingleWalletProvider: true}
		}, "X5CAttestationVerifier.Revocation"},
		"proof binding keys": {func(deps *issuer.Dependencies, revocation certrevocation.Checker) {
			deps.ProofBindingKeys = issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: revocation}
		}, "X5CProofBindingKeyResolver.Revocation"},
		"proof binding keys, by pointer": {func(deps *issuer.Dependencies, revocation certrevocation.Checker) {
			deps.ProofBindingKeys = &issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: revocation}
		}, "X5CProofBindingKeyResolver.Revocation"},
		// A wrapper embedding one keeps its checks.
		"attestation verifier, wrapped": {func(deps *issuer.Dependencies, revocation certrevocation.Checker) {
			deps.AttestationVerifier = meteredAttestationVerifier{issuer.X5CAttestationVerifier{Roots: roots, Revocation: revocation, SingleWalletProvider: true}}
		}, "X5CAttestationVerifier.Revocation"},
		"proof binding keys, wrapped": {func(deps *issuer.Dependencies, revocation certrevocation.Checker) {
			deps.ProofBindingKeys = &meteredProofBindingKeys{issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: revocation}}
		}, "X5CProofBindingKeyResolver.Revocation"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionIssuer(t)
			tc.set(&deps, nil)
			if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "NoCheck") {
				t.Fatalf("New with a nil Revocation = %v, want %s required", err, tc.want)
			}
			tc.set(&deps, certrevocation.NoCheck{})
			if _, err := issuer.New(cfg, deps); err != nil {
				t.Errorf("New with certrevocation.NoCheck{}: %v", err)
			}
			cfg.Assurance = issuer.AssuranceDevelopment
			tc.set(&deps, nil)
			if _, err := issuer.New(cfg, deps); err != nil {
				t.Errorf("New under AssuranceDevelopment with a nil Revocation: %v", err)
			}
		})
	}
}

// meteredAttestationVerifier and meteredProofBindingKeys wrap the X5C
// verifier and resolver, as one counting their calls would.
type meteredAttestationVerifier struct{ issuer.X5CAttestationVerifier }

type meteredProofBindingKeys struct {
	issuer.X5CProofBindingKeyResolver
}

// TestNewProductionChecksWrappedAttestationBinding: an
// X5CAttestationVerifier embedded in a type of the caller's own is
// still held to an explicit IssuerBinding under AssuranceProduction.
func TestNewProductionChecksWrappedAttestationBinding(t *testing.T) {
	cfg, deps := productionAssuredConfigAndDeps(t)
	cfg.NoAttestationStatusCheck = true
	deps.AttestationVerifier = meteredAttestationVerifier{issuer.X5CAttestationVerifier{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}}
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "explicit IssuerBinding") {
		t.Fatalf("New with a wrapped, unbound X5CAttestationVerifier = %v, want an IssuerBinding error", err)
	}
}

// TestNewProductionRequiresSealedStores: under AssuranceProduction, each
// store holding holders' data — pre-authorized codes, Credential Offers,
// deferred transactions, notifications — must declare it seals its
// records (sealing.Store), unless Config.UnsealedStores says the stores
// are as protected as the issuer's keys. A c_nonce store holds nothing
// of the holder's and needn't.
func TestNewProductionRequiresSealedStores(t *testing.T) {
	for name, unseal := range map[string]func(*issuer.Dependencies){
		"pre_authorized_codes": func(d *issuer.Dependencies) {
			d.PreAuthorizedCodes = unsealedPreAuthorizedCodeStore{d.PreAuthorizedCodes.(assuredPreAuthorizedCodeStore)}
		},
		"credential_offers": func(d *issuer.Dependencies) {
			d.CredentialOffers = unsealedCredentialOfferStore{d.CredentialOffers.(assuredCredentialOfferStore)}
		},
		"deferred_transactions": func(d *issuer.Dependencies) {
			d.DeferredTransactions = unsealedDeferredTransactionStore{d.DeferredTransactions.(assuredDeferredTransactionStore)}
		},
		"notifications": func(d *issuer.Dependencies) {
			d.Notifications = unsealedNotificationStore{d.Notifications.(assuredNotificationStore)}
		},
	} {
		cfg, deps := preAuthorizedCodeProductionConfig(t)
		unseal(&deps)
		if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "dependencies."+name+" holds holders' data") {
			t.Errorf("%s unsealed: New = %v, want it refused", name, err)
		}
		cfg.UnsealedStores = true
		if _, err := issuer.New(cfg, deps); err != nil {
			t.Errorf("%s unsealed, with UnsealedStores: %v", name, err)
		}
		cfg.UnsealedStores, cfg.Assurance = false, issuer.AssuranceDevelopment
		if _, err := issuer.New(cfg, deps); err != nil {
			t.Errorf("%s unsealed, under AssuranceDevelopment: %v", name, err)
		}
	}

	cfg, deps := preAuthorizedCodeProductionConfig(t)
	deps.Nonces = unsealedNonceStore{deps.Nonces.(assuredNonceStore)}
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Errorf("an unsealed nonce store: %v", err)
	}
}
