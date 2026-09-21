package issuer_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
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

// assuredAttestationVerifier/assuredProofBindingKeyResolver mirror the
// assured* store wrappers above, but for the two key-source resolvers
// checkKeySourceAssurance covers — pairing fixedAttestationVerifier/
// fixedProofBindingKeyResolver (already defined in
// credential_endpoint_test.go) with a declared
// issuer.KeySourceCapabilities.

type assuredAttestationVerifier struct {
	issuer.AttestationVerifier
	caps issuer.KeySourceCapabilities
}

func (a assuredAttestationVerifier) Capabilities() issuer.KeySourceCapabilities { return a.caps }

type assuredProofBindingKeyResolver struct {
	issuer.ProofBindingKeyResolver
	caps issuer.KeySourceCapabilities
}

func (a assuredProofBindingKeyResolver) Capabilities() issuer.KeySourceCapabilities { return a.caps }

// productionAssuredConfigAndDeps returns validConfig/validDependencies
// with every store AssuranceProduction already requires
// (Nonces/CredentialOffers/DeferredTransactions/Notifications) and
// Audit declared adequate, plus an "attestation" proof type entry
// added to the SD-JWT VC credential configuration — the fixture the
// key-source assurance tests below build on, so a failure in any of
// them is attributable specifically to AttestationVerifier/
// ProofBindingKeys, not an unrelated store/audit check.
func productionAssuredConfigAndDeps(t *testing.T) (issuer.Config, issuer.Dependencies) {
	t.Helper()
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	sdjwtConfig := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	sdjwtConfig.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
		oid4vci.ProofTypeJWT:         {ProofSigningAlgValuesSupported: []string{"ES256"}},
		oid4vci.ProofTypeAttestation: {ProofSigningAlgValuesSupported: []string{"ES256"}},
	}
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = sdjwtConfig

	deps := validDependencies(t)
	deps.Nonces = assuredNonceStore{newFakeNonceStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.CredentialOffers = assuredCredentialOfferStore{newFakeCredentialOfferStore(), issuer.StoreCapabilities{Durable: true}}
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true}}
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
	deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: x509.NewCertPool()}
	deps.ProofBindingKeys = issuer.X5CProofBindingKeyResolver{Roots: x509.NewCertPool()}

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
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true}}
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
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true}}
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
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true}}
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}

	if _, err := issuer.New(cfg, deps); err == nil {
		t.Fatal("New = nil error, want error (nonces declares Durable but not AtomicConsume)")
	}
}

// TestNewRejectsPreAuthorizedCodeStoresUnderProduction covers the
// pre-authorized_code flow's own three conditionally-required stores
// (PreAuthorizedCodes/DPoPReplay, gated on Dependencies.PreAuthorizedCodes
// being set at all) — a configuration validConfig/validDependencies
// never wires in by default, so this builds its own minimal one.
func TestNewRejectsPreAuthorizedCodeStoresUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = issuer.AssuranceProduction
	cfg.Limits.AccessTokenLifetime = time.Hour
	cfg.Limits.MaxDPoPProofAge = time.Minute
	cfg.Limits.MaxTxCodeAttempts = 3
	deps := validDependencies(t)
	deps.Nonces = assuredNonceStore{newFakeNonceStore(), issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	deps.CredentialOffers = assuredCredentialOfferStore{newFakeCredentialOfferStore(), issuer.StoreCapabilities{Durable: true}}
	deps.DeferredTransactions = assuredDeferredTransactionStore{newFakeDeferredTransactionStore(), issuer.StoreCapabilities{Durable: true}}
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}
	deps.PreAuthorizedCodes = newFakePreAuthorizedCodeStore()
	deps.DPoPReplay = newFakeDPoPReplayChecker()
	deps.AccessTokens = &fakeAccessTokenIssuer{}

	if _, err := issuer.New(cfg, deps); err == nil {
		t.Fatal("New = nil error, want error (pre_authorized_codes/dpop_replay declare no StoreAssurance)")
	}
}
