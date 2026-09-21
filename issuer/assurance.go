package issuer

import "fmt"

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
	// DPoPReplay, DPoPNonces — CredentialOffers/DeferredTransactions/
	// Notifications are plain store/get/mark operations with nothing
	// to assert atomicity for). A store that doesn't implement
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
	// bare crypto.Signer to self-declare).
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
	// NonceStore/PreAuthorizedCodeStore/DPoPNonceStore's own Consume, a
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

// checkProductionAssurance runs checkStoreAssurance/checkKeySourceAssurance
// against every store or key source New's own existing
// conditional-required checks have already confirmed is actually
// configured — called only once cfg.Assurance is known to be
// AssuranceProduction. Split out of New purely to keep its own
// cognitive complexity manageable.
func checkProductionAssurance(cfg Config, deps Dependencies) error {
	if !cfg.Endpoints.Nonce.IsZero() {
		if err := checkStoreAssurance("nonces", deps.Nonces, true); err != nil {
			return err
		}
	}
	if !cfg.CredentialOfferEndpoint.IsZero() {
		if err := checkStoreAssurance("credential_offers", deps.CredentialOffers, false); err != nil {
			return err
		}
	}
	if !cfg.Endpoints.DeferredCredential.IsZero() {
		if err := checkStoreAssurance("deferred_transactions", deps.DeferredTransactions, false); err != nil {
			return err
		}
	}
	if !cfg.Endpoints.Notification.IsZero() {
		if err := checkStoreAssurance("notifications", deps.Notifications, false); err != nil {
			return err
		}
	}
	if deps.PreAuthorizedCodes != nil {
		if err := checkStoreAssurance("pre_authorized_codes", deps.PreAuthorizedCodes, true); err != nil {
			return err
		}
		if err := checkStoreAssurance("dpop_replay", deps.DPoPReplay, true); err != nil {
			return err
		}
	}
	if deps.DPoPNonces != nil {
		if err := checkStoreAssurance("dpop_nonces", deps.DPoPNonces, true); err != nil {
			return err
		}
	}
	if deps.AttestationVerifier != nil {
		if err := checkKeySourceAssurance("attestation_verifier", deps.AttestationVerifier); err != nil {
			return err
		}
	}
	if deps.ProofBindingKeys != nil {
		if err := checkKeySourceAssurance("proof_binding_keys", deps.ProofBindingKeys); err != nil {
			return err
		}
	}
	if deps.Audit == nil {
		return fmt.Errorf("dependencies.audit is required under AssuranceProduction")
	}
	return nil
}
