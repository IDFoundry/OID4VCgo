// Package storage provides in-memory implementations of every store
// interface the issuer package defines (NonceStore, CredentialOfferStore,
// DeferredTransactionStore, NotificationStore, PreAuthorizedCodeStore,
// DPoPNonceStore, DPoPReplayChecker) — for local development and
// testing only. Never production.
//
// Every type here is non-durable (an in-process map, gone on restart)
// and grows unboundedly for the life of the process — there is no
// expiry-driven garbage collection. That's fine for a short local
// development session; it is not fine for anything long-running.
//
// None of these types implement issuer.StoreAssurance, and that is
// deliberate, not an oversight: issuer.New's own checkProductionStoreAssurance
// (issuer/assurance.go) rejects any store that doesn't implement
// StoreAssurance at all under issuer.AssuranceProduction, which is
// exactly what already makes issuer.New correctly refuse every type in
// this package under that assurance level. Adding a StoreAssurance
// declaration here — even one that honestly reports Durable: false —
// would only add a false sense of having addressed production-readiness
// to a package that fundamentally cannot be production-ready. Don't.
package storage
