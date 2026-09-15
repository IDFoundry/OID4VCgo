// Package storage provides in-memory implementations of every store
// interface the issuer package defines (NonceStore, CredentialOfferStore,
// DeferredTransactionStore, NotificationStore) — for local development
// and testing only. Never production.
//
// Every type here is non-durable (an in-process map, gone on restart)
// and grows unboundedly for the life of the process — there is no
// expiry-driven garbage collection. That's fine for a short local
// development session; it is not fine for anything long-running.
package storage
