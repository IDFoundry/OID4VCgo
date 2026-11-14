package prodwallet

import (
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Stores are a wallet's durable stores, in one SQLite file, every
// record sealed: sqlstore's walletflow stores, and fapigo/sqlstore's
// client sessions.
type Stores struct {
	// Keys is sqlstore's KeyStore, which declares durable custody
	// (keys.KeyCustodyAssurance): Custody is that declaration.
	Keys           walletflow.KeyStore
	Custody        keys.KeyCustody
	Credentials    walletflow.CredentialStore
	Authorizations walletflow.AuthorizationStore
	Grants         walletflow.GrantStore
	Deferred       walletflow.DeferredStore
	// Sessions is fapigo/sqlstore's client session store, for a wallet
	// driving fapigo/client itself (client.Dependencies.Sessions).
	Sessions storage.SessionStore

	close func() error
}

// Dependencies is deps with s's stores: Keys, Credentials,
// Authorizations, Grants and Deferred.
func (s *Stores) Dependencies(deps walletflow.Dependencies) walletflow.Dependencies {
	deps.Keys, deps.Credentials, deps.Authorizations, deps.Grants, deps.Deferred = s.Keys, s.Credentials, s.Authorizations, s.Grants, s.Deferred
	return deps
}

// Close closes the database.
func (s *Stores) Close() error {
	if s == nil || s.close == nil {
		return nil
	}
	return s.close()
}
