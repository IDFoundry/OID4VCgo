package main

import (
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// backend is what Config.Production changes in the wiring newServers
// builds: the Authorization Server's and the Credential Issuer's
// assurance level, stores, keys and audit, each applied just before
// server.New or issuer.New sees them.
type backend interface {
	// authorizationServer adjusts the Authorization Server's
	// configuration and dependencies, given the clients to register,
	// and returns the Credential Endpoint's DPoP nonce store (or
	// resourceNonces, unchanged).
	authorizationServer(srvCfg *server.Config, deps *server.Dependencies, clients []storage.RegisteredClientConfig, resourceNonces storage.NonceStore) (storage.NonceStore, error)

	// issuer adjusts the Credential Issuer's configuration and
	// dependencies.
	issuer(cfg *issuer.Config, deps *issuer.Dependencies) error
}

// newBackend is the development wiring's backend, which changes
// nothing, or Config.Production's.
func newBackend(cfg Config) (backend, error) {
	if cfg.Production == nil {
		return developmentBackend{}, nil
	}
	return newProductionBackend(cfg)
}

// developmentBackend keeps the development wiring: in-memory stores and
// keys, under development assurance.
type developmentBackend struct{}

func (developmentBackend) authorizationServer(_ *server.Config, _ *server.Dependencies, _ []storage.RegisteredClientConfig, resourceNonces storage.NonceStore) (storage.NonceStore, error) {
	return resourceNonces, nil
}

func (developmentBackend) issuer(*issuer.Config, *issuer.Dependencies) error { return nil }
