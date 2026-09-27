package main

import (
	"context"
	"crypto/x509"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// attesterTrust picks how fapigo/server trusts a Client Attestation's
// signing key (HAIP 1.0 §4.4.1): by its "x5c" chain against each
// client's attester_trust_anchors_pem (server.X5CAttesterChain), or by
// "kid" against its attester_jwks (server.RegisteredAttesterKeys) —
// loadConfig has already checked every client uses the same one.
func attesterTrust(cfg Config) (server.AttesterTrust, error) {
	if !cfg.Client.usesAttesterTrustAnchors() {
		return server.RegisteredAttesterKeys{}, nil
	}
	anchors := perClientAttesterAnchors{}
	for _, cc := range []*ConfigClient{&cfg.Client, cfg.Client2} {
		if cc == nil {
			continue
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cc.AttesterTrustAnchorsPEM)) {
			return nil, fmt.Errorf("config: client %s: attester_trust_anchors_pem holds no PEM certificates", cc.ID)
		}
		anchors[fapi.ClientID(cc.ID)] = pool
	}
	return server.X5CAttesterChain{TrustAnchors: anchors}, nil
}

// perClientAttesterAnchors trusts each client's own attester CA(s) —
// an unknown client gets none, which rejects its attestation.
type perClientAttesterAnchors map[fapi.ClientID]*x509.CertPool

// TrustAnchors implements server.AttesterTrustAnchors.
func (a perClientAttesterAnchors) TrustAnchors(_ context.Context, client storage.RegisteredClient) (*x509.CertPool, error) {
	return a[client.ID()], nil
}
