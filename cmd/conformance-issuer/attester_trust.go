package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// attesterTrust picks how fapigo/server trusts a Client Attestation's
// signing key (HAIP 1.0 §4.4.1): by its "x5c" chain against each
// client's attester_trust_anchors_pem (server.X5CAttesterChain), or by
// "kid" against its attester's attester_jwks
// (server.RegisteredAttesterKeys) — loadConfig has already checked
// every client uses the same one.
func attesterTrust(cfg Config) (server.AttesterTrust, error) {
	if !cfg.Client.usesAttesterTrustAnchors() {
		attesters, err := attesterKeys(cfg)
		if err != nil {
			return nil, err
		}
		return server.RegisteredAttesterKeys{Keys: attesters}, nil
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
	// The attester's leaf certificate names it as a URI SAN, which
	// fapigo/server matches against the client's
	// expected_attester_issuer, so an attester certified under the same
	// anchors can't attest for another attester's clients.
	return server.X5CAttesterChain{TrustAnchors: anchors, IssuerBinding: server.AttesterIssuerInCertificate}, nil
}

// perClientAttesterAnchors trusts each client's own attester CA(s) —
// an unknown client gets none, which rejects its attestation.
type perClientAttesterAnchors map[fapi.ClientID]*x509.CertPool

// TrustAnchors implements server.AttesterTrustAnchors.
func (a perClientAttesterAnchors) TrustAnchors(_ context.Context, client storage.RegisteredClient) (*x509.CertPool, error) {
	return a[client.ID()], nil
}

// attesterKeys registers each client's attester_jwks as its attester's
// keys, under the client's expected_attester_issuer: fapigo resolves an
// attestation's key by the Attester the client is registered with,
// never from the client's own keys, which would let a client attest for
// itself.
func attesterKeys(cfg Config) (keys.StaticAttesterKeys, error) {
	attesters := keys.StaticAttesterKeys{}
	for _, cc := range []*ConfigClient{&cfg.Client, cfg.Client2} {
		if cc == nil {
			continue
		}
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(cc.AttesterJWKS, &set); err != nil || len(set.Keys) == 0 {
			return nil, fmt.Errorf("config: client %s: attester_jwks must be a JWK Set with at least one key", cc.ID)
		}
		for i, raw := range set.Keys {
			key, err := attesterKey(raw)
			if err != nil {
				return nil, fmt.Errorf("config: client %s: attester_jwks key %d: %w", cc.ID, i, err)
			}
			attesters[cc.ExpectedAttesterIssuer] = append(attesters[cc.ExpectedAttesterIssuer], key)
		}
	}
	return attesters, nil
}

// attesterKey reads one JWK of an attester_jwks: its key, "kid" and
// "alg" (ES256, HAIP's, when it names none).
func attesterKey(raw json.RawMessage) (keys.VerificationKey, error) {
	pub, err := jwk.ParsePublicKey(raw)
	if err != nil {
		return keys.VerificationKey{}, err
	}
	var params struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return keys.VerificationKey{}, err
	}
	if params.Alg == "" {
		params.Alg = "ES256"
	}
	alg, err := fapi.ParseSignatureAlgorithm(params.Alg)
	if err != nil {
		return keys.VerificationKey{}, err
	}
	return keys.VerificationKey{KeyID: params.Kid, Algorithm: alg, PublicKey: pub}, nil
}
