package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// The Wallet Provider's identifiers, and the lifetimes of what it
// issues.
const (
	providerIssuer          = "https://wallet-provider.oid4vcgo.example"
	providerCertification   = providerIssuer + "/certification"
	walletName              = "OID4VCgo interop wallet"
	walletVersion           = "1.0.0"
	walletAttestationTTL    = time.Hour
	keyAttestationTTL       = 10 * time.Minute
	statusPeriod            = 60 * 24 * time.Hour // past the issuer's 31-day preferred status periods
	walletAttestationTypHdr = attestation.WalletAttestationTypHeader
)

// provider is a throwaway Wallet Provider issuing the Wallet
// Attestations and Key Attestations the EUDI PID Issuer takes: OID4VCI
// 1.0 Appendix E and D.1's, with the claims the EUDI Wallet Unit
// Attestation specification (TS3) adds and the issuer and its Keycloak
// extension require — wallet_name, wallet_version,
// wallet_solution_certification_information and client_status in the
// Wallet Attestation; key_storage and user_authentication (both
// iso_18045_high), certification and key_storage_status in the Key
// Attestation. Package attestation issues only Appendix D's and E's
// claims, so these are signed here. It implements
// walletflow.WalletProvider.
type provider struct {
	waKey  *ecdsa.PrivateKey
	waCert *x509.Certificate
	kaKey  *ecdsa.PrivateKey
	kaCert *x509.Certificate
	// statusURI is the Wallet Provider's status list, and the indices
	// the attestations' client_status and key_storage_status name.
	statusURI        string
	walletStatusIdx  int
	keyStorageStatus int
	now              func() time.Time
}

// WalletAttestation implements walletflow.WalletProvider.
func (p *provider) WalletAttestation(_ context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	cnf, err := jwk.Marshal(instanceKey)
	if err != nil {
		return "", fmt.Errorf("wallet attestation: instance key: %w", err)
	}
	now := p.now()
	claims := map[string]any{
		"iss":            providerIssuer,
		"sub":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(walletAttestationTTL).Unix(),
		"cnf":            map[string]any{"jwk": cnf},
		"wallet_name":    walletName,
		"wallet_link":    providerIssuer,
		"wallet_version": walletVersion,
		"wallet_solution_certification_information": providerCertification,
		"client_status": p.status(p.walletStatusIdx, now),
	}
	return p.sign(p.waKey, p.waCert, walletAttestationTypHdr, claims)
}

// KeyAttestation implements walletflow.WalletProvider: one Key
// Attestation over keys, carrying nonce, with an exp, which the jwt
// proof type requires (Appendix D.1).
func (p *provider) KeyAttestation(_ context.Context, _ crypto.PublicKey, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("key attestation: no keys to attest")
	}
	attested := make([]any, len(keys))
	for i, k := range keys {
		j, err := jwk.Marshal(k)
		if err != nil {
			return "", fmt.Errorf("key attestation: key %d: %w", i, err)
		}
		attested[i] = j
	}
	now := p.now()
	claims := map[string]any{
		"iss":                 providerIssuer,
		"iat":                 now.Unix(),
		"exp":                 now.Add(keyAttestationTTL).Unix(),
		"attested_keys":       attested,
		"key_storage":         []attestation.AttackPotentialResistance{attestation.ISO18045High},
		"user_authentication": []attestation.AttackPotentialResistance{attestation.ISO18045High},
		"certification":       providerCertification,
		"key_storage_status":  p.status(p.keyStorageStatus, now),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return p.sign(p.kaKey, p.kaCert, attestation.TypHeader, claims)
}

// status is a TS3 client_status or key_storage_status: a Token Status
// List reference, and when the Wallet Provider next updates it.
func (p *provider) status(idx int, now time.Time) map[string]any {
	return map[string]any{
		"status": map[string]any{"status_list": map[string]any{"idx": idx, "uri": p.statusURI}},
		"exp":    now.Add(statusPeriod).Unix(),
	}
}

// sign signs claims as typ, with cert, the signer's (its CA left out,
// as HAIP 1.0 §4.4.1 and §4.5.1 have it), in x5c.
func (p *provider) sign(key *ecdsa.PrivateKey, cert *x509.Certificate, typ string, claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, key, map[string]any{
		"typ": typ,
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}, payload)
}
