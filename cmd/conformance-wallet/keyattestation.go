package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// keyAttestationIssuer is this run's own Key Attestation JWT "iss"
// claim (attestation.Claims.Issuer) — like the Client Attestation
// issuer in attestation.go, an opaque identifier nothing in the suite
// resolves or validates; it's a distinct string from the Client
// Attestation issuer to make live log output unambiguous about which
// attestation authority minted which JWT.
const keyAttestationIssuer = "https://oid4vcigo-wallet-key-attester.example.com"

// buildKeyAttestationProof mints one Key Attestation JWT (OID4VCI 1.0
// Appendix D.1) attesting attestedKeys and submits it via the
// standalone "attestation" proof type (Appendix F.3) — HAIP §4.5.1's
// "Wallets MUST support key attestations" requirement. Unlike a
// jwt-type proof, this alone requests a batch: the suite issues one
// Credential per key in the attestation's own attested_keys claim, so
// len(attestedKeys) == numCreds (see wallet.CredentialRequest's own
// doc comment).
//
// Built via wallet.Wallet.GenerateAttestationProof — the production
// attestation package's own issuance path
// (github.com/idfoundry/oid4vcigo/attestation), not a hand-rolled JWT,
// so this binary's live run proves that real code path works, not a
// test double of it.
func buildKeyAttestationProof(w *wallet.Wallet, run *walletRun, attestedKeys []crypto.Signer, nonce string) (string, error) {
	leafCert, err := conformancecert.ParseCertificatePEM(run.keyAttestationLeafPEM)
	if err != nil {
		return "", fmt.Errorf("parse key attestation leaf certificate: %w", err)
	}

	rawKeys := make([]json.RawMessage, len(attestedKeys))
	for i, signer := range attestedKeys {
		pub, err := jwk.Marshal(signer.Public())
		if err != nil {
			return "", fmt.Errorf("marshal attested key %d: %w", i, err)
		}
		raw, err := json.Marshal(pub)
		if err != nil {
			return "", fmt.Errorf("marshal attested key %d: %w", i, err)
		}
		rawKeys[i] = raw
	}

	// HAIP §4.5.1: "the public key used to validate the key attestation
	// signature MUST be included in the x5c JOSE header parameter" — the
	// same CA-issued, non-self-signed leaf/trust-anchor shape
	// mintClientAttestationJWT already established for Client
	// Attestation, chaining to client_attestation.key_attestation_trust_anchor_pem
	// (config.go) instead of client_attestation.trust_anchor.
	header := attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(leafCert.Raw)}}
	claims := attestation.Claims{Issuer: keyAttestationIssuer, AttestedKeys: rawKeys}

	proof, err := w.GenerateAttestationProof(run.keyAttestationKey, jose.ES256, header, claims, nonce)
	if err != nil {
		return "", fmt.Errorf("generate key attestation proof: %w", err)
	}
	return proof, nil
}

// generateAttestedKeys generates n fresh EC P-256 signers to attest —
// the credential-binding keys a real wallet's secure element/OS
// attestation service would otherwise have already provisioned and
// attested itself (see wallet.Wallet.GenerateAttestationProof's own
// doc comment on why this package builds one directly here instead).
func generateAttestedKeys(n int) ([]crypto.Signer, error) {
	keys := make([]crypto.Signer, n)
	for i := range keys {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate attested key %d: %w", i, err)
		}
		keys[i] = key
	}
	return keys, nil
}
