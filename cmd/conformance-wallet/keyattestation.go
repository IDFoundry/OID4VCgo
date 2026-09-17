package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// proofStrategy selects which Credential Request proof mechanism a
// run uses for every module it drives (driveModule's own switch).
type proofStrategy string

const (
	// proofStrategyJWT is the default: a jwk-conveyed jwt-type proof
	// per credential (Appendix F.1), no Key Attestation involved.
	proofStrategyJWT proofStrategy = "jwt"

	// proofStrategyAttestation submits a single standalone Key
	// Attestation JWT as the "attestation" proof type (Appendix F.3,
	// HAIP §4.5.1) — no per-credential jwt proof at all; see
	// buildKeyAttestationProof's own doc comment.
	proofStrategyAttestation proofStrategy = "attestation"

	// proofStrategyJWTKeyAttestation submits ordinary jwt-type proofs
	// (one per credential, as proofStrategyJWT does), but with a Key
	// Attestation JWT nested in each proof's own JOSE header via its
	// "key_attestation" member — Appendix D.1's "if used with the jwt
	// proof type" case, distinct from proofStrategyAttestation's
	// standalone proof type. All proofs in one request share the same
	// attestation (attesting every key in the batch at once) rather
	// than each minting its own — see driveModule's own comment on why.
	proofStrategyJWTKeyAttestation proofStrategy = "jwt-key-attestation"
)

// keyAttestationIssuer is this run's own Key Attestation JWT "iss"
// claim (attestation.Claims.Issuer) — like the Client Attestation
// issuer in attestation.go, an opaque identifier nothing in the suite
// resolves or validates; it's a distinct string from the Client
// Attestation issuer to make live log output unambiguous about which
// attestation authority minted which JWT.
const keyAttestationIssuer = "https://oid4vcgo-wallet-key-attester.example.com"

// keyAttestationLifetime bounds the "exp" claim buildKeyAttestationProof
// sets when includeExpiry is true — an arbitrary, generous window; the
// suite only checks it's absent-or-plausible (ValidateKeyAttestationExp),
// never a specific value.
const keyAttestationLifetime = 5 * time.Minute

// buildKeyAttestationProof mints one Key Attestation JWT (OID4VCI 1.0
// Appendix D.1) attesting attestedKeys — HAIP §4.5.1's "Wallets MUST
// support key attestations" requirement. Built via
// wallet.Wallet.GenerateAttestationProof — the production attestation
// package's own issuance path
// (github.com/idfoundry/oid4vcgo/attestation), not a hand-rolled JWT,
// so this binary's live run proves that real code path works, not a
// test double of it.
//
// includeExpiry sets the "exp" claim, REQUIRED by Appendix D.1 "if the
// attestation is used with the JWT proof type" (proofStrategyJWTKeyAttestation)
// but not otherwise (proofStrategyAttestation's own standalone use
// leaves it optional) — see EnsureKeyAttestationExpIsPresentForJwtProof
// in the suite's own AbstractVCIWalletTest.java.
func buildKeyAttestationProof(w *wallet.Wallet, run *walletRun, attestedKeys []crypto.Signer, nonce string, includeExpiry bool) (string, error) {
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
	if includeExpiry {
		exp := time.Now().Add(keyAttestationLifetime).Unix()
		claims.ExpiresAt = &exp
	}

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
