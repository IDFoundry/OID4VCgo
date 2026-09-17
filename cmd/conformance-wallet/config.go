package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// walletRun holds everything generated once per invocation of this
// binary: the throwaway key material for Client Attestation
// (draft-ietf-oauth-attestation-based-client-auth-07), the Credential
// Issuer signing key the suite itself will sign issued credentials
// with, and the resulting suite-side plan configuration JSON. A fresh
// run always generates fresh keys/aliases — there is no reason to
// persist or reuse them across invocations, the same "fresh per run"
// convention FAPIgo's own cmd/conformance-client follows.
type walletRun struct {
	alias                     string
	clientID                  string
	redirectURI               string
	scope                     string
	credentialConfigurationID string

	// attesterKey signs this run's own Client Attestation JWT
	// (attestation.go) — this binary plays both the Wallet and its own
	// Attester, the same way cmd/conformance-issuer/flow_test.go's own
	// test helpers simulate an Attester, but as production code here.
	attesterKey     *ecdsa.PrivateKey
	attesterCAPEM   string // client_attestation.trust_anchor, configured on the suite side
	attesterLeafPEM string

	// keyAttestationKey signs this run's own Key Attestation JWT(s)
	// (keyattestation.go) when proofType requests one — a separate
	// CA-issued identity from attesterKey, chaining to its own
	// client_attestation.key_attestation_trust_anchor_pem config value
	// (config.go's own newWalletRun), matching how a real deployment's
	// Key Attestation authority (a secure element/OS attestation
	// service) is a distinct authority from the Wallet Attestation
	// issuer above.
	keyAttestationKey     *ecdsa.PrivateKey
	keyAttestationLeafPEM string

	// proofType selects which of the three Credential Request proof
	// strategies (proof.go) this run uses for every module it drives —
	// see proofStrategy's own doc comment. Only meaningful when
	// credentialConfigurationID names a fixture whose
	// proof_types_supported actually offers the selected strategy's own
	// proof type (e.g. eu.europa.ec.eudi.pid.1.attestation for
	// proofStrategyAttestation) — the suite rejects any other
	// combination itself, so this binary doesn't cross-check it.
	proofType proofStrategy

	planConfig []byte
}

// newWalletRun generates a fresh alias/client ID/key material and
// builds the suite-side plan configuration JSON for one run.
// cfg.credentialConfigurationID/cfg.scope are the suite's own fixed
// values for its fixture "eu.europa.ec.eudi.pid.1" jwt-proof-type
// credential configuration (confirmed live via a created module's own
// "Created credential issuer metadata" log entry — the suite's
// emulated Credential Issuer defines a small fixed set of
// credential_configuration_id/scope pairs, not an arbitrary
// tester-chosen name).
func newWalletRun(cfg runConfig) (*walletRun, error) {
	suffix, err := randomHex(4)
	if err != nil {
		return nil, fmt.Errorf("generate run suffix: %w", err)
	}
	alias := "oid4vcgo-wallet-" + suffix
	clientID := "oid4vcgo-wallet-client-" + suffix
	redirectURI := cfg.apiBase + "test/a/" + alias + "/callback"

	attesterKey, _, attesterLeafPEM, attesterCAPEM, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-wallet-attester-leaf", "oid4vcgo-wallet-attester-ca")
	if err != nil {
		return nil, fmt.Errorf("generate attester key/cert: %w", err)
	}

	// A dedicated CA/leaf for Key Attestation JWTs (keyattestation.go),
	// distinct from the Client Attestation attester above — generated
	// unconditionally (cheap) so client_attestation.key_attestation_trust_anchor_pem
	// below is always a real, dedicated trust anchor rather than a
	// placeholder, regardless of useAttestationProof.
	keyAttestationKey, _, keyAttestationLeafPEM, keyAttestationCAPEM, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-wallet-key-attester-leaf", "oid4vcgo-wallet-key-attester-ca")
	if err != nil {
		return nil, fmt.Errorf("generate key attestation key/cert: %w", err)
	}

	// HAIP §6.1.1 requires the credential signing certificate not be
	// self-signed (confirmed live: VCIEnsureCredentialSigningCertificateIsNotSelfSigned
	// rejects one that is) — a throwaway CA-issued leaf, mirroring the
	// attester's own leaf/CA shape, satisfies this the same way
	// cmd/conformance-wallet-vp's own credential-issuer cert does.
	credentialSigningKey, _, credentialSigningLeafPEM, _, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-wallet-credential-issuer-leaf", "oid4vcgo-wallet-credential-issuer-ca")
	if err != nil {
		return nil, fmt.Errorf("generate credential signing key/cert: %w", err)
	}
	credentialSigningJWK, err := privateJWKWithX5C(credentialSigningKey, credentialSigningLeafPEM)
	if err != nil {
		return nil, fmt.Errorf("build credential signing jwk: %w", err)
	}

	// server.jwks is the suite's own emulated Authorization Server
	// signing key set — required in the submitted config (confirmed
	// live: LoadServerJWKs fails "Couldn't find a JWK set in
	// configuration" without it), regardless of ClientAuthType.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server signing key: %w", err)
	}
	serverJWK, err := privateJWK(serverKey, "oid4vcgo-wallet-server-key")
	if err != nil {
		return nil, fmt.Errorf("build server jwk: %w", err)
	}

	planConfig, err := json.Marshal(map[string]any{
		"alias": alias,
		"server": map[string]any{
			"jwks": map[string]any{"keys": []any{serverJWK}},
		},
		"client": map[string]any{
			"client_id":    clientID,
			"scope":        cfg.scope,
			"redirect_uri": redirectURI,
		},
		"client_attestation": map[string]any{
			// issuer is an opaque identifier the suite checks the
			// Client Attestation JWT's own "iss" claim against
			// (ValidateClientAttestationIssuer) — it never needs to
			// resolve to anything real.
			"issuer":       "https://oid4vcgo-wallet-attester.example.com",
			"trust_anchor": attesterCAPEM,
			// key_attestation_trust_anchor_pem is required config
			// regardless of proofType — a distinct HAIP §4.5.1
			// requirement from Wallet Attestation client auth (see
			// AGENTS.md's own note on not conflating the two). Its own
			// dedicated CA (above) only actually gets exercised when a
			// Key Attestation JWT is presented (keyattestation.go).
			"key_attestation_trust_anchor_pem": keyAttestationCAPEM,
			// key_attestation_jwks is a required-but-unused placeholder
			// under the base (non-HAIP) plan's own fapi_profile=vci
			// variant — AbstractVCIWalletTest.java only hides it under
			// fapi_profile=vci_haip, and its own fallback verifier
			// (VerifyKeyAttestationSignatureUsingConfigJwks) only ever
			// reads it when a presented Key Attestation JWT lacks an x5c
			// header, which keyattestation.go never omits — matching the
			// same required-but-unused pattern already found for the
			// Issuer role's own client_attestation.key_attestation_jwks
			// (run-fapi2sp-battery/config.go).
			"key_attestation_jwks": map[string]any{"keys": []any{}},
		},
		"credential": map[string]any{
			"signing_jwk": credentialSigningJWK,
		},
		"vci": vciConfig(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal plan config: %w", err)
	}

	return &walletRun{
		alias: alias, clientID: clientID, redirectURI: redirectURI,
		scope: cfg.scope, credentialConfigurationID: cfg.credentialConfigurationID,
		attesterKey: attesterKey, attesterCAPEM: attesterCAPEM, attesterLeafPEM: attesterLeafPEM,
		keyAttestationKey: keyAttestationKey, keyAttestationLeafPEM: keyAttestationLeafPEM,
		proofType:  cfg.proofType,
		planConfig: planConfig,
	}, nil
}

// vciConfig builds the plan config's own "vci" object — just
// credential_configuration_id for wallet_initiated, plus
// credential_offer_endpoint for issuer_initiated
// (@VariantHidesConfigurationFields in AbstractVCIWalletTest.java
// hides that field entirely for wallet_initiated, so it's only
// included when actually needed).
func vciConfig(cfg runConfig) map[string]any {
	vci := map[string]any{"credential_configuration_id": cfg.credentialConfigurationID}
	if cfg.issuerInitiated {
		vci["credential_offer_endpoint"] = cfg.credentialOfferEndpoint + credentialOfferPath
	}
	return vci
}

// privateJWKWithX5C builds the suite's own "credential.signing_jwk"
// config value: an EC P-256 JWK carrying the private "d" (the suite
// signs issued test credentials with this key directly, so — unlike
// every other key in this binary — the private scalar itself, not just
// the public half, has to cross into the suite's own config) plus an
// "x5c" entry (built from leafCertPEM, a CA-issued, non-self-signed
// certificate for key — see HAIP §6.1.1's own requirement) so a
// credential the suite issues carries a certificate chain, matching
// the sample config schema found in the suite's own
// scripts/test-configs-rp-against-op/vci-wallet-test-config-haip.json.
func privateJWKWithX5C(key *ecdsa.PrivateKey, leafCertPEM string) (map[string]any, error) {
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	cert, err := conformancecert.ParseCertificatePEM(leafCertPEM)
	if err != nil {
		return nil, err
	}
	d, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode private scalar: %w", err)
	}
	return map[string]any{
		"kty": pub.Kty, "crv": pub.Crv, "x": pub.X, "y": pub.Y, "alg": "ES256",
		"d":   base64.RawURLEncoding.EncodeToString(d),
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}, nil
}

// privateJWK builds a plain private EC P-256 JWK (kty/crv/x/y/d/kid,
// no x5c) — the shape server.jwks needs.
func privateJWK(key *ecdsa.PrivateKey, kid string) (map[string]any, error) {
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	d, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode private scalar: %w", err)
	}
	return map[string]any{
		"kty": pub.Kty, "crv": pub.Crv, "x": pub.X, "y": pub.Y, "alg": "ES256",
		"d": base64.RawURLEncoding.EncodeToString(d), "kid": kid,
	}, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}
