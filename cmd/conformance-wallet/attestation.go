package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// clientAttestationTypHeader/clientAttestationChallengeEndpointPath
// match draft-ietf-oauth-attestation-based-client-auth-07 §5.1 and the
// suite's own fixed "challenge" path
// (AbstractVCIWalletTest.handleClientRequestForPath) exactly.
const (
	clientAttestationTypHeader     = "oauth-client-attestation+jwt"
	clientAttestationLifetime      = 5 * time.Minute
	clientAttestationChallengePath = "/challenge"
)

// mintClientAttestationJWT builds and signs this run's own Client
// Attestation JWT (draft-07 §5.1): a reusable, pre-issued credential
// this binary plays both Wallet and Attester for — signed by
// attesterKey, whose leaf certificate (attesterLeafPEM) chains to the
// CA the suite's own "client_attestation.trust_anchor" config trusts
// (see newWalletRun's own doc comment). Confirmed against the suite's
// own ValidateClientAttestationSignature.java (verifies via the x5c
// header's leaf public key, not a registered JWKS) and
// ValidateClientAttestationX5cClaimInProofJwt.java (walks the chain up
// to client_attestation_trust_anchor_pem, which must NOT include the
// trust anchor itself and whose leaf must NOT be self-signed — hence
// attesterLeafPEM being CA-issued, not self-signed, in config.go).
func mintClientAttestationJWT(attesterKey *ecdsa.PrivateKey, attesterLeafPEM, attesterIssuer, clientID string, instanceKey crypto.PublicKey, now time.Time) (string, error) {
	leafCert, err := conformancecert.ParseCertificatePEM(attesterLeafPEM)
	if err != nil {
		return "", fmt.Errorf("parse attester leaf certificate: %w", err)
	}
	instanceJWK, err := jwk.Marshal(instanceKey)
	if err != nil {
		return "", fmt.Errorf("marshal client instance key: %w", err)
	}
	claims := map[string]any{
		"iss": attesterIssuer,
		"sub": clientID,
		"iat": now.Unix(),
		"exp": now.Add(clientAttestationLifetime).Unix(),
		"cnf": map[string]any{"jwk": instanceJWK},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal client attestation claims: %w", err)
	}
	header := map[string]any{
		"typ": clientAttestationTypHeader,
		"x5c": []string{base64.StdEncoding.EncodeToString(leafCert.Raw)},
	}
	return jose.Sign(jose.ES256, attesterKey, header, payload)
}

// staticAttestationSource is a fixed client.AttestationSource: this
// binary mints one Client Attestation JWT per run and holds it for the
// run's whole duration, exactly matching the real-world contract
// (client.AttestationSource's own doc comment: "an opaque, out-of-band-
// issued, reusable credential this package never constructs itself" —
// here, "out of band" is this run's own startup, not a genuinely
// separate process, since this binary simulates both roles).
type staticAttestationSource string

func (s staticAttestationSource) CurrentAttestation(context.Context) (string, error) {
	return string(s), nil
}

// challengeSource implements client.ChallengeSource by POSTing to the
// suite's own Attestation Challenge Endpoint (draft-07 §8.1) each time
// FAPIgo's client package needs one — never cached, matching a fresh
// challenge per PoP JWT.
type challengeSource struct {
	httpClient *http.Client
	endpoint   string
}

// attestationChallengeResponse is the Challenge Endpoint's own
// response shape (confirmed against the suite's own
// GenerateAttestationChallengeResponse.java: JSON body, not a response
// header — that's a separate, optional draft-07 §8.2 mechanism this
// binary doesn't use).
type attestationChallengeResponse struct {
	AttestationChallenge string `json:"attestation_challenge"`
}

func (c challengeSource) CurrentChallenge(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, nil)
	if err != nil {
		return "", err
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("challenge endpoint returned status %d", res.StatusCode)
	}
	var body attestationChallengeResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode challenge response: %w", err)
	}
	if body.AttestationChallenge == "" {
		return "", fmt.Errorf("challenge response carries no attestation_challenge")
	}
	return body.AttestationChallenge, nil
}

// attestationAndChallengeSource combines staticAttestationSource and
// challengeSource into the single value client.Dependencies.Attestation
// expects — FAPIgo's own attestationHeaders type-asserts this value for
// client.ChallengeSource, so both methods must live on one type.
type attestationAndChallengeSource struct {
	staticAttestationSource
	challengeSource
}
