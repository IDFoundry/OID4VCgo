package wallet

import (
	"context"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
)

// maxAttestationChallengeLen bounds an Attestation Challenge: it goes
// back to the Authorization Server in every Client Attestation PoP.
const maxAttestationChallengeLen = 1024

// RequestAttestationChallenge fetches a fresh Attestation Challenge from
// an Authorization Server's challenge endpoint
// (draft-ietf-oauth-attestation-based-client-auth-07 §8): an HTTP POST
// with no body, answered with {"attestation_challenge": "..."}. The
// Client Attestation PoP of the next request to that server carries it.
// It goes through this Wallet's own fetcher, like every other request
// here.
func (w *Wallet) RequestAttestationChallenge(ctx context.Context, endpoint fapi.URL) (string, error) {
	target := endpoint.URL()
	res, err := w.fetcher.Post(ctx, fapihttp.PostRequest{
		URL: &target,
		// §8's own example sends no body. fapihttp.Post requires a
		// Content-Type all the same, as the Nonce Request does.
		ContentType:         "application/json",
		ExpectedContentType: "application/json",
	})
	if err != nil {
		return "", fmt.Errorf("wallet: request attestation challenge: %w", err)
	}
	var body struct {
		AttestationChallenge string `json:"attestation_challenge"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		return "", fmt.Errorf("wallet: request attestation challenge: decode response: %w", err)
	}
	switch n := len(body.AttestationChallenge); {
	case n == 0:
		return "", fmt.Errorf("wallet: request attestation challenge: response is missing attestation_challenge")
	case n > maxAttestationChallengeLen:
		return "", fmt.Errorf("wallet: request attestation challenge: attestation_challenge is %d bytes, longer than %d", n, maxAttestationChallengeLen)
	}
	return body.AttestationChallenge, nil
}
