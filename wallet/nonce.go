package wallet

import (
	"context"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
)

// NonceResult is returned by a successful RequestNonce.
type NonceResult struct {
	// CNonce is the fresh challenge (§7.2) — pass it to GenerateProof.
	CNonce string
}

// RequestNonce implements the Nonce Endpoint's own client side (§7.1):
// an unauthenticated HTTP POST with an empty body. The Nonce Endpoint
// is not a protected resource (§7.1) — no access token or DPoP proof
// is needed to call it.
func (w *Wallet) RequestNonce(ctx context.Context, endpoint fapi.URL) (NonceResult, error) {
	target := endpoint.URL()
	res, err := w.fetcher.Post(ctx, fapihttp.PostRequest{
		URL: &target,
		// The Nonce Request has no body (§7.1's own example: "Content-Length: 0").
		// A Content-Type is still set — fapihttp.Post requires one, and no
		// real server rejects an empty POST body over a stated
		// application/json type.
		ContentType:         "application/json",
		ExpectedContentType: "application/json",
	})
	if err != nil {
		return NonceResult{}, fmt.Errorf("wallet: request nonce: %w", err)
	}

	var body struct {
		CNonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		return NonceResult{}, fmt.Errorf("wallet: request nonce: decode response: %w", err)
	}
	if body.CNonce == "" {
		return NonceResult{}, fmt.Errorf("wallet: request nonce: response is missing c_nonce")
	}
	return NonceResult{CNonce: body.CNonce}, nil
}
