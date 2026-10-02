package wallet

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	fapi "github.com/idfoundry/fapigo"
)

// DPoPResourceClient returns a ProtectedResourceClient that presents
// accessToken, bound to dpopKey, the way RFC 9449 §7 requires: each
// request carries "Authorization: DPoP <token>" and a fresh DPoP proof
// signed by dpopKey, with ath bound to the token (§4.3). It's for a
// token RequestPreAuthorizedCodeToken obtained with the same dpopKey;
// the Authorization Code Flow's token goes through fapigo/client's
// (*client.Client).ProtectedResource instead.
//
// When the resource server challenges with a fresh DPoP nonce (§9: 401,
// WWW-Authenticate naming use_dpop_nonce, and a DPoP-Nonce header), the
// request is retried once with it; the latest nonce the server sends is
// reused for later requests through the same client. A request's body,
// if any, must be replayable (req.GetBody set, as
// http.NewRequestWithContext does for a *bytes.Reader). Requests go
// through Dependencies.HTTP.
func (w *Wallet) DPoPResourceClient(accessToken fapi.Secret, dpopKey crypto.Signer) ProtectedResourceClient {
	return &dpopResourceClient{w: w, token: accessToken.Reveal(), key: dpopKey}
}

type dpopResourceClient struct {
	w     *Wallet
	token string
	key   crypto.Signer

	mu    sync.Mutex
	nonce string // the latest DPoP-Nonce the resource server sent
}

func (c *dpopResourceClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.token == "" || c.key == nil {
		return nil, errors.New("wallet: dpop resource client: an access token and its DPoP key are required")
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return nil, errors.New("wallet: dpop resource client: the request body must be replayable (GetBody) for a DPoP nonce retry")
	}
	c.mu.Lock()
	nonce := c.nonce
	c.mu.Unlock()

	res, err := c.send(ctx, req, nonce)
	if err != nil {
		return nil, err
	}
	if fresh := res.Header.Get("DPoP-Nonce"); res.StatusCode == http.StatusUnauthorized && fresh != "" &&
		strings.Contains(res.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
		_ = res.Body.Close()
		retry := req.Clone(ctx)
		if req.GetBody != nil {
			if retry.Body, err = req.GetBody(); err != nil {
				return nil, fmt.Errorf("wallet: dpop resource client: replay request body: %w", err)
			}
		}
		if res, err = c.send(ctx, retry, fresh); err != nil {
			return nil, err
		}
	}
	if next := res.Header.Get("DPoP-Nonce"); next != "" {
		c.mu.Lock()
		c.nonce = next
		c.mu.Unlock()
	}
	return res, nil
}

// send performs req with a fresh DPoP proof carrying nonce.
func (c *dpopResourceClient) send(ctx context.Context, req *http.Request, nonce string) (*http.Response, error) {
	htu := *req.URL
	htu.RawQuery, htu.Fragment = "", ""
	proof, err := c.w.GenerateDPoPProof(c.key, req.Method, htu.String(), nonce, DPoPAccessTokenHash(c.token))
	if err != nil {
		return nil, fmt.Errorf("wallet: dpop resource client: %w", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "DPoP "+c.token)
	req.Header.Set("DPoP", proof)
	res, err := c.w.deps.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wallet: dpop resource client: %w", err)
	}
	return res, nil
}
