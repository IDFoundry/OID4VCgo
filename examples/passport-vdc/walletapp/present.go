package walletapp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// PresentOptions controls Present.
type PresentOptions struct {
	// Format, if set, restricts which stored credentials are offered to
	// the Verifier's query ("mso_mdoc" or "dc+sd-jwt") — how the demo
	// shows a Verifier accepting either format.
	Format string
	// HTTP makes every request; nil means a client with a 10 s timeout.
	HTTP *http.Client
}

// Presented summarizes what Present sent.
type Presented struct {
	VerifierClientID string
	// Credentials are the DCQL credential query IDs presented.
	Credentials []string
}

// Present answers an OpenID4VP Authorization Request (an openid4vp://
// link carrying client_id and request_uri) with credentials from store:
// it fetches and verifies the signed Request Object, matches its DCQL
// query against the stored credentials, builds selectively disclosed
// presentations bound to the Verifier's nonce, and POSTs them to the
// response_uri as an encrypted direct_post.jwt response.
//
// Like the rest of this demo wallet, it asks no one before presenting:
// a real wallet would show the holder what's requested, and by whom.
func Present(ctx context.Context, requestLink string, store Store, opts PresentOptions) (Presented, error) {
	httpClient := opts.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: httpTimeout}
	}
	link, err := url.Parse(requestLink)
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: presentation request link: %w", err)
	}
	clientID, requestURI := link.Query().Get("client_id"), link.Query().Get("request_uri")
	if clientID == "" || requestURI == "" {
		return Presented{}, fmt.Errorf("walletapp: presentation request link needs client_id and request_uri")
	}

	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: httpTimeout, MaxRedirects: 2, AllowLoopbackHTTP: true},
	}, wallet.Dependencies{HTTP: httpClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: %w", err)
	}
	// FetchAuthorizationRequest checks the Request Object's signature
	// and that client_id is its signing certificate's x509_hash — it
	// establishes who the Verifier is, not whether to trust them.
	authReq, err := w.FetchAuthorizationRequest(ctx, requestURI, clientID)
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: presentation request: %w", err)
	}

	held, err := heldCredentials(store, opts.Format)
	if err != nil {
		return Presented{}, err
	}
	vpToken, err := wallet.PresentCredentials(ctx, wallet.PresentationRequest{
		Query: authReq.Query, Credentials: held, Audience: authReq.ClientID, Nonce: authReq.Nonce,
		ResponseURI: authReq.ResponseURI, ResponseEncryptionKey: authReq.ResponseEncryptionKey,
	})
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: no stored credential satisfies the request: %w", err)
	}
	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: authReq.State,
		EncryptionKey: authReq.ResponseEncryptionKey, EncryptionKeyID: authReq.ResponseEncryptionKeyID,
		EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: presentation response: %w", err)
	}
	if err := postResponse(ctx, httpClient, authReq.ResponseURI, responseJWE); err != nil {
		return Presented{}, err
	}

	presented := Presented{VerifierClientID: authReq.ClientID}
	for id := range vpToken {
		presented.Credentials = append(presented.Credentials, id)
	}
	sort.Strings(presented.Credentials)
	return presented, nil
}

// heldCredentials loads the store as wallet.HeldCredentials, optionally
// only those of one format.
func heldCredentials(store Store, format string) ([]wallet.HeldCredential, error) {
	stored, err := store.List()
	if err != nil {
		return nil, err
	}
	var held []wallet.HeldCredential
	for _, s := range stored {
		if format != "" && s.Format != format {
			continue
		}
		block, _ := pem.Decode([]byte(s.HolderKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("walletapp: %s: no holder key", s.Path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("walletapp: %s: holder key: %w", s.Path, err)
		}
		held = append(held, wallet.HeldCredential{
			Format: s.Format, Credential: s.Credential,
			HolderKey: key, HolderKeyAlg: oid4vci.ES256, MdocDocType: s.DocType,
		})
	}
	if len(held) == 0 {
		return nil, fmt.Errorf("walletapp: no stored credentials to present")
	}
	return held, nil
}

// postResponse POSTs a direct_post.jwt response (§8.3.1) and checks the
// Verifier accepted it.
func postResponse(ctx context.Context, hc *http.Client, responseURI, responseJWE string) error {
	form := url.Values{"response": {responseJWE}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURI, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("walletapp: response: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("walletapp: response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		return fmt.Errorf("walletapp: verifier rejected the presentation: status %d %s %s", resp.StatusCode, e.Error, e.Description)
	}
	return nil
}
