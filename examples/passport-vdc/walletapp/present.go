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

// Presented summarizes what was sent.
type Presented struct {
	VerifierClientID string
	// Credentials are the DCQL credential query IDs presented.
	Credentials []string
}

// Prepared is a verified presentation request the holder hasn't
// answered yet, with every way the wallet's stored credentials can
// satisfy it.
type Prepared struct {
	// VerifierClientID identifies the verifier: its x509_hash client
	// identifier, checked against the Request Object's signature. It
	// establishes who the verifier is, not whether to trust them.
	VerifierClientID string
	// ResponseURI is where the answer would be sent.
	ResponseURI string
	// Options are the ways to answer, one per format the wallet can
	// answer in.
	Options []Option

	authReq wallet.AuthorizationRequest
	store   Store
	http    *http.Client
}

// Option is one way to answer a request.
type Option struct {
	Format string
	// QueryID is the DCQL credential query this answers.
	QueryID string
	// Claims are the claim paths that would be disclosed (e.g.
	// ["family_name"], or [namespace, element] for an mdoc).
	Claims [][]string
}

// Present answers an OpenID4VP Authorization Request without asking
// the holder — Prepare then Send with opts.Format.
func Present(ctx context.Context, requestLink string, store Store, opts PresentOptions) (Presented, error) {
	p, err := Prepare(ctx, requestLink, store, opts.HTTP)
	if err != nil {
		return Presented{}, err
	}
	return p.Send(ctx, opts.Format)
}

// Prepare fetches and verifies an OpenID4VP Authorization Request (an
// openid4vp:// link carrying client_id and request_uri) and works out
// how the stored credentials can answer it, without sending anything —
// so a wallet can ask the holder first.
func Prepare(ctx context.Context, requestLink string, store Store, httpClient *http.Client) (*Prepared, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: httpTimeout}
	}
	link, err := url.Parse(requestLink)
	if err != nil {
		return nil, fmt.Errorf("walletapp: presentation request link: %w", err)
	}
	clientID, requestURI := link.Query().Get("client_id"), link.Query().Get("request_uri")
	if clientID == "" || requestURI == "" {
		return nil, fmt.Errorf("walletapp: presentation request link needs client_id and request_uri")
	}

	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: httpTimeout, MaxRedirects: 2, AllowLoopbackHTTP: true},
	}, wallet.Dependencies{HTTP: httpClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		return nil, fmt.Errorf("walletapp: %w", err)
	}
	// FetchAuthorizationRequest checks the Request Object's signature
	// and that client_id is its signing certificate's x509_hash.
	authReq, err := w.FetchAuthorizationRequest(ctx, requestURI, clientID)
	if err != nil {
		return nil, fmt.Errorf("walletapp: presentation request: %w", err)
	}

	p := &Prepared{VerifierClientID: authReq.ClientID, ResponseURI: authReq.ResponseURI, authReq: authReq, store: store, http: httpClient}
	byID := make(map[string][][]string, len(authReq.Query.Credentials))
	for _, cq := range authReq.Query.Credentials {
		for _, c := range cq.Claims {
			path := make([]string, len(c.Path))
			for i, el := range c.Path {
				path[i] = el.Key()
			}
			byID[cq.ID] = append(byID[cq.ID], path)
		}
	}
	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		held, err := heldCredentials(store, format)
		if err != nil {
			continue
		}
		matches, err := wallet.MatchDCQLQuery(ctx, authReq.Query, held, nil)
		if err != nil {
			continue
		}
		for id := range matches {
			p.Options = append(p.Options, Option{Format: format, QueryID: id, Claims: byID[id]})
		}
	}
	if len(p.Options) == 0 {
		return nil, fmt.Errorf("walletapp: no stored credential satisfies the request")
	}
	return p, nil
}

// Send answers the request with the stored credential of format ("" for
// whichever matches first): it builds selectively disclosed
// presentations bound to the verifier's nonce and POSTs them to the
// response_uri as an encrypted direct_post.jwt response.
func (p *Prepared) Send(ctx context.Context, format string) (Presented, error) {
	held, err := heldCredentials(p.store, format)
	if err != nil {
		return Presented{}, err
	}
	a := p.authReq
	vpToken, err := wallet.PresentCredentials(ctx, wallet.PresentationRequest{
		Query: a.Query, Credentials: held, Audience: a.ClientID, Nonce: a.Nonce,
		ResponseURI: a.ResponseURI, ResponseEncryptionKey: a.ResponseEncryptionKey,
	})
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: no stored credential satisfies the request: %w", err)
	}
	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: a.State,
		EncryptionKey: a.ResponseEncryptionKey, EncryptionKeyID: a.ResponseEncryptionKeyID,
		EncryptionEnc: a.ResponseEncryptionEnc,
	})
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: presentation response: %w", err)
	}
	if err := postResponse(ctx, p.http, a.ResponseURI, responseJWE); err != nil {
		return Presented{}, err
	}
	presented := Presented{VerifierClientID: a.ClientID}
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
