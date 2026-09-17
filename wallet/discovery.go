package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcigo"
)

// FetchCredentialIssuerMetadata fetches and decodes issuerURL's own
// Credential Issuer Metadata (§12.2, via a hardened, SSRF-resistant GET
// — fapihttp.Client.Fetch, the same transport ResolveCredentialOffer's
// own by-reference fetch uses) — §11.2.1's own well-known URL
// convention: "/.well-known/openid-credential-issuer" is inserted
// BEFORE issuerURL's own path component, not appended after it, the
// same RFC 8414 §3.1 rule FetchAuthorizationServerMetadata follows.
func (w *Wallet) FetchCredentialIssuerMetadata(ctx context.Context, issuerURL string) (oid4vci.Metadata, error) {
	target, err := wellKnownURL(issuerURL, "openid-credential-issuer")
	if err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("wallet: fetch credential issuer metadata: %w", err)
	}
	res, err := w.fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: "application/json"})
	if err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("wallet: fetch credential issuer metadata: %w", err)
	}
	var meta oid4vci.Metadata
	if err := json.Unmarshal(res.Body, &meta); err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("wallet: fetch credential issuer metadata: decode: %w", err)
	}
	return meta, nil
}

// AuthorizationServerMetadata is the RFC 8414 subset a Wallet needs to
// drive the Authorization Code Flow against a plain-OAuth (non-OIDC)
// Authorization Server — see FetchAuthorizationServerMetadata's own
// doc comment for why this package fetches it directly rather than
// going through fapigo/client.Discover.
type AuthorizationServerMetadata struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
}

// FetchAuthorizationServerMetadata fetches and decodes issuerURL's own
// Authorization Server Metadata — RFC 8414 §3.1's own well-known URL
// convention: "/.well-known/oauth-authorization-server" is inserted
// BEFORE issuerURL's own path component, not appended after it.
//
// fapigo/client.Discover doesn't support this: its own doc comment
// explains it deliberately only speaks OIDC Discovery's own
// append-after-path convention (".well-known/openid-configuration"),
// acknowledging RFC 8414 §3.1's insert-before-path algorithm as a gap.
// A Wallet targeting a plain-OAuth (non-OIDC) Authorization Server —
// HAIP's own FAPIOpenIDConnect=plain_oauth profile, which this
// package's own RequestPreAuthorizedCodeToken and
// BuildAuthorizationRequest calls already assume — needs this instead.
func (w *Wallet) FetchAuthorizationServerMetadata(ctx context.Context, issuerURL string) (AuthorizationServerMetadata, error) {
	target, err := wellKnownURL(issuerURL, "oauth-authorization-server")
	if err != nil {
		return AuthorizationServerMetadata{}, fmt.Errorf("wallet: fetch authorization server metadata: %w", err)
	}
	res, err := w.fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: "application/json"})
	if err != nil {
		return AuthorizationServerMetadata{}, fmt.Errorf("wallet: fetch authorization server metadata: %w", err)
	}
	var meta AuthorizationServerMetadata
	if err := json.Unmarshal(res.Body, &meta); err != nil {
		return AuthorizationServerMetadata{}, fmt.Errorf("wallet: fetch authorization server metadata: decode: %w", err)
	}
	return meta, nil
}

// wellKnownURL builds a RFC 8414 §3.1-style well-known URL for
// issuerURL, a URL that may itself carry a path component (e.g. the
// OIDF conformance suite's own module base URL,
// "https://host/test/a/<alias>"): "/.well-known/<suffix>" is inserted
// *before* that path, not appended after it —
// "https://host/.well-known/<suffix>/test/a/<alias>" — the same
// insertion rule OID4VCI's own Credential Issuer Metadata discovery
// follows (§11.2.1) for an Issuer whose identifier carries a path.
func wellKnownURL(issuerURL, suffix string) (*url.URL, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("parse issuer url: %w", err)
	}
	u.Path = "/.well-known/" + suffix + u.Path
	return u, nil
}
