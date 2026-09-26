package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo"
)

// FetchCredentialIssuerMetadata fetches and decodes issuerURL's own
// Credential Issuer Metadata (§12.2, via a hardened, SSRF-resistant GET
// — fapihttp.Client.Fetch, the same transport ResolveCredentialOffer's
// own by-reference fetch uses) — §12.2.2's own well-known URL
// convention: "/.well-known/openid-credential-issuer" is inserted
// BEFORE issuerURL's own path component, not appended after it (any
// trailing "/" is kept, unlike RFC 8414 §3.1).
//
// The metadata's credential_issuer must be identical to issuerURL
// (§12.2.4: "If these values are not identical (when compared using a
// simple string comparison with no normalization), the data contained
// in the response MUST NOT be used") — otherwise a Credential Issuer
// could vouch for metadata naming another issuer.
func (w *Wallet) FetchCredentialIssuerMetadata(ctx context.Context, issuerURL string) (oid4vci.Metadata, error) {
	target, err := wellKnownURL(issuerURL, "openid-credential-issuer", false)
	if err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("wallet: fetch credential issuer metadata: %w", err)
	}
	res, err := w.fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: "application/json"})
	if err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("wallet: fetch credential issuer metadata: %w", err)
	}
	// Honor Config.Fetch.AllowLoopbackHTTP when decoding too, not just
	// when fetching: otherwise a local http://127.0.0.1 issuer's
	// metadata downloads fine and then fails to decode, since its URLs
	// aren't https.
	// Compared on the raw JSON string, before DecodeMetadata parses it
	// as a URL: §12.2.4's comparison allows no normalization.
	var identity struct {
		CredentialIssuer string `json:"credential_issuer"`
	}
	if err := json.Unmarshal(res.Body, &identity); err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("wallet: fetch credential issuer metadata: decode: %w", err)
	}
	if identity.CredentialIssuer != issuerURL {
		return oid4vci.Metadata{}, fmt.Errorf("wallet: fetch credential issuer metadata: credential_issuer %q is not the issuer %q it was fetched for", identity.CredentialIssuer, issuerURL)
	}
	var opts []fapi.URLOption
	if w.cfg.Fetch.AllowLoopbackHTTP {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	meta, err := oid4vci.DecodeMetadata(res.Body, opts...)
	if err != nil {
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
// convention: any terminating "/" is removed from issuerURL's path, and
// "/.well-known/oauth-authorization-server" is inserted BEFORE that
// path, not appended after it. The metadata's issuer must be identical
// to issuerURL (RFC 8414 §3.3: "If these values are not identical, the
// data contained in the response MUST NOT be used") — the value the
// Wallet then expects as the authorization response's iss (RFC 9207),
// so a mismatch here would defeat mix-up protection.
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
	target, err := wellKnownURL(issuerURL, "oauth-authorization-server", true)
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
	if meta.Issuer != issuerURL {
		return AuthorizationServerMetadata{}, fmt.Errorf("wallet: fetch authorization server metadata: issuer %q is not the issuer %q it was fetched for", meta.Issuer, issuerURL)
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
// follows (§12.2.2) for an Issuer whose identifier carries a path.
// stripTrailingSlash removes a terminating "/" from that path first, as
// RFC 8414 §3.1 requires for Authorization Server Metadata; OID4VCI's
// own well-known URL keeps it.
func wellKnownURL(issuerURL, suffix string, stripTrailingSlash bool) (*url.URL, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("parse issuer url: %w", err)
	}
	path := u.Path
	if stripTrailingSlash {
		path = strings.TrimSuffix(path, "/")
	}
	u.Path = "/.well-known/" + suffix + path
	u.RawPath = ""
	return u, nil
}
