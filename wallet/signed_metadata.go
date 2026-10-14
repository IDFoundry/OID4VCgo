package wallet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// signedMetadataTyp is a signed Credential Issuer Metadata JWT's "typ"
// (OpenID4VCI §12.2.3).
const signedMetadataTyp = "openidvci-issuer-metadata+jwt"

// maxSignedMetadataClockSkew is how far a signed metadata JWT's iat may
// be ahead of the Wallet's clock.
const maxSignedMetadataClockSkew = time.Minute

// newSignedMetadataFetcher is the Wallet's fetcher with an Accept header
// asking for signed metadata ahead of plain JSON (OpenID4VCI §12.2.2):
// the same hardened transport and limits, one header more.
func newSignedMetadataFetcher(client fapihttp.HTTPClient, cfg fapihttp.Config) (*fapihttp.Client, error) {
	if hc, ok := client.(*http.Client); ok {
		accepting := *hc
		base := hc.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		accepting.Transport = acceptSignedMetadata{base}
		return fapihttp.New(&accepting, cfg)
	}
	return fapihttp.New(acceptSignedMetadataClient{client}, cfg)
}

const acceptSignedMetadataHeader = "application/jwt, application/json;q=0.5"

type acceptSignedMetadata struct{ base http.RoundTripper }

func (a acceptSignedMetadata) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Accept", acceptSignedMetadataHeader)
	return a.base.RoundTrip(req)
}

type acceptSignedMetadataClient struct{ base fapihttp.HTTPClient }

func (a acceptSignedMetadataClient) Do(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Accept", acceptSignedMetadataHeader)
	return a.base.Do(req)
}

// metadataJSON returns a fetched metadata body as JSON: a signed
// response's verified claims, or a plain JSON body, refused when
// Config.RequireSignedIssuerMetadata is set. The body's shape decides,
// not its Content-Type, since the signature is what's trusted: a JSON
// document starts with "{", a compact JWT never does.
func (w *Wallet) metadataJSON(body []byte, issuerURL string) ([]byte, error) {
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		if w.cfg.RequireSignedIssuerMetadata {
			return nil, errors.New("the issuer sent unsigned metadata, and require_signed_issuer_metadata is set")
		}
		return body, nil
	}
	if w.cfg.IssuerMetadataRoots == nil {
		return nil, errors.New("the issuer sent signed metadata, and issuer_metadata_roots is not set to verify it")
	}
	return w.verifySignedMetadata(string(bytes.TrimSpace(body)), issuerURL)
}

// verifySignedMetadata verifies a signed Credential Issuer Metadata JWT
// (OpenID4VCI §12.2.3, HAIP 1.0 §4.1) and returns its metadata members
// as JSON. It checks:
//   - its typ;
//   - a signature by the key of an x5c leaf chaining to
//     Config.IssuerMetadataRoots ("the Wallet MUST establish trust in
//     the signer of the metadata");
//   - sub naming the issuer;
//   - an iat that isn't in the future, and an exp, when present, not
//     past.
func (w *Wallet) verifySignedMetadata(token, issuerURL string) ([]byte, error) {
	header, _, err := jose.DecodeUnverifiedMax(token, int(w.cfg.Fetch.MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != signedMetadataTyp {
		return nil, fmt.Errorf("signed metadata: typ %q, want %q", header["typ"], signedMetadataTyp)
	}
	x5c, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	leaf, err := certchain.VerifyLeaf(x5c, w.cfg.IssuerMetadataRoots)
	if err != nil {
		return nil, fmt.Errorf("signed metadata: signer certificate: %w", err)
	}
	if certchain.IsSelfSigned(leaf) {
		return nil, errors.New("signed metadata: the signer certificate is self-signed")
	}
	alg, _ := header["alg"].(string)
	if !jose.IsSupported(jose.Alg(alg)) {
		return nil, fmt.Errorf("signed metadata: alg %q is not supported", alg)
	}
	_, payload, err := jose.VerifyMax(jose.Alg(alg), leaf.PublicKey, token, int(w.cfg.Fetch.MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("signed metadata: claims: %w", err)
	}
	if err := w.checkSignedMetadataClaims(claims, issuerURL); err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	// The JWT's own claims aren't metadata members.
	for _, name := range []string{"sub", "iat", "exp", "iss", "nbf"} {
		delete(claims, name)
	}
	return json.Marshal(claims)
}

// checkSignedMetadataClaims checks a signed metadata JWT's sub, iat and
// exp.
func (w *Wallet) checkSignedMetadataClaims(claims map[string]json.RawMessage, issuerURL string) error {
	var sub string
	if err := json.Unmarshal(claims["sub"], &sub); err != nil || sub != issuerURL {
		return fmt.Errorf("sub %s doesn't name the issuer %q", claims["sub"], issuerURL)
	}
	now := w.deps.Clock.Now()
	var iat int64
	if err := json.Unmarshal(claims["iat"], &iat); err != nil {
		return errors.New("iat is missing or not a number")
	}
	if time.Unix(iat, 0).After(now.Add(maxSignedMetadataClockSkew)) {
		return errors.New("iat is in the future")
	}
	if raw, present := claims["exp"]; present {
		var exp int64
		if err := json.Unmarshal(raw, &exp); err != nil || !time.Unix(exp, 0).After(now) {
			return errors.New("expired")
		}
	}
	return nil
}
