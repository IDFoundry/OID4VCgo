package statuslist

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Fetcher fetches Status List Tokens (draft-14 §8.1): an HTTPS GET of a
// Referenced Token's status_list uri, asking for one token format.
//
// It fetches exactly the uri given — https only, redirects refused —
// and accepts only a 2xx response of the requested media type, no
// larger than MaxBytes. A redirect is refused because the uri is what
// the Referenced Token's issuer signed; following one could leave https,
// or reach somewhere the issuer never named.
type Fetcher struct {
	// HTTP is the client fetches use, e.g. one trusting a private CA.
	// Nil means a client with a 30-second timeout. Its CheckRedirect is
	// overridden to refuse redirects.
	HTTP *http.Client

	// MaxBytes bounds a token's size; zero means 1 MiB.
	MaxBytes int
}

// Fetch GETs uri, asking for mediaType (TokenMediaType or
// CWTTokenMediaType), and returns the token's bytes.
func (f Fetcher) Fetch(ctx context.Context, uri, mediaType string) ([]byte, error) {
	if u, err := url.Parse(uri); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("statuslist: status list uri %q isn't an https URL", uri)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("statuslist: fetch: %w", err)
	}
	req.Header.Set("Accept", mediaType)
	client := http.Client{Timeout: 30 * time.Second}
	if f.HTTP != nil {
		client = *f.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("statuslist: fetch %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("statuslist: fetch %s: HTTP %d", uri, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != mediaType {
		return nil, fmt.Errorf("statuslist: fetch %s: content type %q, want %q", uri, got, mediaType)
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = maxTokenBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("statuslist: fetch %s: %w", uri, err)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("statuslist: fetch %s: token exceeds %d bytes", uri, limit)
	}
	return body, nil
}

// Checker checks a Referenced Token's status end to end (draft-14
// §8.3): it fetches the Status List Token its reference names, then
// verifies it with CheckX5C or CheckCWTX5Chain — its signer's
// certificate chain to Roots, its sub against the reference, and the
// status at the reference's index.
type Checker struct {
	Fetcher Fetcher

	// Roots are the trust anchors for Status List Token signers,
	// REQUIRED — normally the same anchors the Referenced Tokens'
	// issuers chain to. Options.LeafPolicy can narrow them further.
	Roots *x509.CertPool

	Options VerifyOptions
}

// Check fetches and checks the Status List Token ref names: the CWT
// form when cwt is true (an mdoc's reference), the JWT form otherwise
// (an SD-JWT VC's — SD-JWT VC requires a JWT Status List Token).
func (c Checker) Check(ctx context.Context, ref StatusListRef, cwt bool) (StatusType, TokenClaims, error) {
	if c.Roots == nil {
		return 0, TokenClaims{}, errors.New("statuslist: Checker.Roots is required")
	}
	mediaType := TokenMediaType
	if cwt {
		mediaType = CWTTokenMediaType
	}
	token, err := c.Fetcher.Fetch(ctx, ref.URI, mediaType)
	if err != nil {
		return 0, TokenClaims{}, err
	}
	if cwt {
		return CheckCWTX5Chain(token, c.Roots, ref, c.Options)
	}
	return CheckX5C(string(token), c.Roots, ref, c.Options)
}
