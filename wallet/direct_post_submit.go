package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/idfoundry/fapigo/fapihttp"
)

// maxDirectPostReplyBytes bounds the Verifier's reply to a direct_post
// submission: a small JSON object (OID4VP §8.2).
const maxDirectPostReplyBytes = 64 << 10

// maxReplyTextRunes bounds each Verifier-supplied error string kept in
// a DirectPostRejectedError, which callers are likely to log.
const maxReplyTextRunes = 256

// DirectPostResult is the Verifier's reply to an Authorization Response
// sent with SubmitDirectPostResponse (OID4VP §8.2).
type DirectPostResult struct {
	// RedirectURI, when the Verifier returned one, is where the Wallet
	// MUST now send the user agent — the same-device flow's way back to
	// the Verifier (§8.2; HAIP 1.0 §5.1 requires Wallets to follow it).
	// It is an absolute https URL: anything else is refused.
	RedirectURI string
}

// DirectPostRejectedError is returned by SubmitDirectPostResponse when
// the Verifier's Response Endpoint answers with anything but 200.
type DirectPostRejectedError struct {
	StatusCode int
	// Code and Description are the reply's "error"/"error_description",
	// when it carried them — Verifier-supplied text, so control
	// characters are dropped and each is cut to maxReplyTextRunes.
	Code        string
	Description string
}

func (e *DirectPostRejectedError) Error() string {
	return fmt.Sprintf("wallet: verifier rejected the authorization response: status %d %s %s", e.StatusCode, e.Code, e.Description)
}

// SubmitDirectPostResponse POSTs an encrypted Authorization Response —
// from BuildDirectPostResponse or BuildDirectPostErrorResponse — to
// the Verifier's response_uri as response mode direct_post.jwt's
// "response" form parameter (OID4VP §8.3.1), and returns the Verifier's
// reply (§8.2): on success, the redirect_uri to send the user agent to,
// if any; otherwise a *DirectPostRejectedError.
//
// responseURI is AuthorizationRequest.ResponseURI, from a Request
// Object ParseAuthorizationRequest has verified; client performs the
// POST.
func SubmitDirectPostResponse(ctx context.Context, client fapihttp.HTTPClient, responseURI, responseJWE string) (DirectPostResult, error) {
	form := url.Values{"response": {responseJWE}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURI, strings.NewReader(form.Encode()))
	if err != nil {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectPostReplyBytes+1))
	if err != nil {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: read reply: %w", err)
	}
	if len(body) > maxDirectPostReplyBytes {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: reply exceeds %d bytes", maxDirectPostReplyBytes)
	}

	isJSON := false
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil {
		isJSON = mediaType == "application/json"
	}
	if resp.StatusCode != http.StatusOK {
		rejected := &DirectPostRejectedError{StatusCode: resp.StatusCode}
		if isJSON {
			var e struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if json.Unmarshal(body, &e) == nil {
				rejected.Code, rejected.Description = sanitizeReplyText(e.Error), sanitizeReplyText(e.Description)
			}
		}
		return DirectPostResult{}, rejected
	}
	// §8.2 has the reply be a JSON object; one that isn't JSON at all is
	// accepted as carrying no redirect_uri.
	if !isJSON || len(body) == 0 {
		return DirectPostResult{}, nil
	}
	var reply struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: parse reply: %w", err)
	}
	if reply.RedirectURI == "" {
		return DirectPostResult{}, nil
	}
	if u, err := url.Parse(reply.RedirectURI); err != nil || u.Scheme != "https" || u.Host == "" {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: redirect_uri %q isn't an absolute https URL", reply.RedirectURI)
	}
	return DirectPostResult{RedirectURI: reply.RedirectURI}, nil
}

// sanitizeReplyText drops control characters from Verifier-supplied
// text and cuts it to maxReplyTextRunes, so it can't forge log lines or
// flood them.
func sanitizeReplyText(text string) string {
	var b strings.Builder
	n := 0
	for _, r := range text {
		if unicode.IsControl(r) {
			continue
		}
		if n == maxReplyTextRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
