package wallet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
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
	// It is an absolute URI: an https page, or a scheme the Verifier's
	// own app registered. Plain http, one that runs code or reads local
	// data (javascript:, data:, file:, Android's intent:, content: and
	// android-app:), and one that opens a system handler rather than
	// the Verifier's page or app (an app install or store, a call, a
	// message, the settings, a Shortcut or a map: itms-services:,
	// market:, tel:, sms:, mailto:, ms-settings:, shortcuts:, geo: and
	// their like) are refused, and through a Wallet whose
	// Config.VerifierRedirectSchemes is set, any scheme but https and
	// those it names. Open a non-https one only through the platform's
	// handling of app links, never in a web view.
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

// Is reports a *DirectPostRejectedError as ErrResponseDelivered: the
// Verifier replied, so it received the response.
func (e *DirectPostRejectedError) Is(target error) bool { return target == ErrResponseDelivered }

// ErrResponseDelivered is matched (errors.Is) by an error
// SubmitDirectPostResponse returns after the Verifier replied, whatever
// it replied: a refusal, a redirect, a reply from elsewhere, or one it
// can't read. The response reached response_uri, so a caller treats it
// as presented: sending the same credential again, or another of its
// copies as unseen, would be linkable.
var ErrResponseDelivered = errors.New("the response reached the Verifier")

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
// POST. Redirects are never followed: §8.2's reply is a 200 carrying
// JSON, and following one would resend the response, and take the
// redirect_uri, from wherever it pointed — plain http included. A
// *http.Client is used with redirects turned off; for any other client,
// a reply that didn't come from responseURI itself is refused.
//
// response_uri is the Verifier's choice, and nothing here checks the
// address it reaches: in production, client must be one
// fapihttp.NewClient built, which refuses internal addresses when it
// dials, with a Timeout. (*Wallet).SubmitDirectPostResponse uses the
// Wallet's own client, which New has already checked, and refuses a
// redirect_uri its Config.VerifierRedirectSchemes doesn't allow too.
func SubmitDirectPostResponse(ctx context.Context, client fapihttp.HTTPClient, responseURI, responseJWE string) (DirectPostResult, error) {
	return submitDirectPostResponse(ctx, client, responseURI, responseJWE, nil)
}

// submitDirectPostResponse is SubmitDirectPostResponse, refusing a
// redirect_uri whose scheme is neither https nor among redirectSchemes
// when they're set (Config.VerifierRedirectSchemes).
func submitDirectPostResponse(ctx context.Context, client fapihttp.HTTPClient, responseURI, responseJWE string, redirectSchemes []string) (DirectPostResult, error) {
	form := url.Values{"response": {responseJWE}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURI, strings.NewReader(form.Encode()))
	if err != nil {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := doWithoutRedirects(client, req)
	if err != nil {
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	result, err := readDirectPostReply(resp, redirectSchemes)
	if err != nil {
		var rejected *DirectPostRejectedError
		if errors.As(err, &rejected) {
			return DirectPostResult{}, err
		}
		return DirectPostResult{}, fmt.Errorf("wallet: submit direct_post response: %w: %w", ErrResponseDelivered, err)
	}
	return result, nil
}

// SubmitDirectPostResponse is the package-level SubmitDirectPostResponse
// sent with this Wallet's own HTTP client (Dependencies.HTTP), so the
// POST to response_uri has the address checks and timeout New set up,
// and refusing a redirect_uri Config.VerifierRedirectSchemes doesn't
// allow.
func (w *Wallet) SubmitDirectPostResponse(ctx context.Context, responseURI, responseJWE string) (DirectPostResult, error) {
	return submitDirectPostResponse(ctx, w.deps.HTTP, responseURI, responseJWE, w.cfg.VerifierRedirectSchemes)
}

// readDirectPostReply reads the Verifier's reply to a direct_post
// response (§8.2), refusing a redirect_uri the Wallet doesn't follow
// (followable).
func readDirectPostReply(resp *http.Response, redirectSchemes []string) (DirectPostResult, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectPostReplyBytes+1))
	if err != nil {
		return DirectPostResult{}, fmt.Errorf("read reply: %w", err)
	}
	if len(body) > maxDirectPostReplyBytes {
		return DirectPostResult{}, fmt.Errorf("reply exceeds %d bytes", maxDirectPostReplyBytes)
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
			if strictjson.Unmarshal(body, &e) == nil {
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
	if err := strictjson.Unmarshal(body, &reply); err != nil {
		return DirectPostResult{}, fmt.Errorf("parse reply: %w", err)
	}
	if reply.RedirectURI == "" {
		return DirectPostResult{}, nil
	}
	if err := followable(reply.RedirectURI, redirectSchemes); err != nil {
		return DirectPostResult{}, err
	}
	return DirectPostResult{RedirectURI: reply.RedirectURI}, nil
}

// followable refuses redirectURI unless the Wallet follows it. OpenID4VP
// §8.2: "an absolute URI", which HAIP 1.0 §5.1 has the Wallet follow:
// an https page, or the Verifier's own app's scheme. Not one that runs
// code or reads local data in what opens it, invokes a Wallet or opens
// a system handler (unsafeRedirectSchemes); and with redirectSchemes
// set (Config.VerifierRedirectSchemes, in lower case), only https or
// one of them.
func followable(redirectURI string, redirectSchemes []string) error {
	u, err := url.Parse(redirectURI)
	if err != nil || !u.IsAbs() || unsafeRedirectSchemes[strings.ToLower(u.Scheme)] {
		return fmt.Errorf("redirect_uri %q isn't an absolute URI the Wallet can follow", redirectURI)
	}
	if scheme := strings.ToLower(u.Scheme); len(redirectSchemes) > 0 && scheme != "https" && !slices.Contains(redirectSchemes, scheme) {
		return fmt.Errorf("redirect_uri %q has a scheme the Wallet doesn't allow (Config.VerifierRedirectSchemes)", redirectURI)
	}
	return nil
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

// doWithoutRedirects performs req with client, never following a
// redirect: a *http.Client is copied with redirects turned off, and a
// reply that is itself a redirect, or that another client took from
// anywhere but req's URL, is an error.
func doWithoutRedirects(client fapihttp.HTTPClient, req *http.Request) (*http.Response, error) {
	if hc, ok := client.(*http.Client); ok {
		noRedirects := *hc
		noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &noRedirects
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: response_uri answered with a redirect (status %d), which isn't followed", ErrResponseDelivered, resp.StatusCode)
	case resp.Request != nil && resp.Request.URL.String() != req.URL.String():
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: the reply came from %q, not response_uri", ErrResponseDelivered, resp.Request.URL.Redacted())
	}
	return resp, nil
}

// unsafeRedirectSchemes are the URI schemes a redirect_uri may not
// have: each runs code, or reads local data, in whatever opens it —
// Android's among them: intent: launches any app component, with
// whatever extras the Verifier chose, android-app: an app the Verifier
// names, and content: reads a content provider's data. Plain http too: HAIP requires TLS, and a same-device return over it
// could be read or rewritten on the way. And the schemes that invoke a
// Wallet (OpenID4VP 1.0 §13.1.1, OpenID4VCI 1.0 §4.1, HAIP 1.0 §5 and
// §4.1, ISO/IEC 18013-7 Annex B's mdoc-openid4vp, the EUDI Wallet's
// eudi-openid4vp): a Verifier's redirect back is to its own page or
// app, and one to a Wallet's scheme would start another presentation
// or issuance straight after the holder consented to this one.
// walletflow refuses the Wallet's own redirect URI's scheme too.
//
// And the schemes that open a system handler rather than a Verifier's
// page or app, where an honest Verifier never sends the holder after a
// presentation, but where a redirect straight after the holder opened a
// link, or consented, looks like the Wallet's own next step: an app's
// install prompt or store page (iOS's itms-services:, itms-apps: and
// itms-appss:, Android's market:, Windows's ms-appinstaller: and
// ms-windows-store:), a call (tel:, and iOS's facetime: and
// facetime-audio:), a message (sms:, and Android's smsto:, mms: and
// mmsto:; mailto:), the settings (Windows's ms-settings:), a Shortcut
// run (iOS's shortcuts:) or a map (geo:, and iOS's maps:). A Verifier's
// own app's scheme is still followed.
var unsafeRedirectSchemes = map[string]bool{
	"http": true, "javascript": true, "data": true, "file": true, "vbscript": true, "blob": true, "about": true,
	"intent": true, "android-app": true, "content": true,
	"openid4vp": true, "haip-vp": true, "openid-credential-offer": true, "haip-vci": true,
	"mdoc-openid4vp": true, "eudi-openid4vp": true,
	"itms-services": true, "itms-apps": true, "itms-appss": true, "market": true, "ms-appinstaller": true, "ms-windows-store": true,
	"tel": true, "facetime": true, "facetime-audio": true,
	"sms": true, "smsto": true, "mms": true, "mmsto": true, "mailto": true,
	"ms-settings": true, "shortcuts": true, "geo": true, "maps": true,
}

// checkVerifierRedirectSchemes refuses a Config.VerifierRedirectSchemes
// entry that isn't a URI scheme (RFC 3986 §3.1), or that names one the
// Wallet never follows (unsafeRedirectSchemes), and returns the schemes
// in lower case; nil when there are none.
func checkVerifierRedirectSchemes(schemes []string) ([]string, error) {
	if len(schemes) == 0 {
		return nil, nil
	}
	lower := make([]string, len(schemes))
	for i, scheme := range schemes {
		if !isURIScheme(scheme) {
			return nil, fmt.Errorf("wallet: config: verifier_redirect_schemes: %q isn't a URI scheme", scheme)
		}
		lower[i] = strings.ToLower(scheme)
		if unsafeRedirectSchemes[lower[i]] {
			return nil, fmt.Errorf("wallet: config: verifier_redirect_schemes: a redirect_uri with the scheme %q is never followed", scheme)
		}
	}
	return lower, nil
}

// isURIScheme reports whether s is a URI scheme: a letter, then
// letters, digits, "+", "-" and "." (RFC 3986 §3.1).
func isURIScheme(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return s != ""
}
