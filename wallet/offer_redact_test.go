package wallet_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A malformed offer link's error never carries the link, which may hold
// a pre-authorized code; it's still a *url.Error, so callers can tell a
// malformed link.
func TestResolveCredentialOffer_ErrorOmitsTheLink(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("no request expected") })
	_, err := w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?credential_offer=SECRET-CODE\x01")
	var urlErr *url.Error
	if err == nil || strings.Contains(err.Error(), "SECRET-CODE") || !errors.As(err, &urlErr) {
		t.Errorf("err = %v; want a *url.Error without the link", err)
	}
}

// A by-reference offer's credential_offer_uri serves the offer, its
// pre-authorized code included, until the issuer retires it: a failed
// fetch's error never carries it, in its text or in the *url.Error it
// wraps, but keeps its cause, so callers still tell a refused
// connection or a timeout.
func TestResolveCredentialOffer_FetchErrorOmitsTheOfferURI(t *testing.T) {
	// A port nothing listens on: the connection is refused, as a TLS
	// failure, a reset or a timeout on a real network would fail it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second, AllowLoopbackHosts: true},
	}, wallet.Dependencies{Clock: wallet.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "q3Vx9-OFFER-REFERENCE"
	link := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape("https://"+addr+"/credential-offer/"+secret+"?code="+secret)

	_, err = w.ResolveCredentialOffer(context.Background(), link)
	assertURLRedacted(t, err, secret, "(the credential_offer_uri)", "Get")
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Errorf("err = %v; want the dial failure kept", err)
	}
}

// What a hardened transport's dial-time refusal or a timeout looks like
// from http.Client.Do: still found by errors.Is once the URL is gone.
func TestResolveCredentialOffer_FetchErrorKeepsItsCause(t *testing.T) {
	const secret = "OFFER-REF-7a1"
	for _, cause := range []error{fapihttp.ErrSSRFBlocked, context.DeadlineExceeded} {
		w := newTestWallet(t, func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: fmt.Errorf("dial: %w", cause)}
		})
		link := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape("http://localhost/credential-offer/"+secret)
		_, err := w.ResolveCredentialOffer(context.Background(), link)
		assertURLRedacted(t, err, secret, "(the credential_offer_uri)", "Get")
		if !errors.Is(err, cause) {
			t.Errorf("err = %v; want it to wrap %v", err, cause)
		}
	}
	// url.Error's Timeout, which net.Error users rely on, is kept.
	w := newTestWallet(t, func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: timeoutError{}}
	})
	_, err := w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?credential_offer_uri="+url.QueryEscape("http://localhost/o/"+secret))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() || strings.Contains(err.Error(), secret) {
		t.Errorf("err = %v; want a redacted net.Error timeout", err)
	}
}

// The request_uri of an OpenID4VP invocation is redacted the same way,
// on a GET, on a POST, and when the link itself is malformed.
func TestFetchAuthorizationRequest_ErrorOmitsTheRequestURI(t *testing.T) {
	const secret = "REQUEST-REF-91c"
	w := newTestWalletTrusting(t, wallet.NoVerifierTrust{}, func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: req.Method[:1] + strings.ToLower(req.Method[1:]), URL: req.URL.String(), Err: fmt.Errorf("dial: %w", fapihttp.ErrSSRFBlocked)}
	})
	requestURI := "http://localhost/request/" + secret
	_, err := w.FetchAuthorizationRequest(context.Background(), requestURI, "x509_hash:abc")
	assertURLRedacted(t, err, secret, "(the request_uri)", "Get")
	if !errors.Is(err, fapihttp.ErrSSRFBlocked) {
		t.Errorf("GET: err = %v; want it to wrap ErrSSRFBlocked", err)
	}
	_, err = w.FetchAuthorizationRequestPost(context.Background(), requestURI, "x509_hash:abc", "wn-1", nil)
	assertURLRedacted(t, err, secret, "(the request_uri)", "Post")
	if !errors.Is(err, fapihttp.ErrSSRFBlocked) {
		t.Errorf("POST: err = %v; want it to wrap ErrSSRFBlocked", err)
	}

	_, err = wallet.ParseAuthorizationRequestLink("openid4vp://?client_id=x&request_uri=" + secret + "\x01")
	var urlErr *url.Error
	if err == nil || strings.Contains(err.Error(), secret) || !errors.As(err, &urlErr) || strings.Contains(urlErr.URL, secret) {
		t.Errorf("malformed link: err = %v; want a *url.Error without the link", err)
	}
	_, err = wallet.ParseAuthorizationRequestLink("openid4vp://?client_id=x&request_uri=" + url.QueryEscape("/request/"+secret))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("relative request_uri: err = %v; want an error without it", err)
	}
}

// assertURLRedacted fails unless err carries no trace of secret, and
// wraps a *url.Error with op whose URL is placeholder.
func assertURLRedacted(t *testing.T, err error, secret, placeholder, op string) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("err = %v; the URL is in its text", err)
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatalf("err = %v; want a *url.Error", err)
	}
	if urlErr.URL != placeholder || urlErr.Op != op {
		t.Errorf("*url.Error = {Op: %q, URL: %q}; want {Op: %q, URL: %q}", urlErr.Op, urlErr.URL, op, placeholder)
	}
	if !strings.Contains(err.Error(), placeholder) {
		t.Errorf("err = %v; want it to name %s", err, placeholder)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
