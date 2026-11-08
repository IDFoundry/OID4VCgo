package main

import (
	"net/http"
	"regexp"
	"sync"
)

// exchange is one HTTP exchange the wallet made, as the run reports it:
// no query, header value or body, only what shows which protocol
// features were used.
type exchange struct {
	Method      string `json:"method"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	// DPoP and Attestation report whether the request carried a DPoP
	// proof and a Wallet Attestation (with its PoP).
	DPoP        bool `json:"dpop,omitempty"`
	Attestation bool `json:"attestation,omitempty"`
	// DPoPNonce reports whether the response handed out a DPoP-Nonce,
	// and Error the error code its WWW-Authenticate header named, if
	// any (use_dpop_nonce, say).
	DPoPNonce bool   `json:"dpop_nonce,omitempty"`
	Error     string `json:"www_authenticate_error,omitempty"`
}

// recorder is an http.RoundTripper recording each exchange.
type recorder struct {
	next http.RoundTripper

	mu        sync.Mutex
	exchanges []exchange
}

var wwwAuthenticateError = regexp.MustCompile(`error="([^"]*)"`)

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := r.next.RoundTrip(req)
	e := exchange{
		Method:      req.Method,
		Host:        req.URL.Host,
		Path:        req.URL.Path,
		DPoP:        req.Header.Get("DPoP") != "",
		Attestation: req.Header.Get("OAuth-Client-Attestation") != "" && req.Header.Get("OAuth-Client-Attestation-PoP") != "",
	}
	if err == nil {
		e.Status = res.StatusCode
		e.ContentType = res.Header.Get("Content-Type")
		e.DPoPNonce = res.Header.Get("DPoP-Nonce") != ""
		if m := wwwAuthenticateError.FindStringSubmatch(res.Header.Get("WWW-Authenticate")); m != nil {
			e.Error = m[1]
		}
	}
	r.mu.Lock()
	r.exchanges = append(r.exchanges, e)
	r.mu.Unlock()
	return res, err
}

// recorded is a copy of the exchanges so far.
func (r *recorder) recorded() []exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]exchange(nil), r.exchanges...)
}

// count is how many recorded exchanges match.
func (r *recorder) count(match func(exchange) bool) int {
	n := 0
	for _, e := range r.recorded() {
		if match(e) {
			n++
		}
	}
	return n
}
