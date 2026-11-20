// Package defaulttransport gives the library's HTTP clients a copy of
// http.DefaultTransport to build on, whatever the program has replaced
// it with.
package defaulttransport

import (
	"net"
	"net/http"
	"time"
)

// Clone returns a copy of http.DefaultTransport when it's an
// *http.Transport, as it is unless the program replaced it, and
// otherwise a new transport with the settings Go gives
// http.DefaultTransport. A program that wraps http.DefaultTransport (to
// trace its requests, say) then doesn't make a client that needs an
// *http.Transport fail, or panic: that client's requests bypass the
// wrapper instead.
func Clone() *http.Transport {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}
