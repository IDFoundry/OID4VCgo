package walletflow

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// validateAllowedPrivateHosts refuses a Config.AllowedPrivateHosts entry
// that isn't a host name: empty, an IP address (the allowance is for
// named hosts, never an address), a pattern (no wildcards: each host is
// matched exactly), a name with a port or a trailing dot, or a loopback
// name (localhost, or one under .localhost), which the allowance never
// lets the wallet dial.
func (c Config) validateAllowedPrivateHosts() error {
	for _, host := range c.AllowedPrivateHosts {
		name := strings.TrimSuffix(strings.ToLower(host), ".")
		switch {
		case host == "" || strings.ContainsAny(host, "*/:@[]% ") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, "."):
			return fmt.Errorf("walletflow: Config.AllowedPrivateHosts: %q isn't a host name: name each host exactly, with no wildcard, port or trailing dot", host)
		case net.ParseIP(host) != nil:
			return fmt.Errorf("walletflow: Config.AllowedPrivateHosts: %q is an IP address: name the host, whose resolved private addresses are then allowed", host)
		case name == "localhost" || strings.HasSuffix(name, ".localhost"):
			return fmt.Errorf("walletflow: Config.AllowedPrivateHosts: %q is a loopback name, which the wallet never dials outside Development", host)
		}
	}
	return nil
}

// checkCallersPrivateHosts refuses, outside Development, a
// Config.AllowedPrivateHosts the caller's Dependencies.HTTP doesn't
// allow exactly: that client's transport decides what its token,
// Credential and response requests dial, and the wallet's own fetches
// and status lists go by Config's, so the two must agree for every
// request to be held to one list. A client fapihttp.HardeningOf doesn't
// recognise is wallet.New's to refuse.
func checkCallersPrivateHosts(cfg Config, given *http.Client) error {
	if cfg.Development || given == nil || len(cfg.AllowedPrivateHosts) == 0 {
		return nil
	}
	h, ok := fapihttp.HardeningOf(given)
	if !ok {
		return nil
	}
	if !sameHosts(h.AllowedPrivateHosts(), cfg.AllowedPrivateHosts) {
		return errors.New("walletflow: Config.AllowedPrivateHosts must be the hosts Dependencies.HTTP's transport allows: build it with fapihttp.NewClient and TransportConfig.AllowedPrivateHosts set to the same list")
	}
	return nil
}

// sameHosts reports whether a and b name the same hosts, without case.
func sameHosts(a, b []string) bool {
	fold := func(hosts []string) []string {
		out := make([]string, len(hosts))
		for i, h := range hosts {
			out[i] = strings.ToLower(h)
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(fold(a), fold(b))
}

// statusHTTP is the client the wallet fetches status and identifier
// lists with when Config.AllowedPrivateHosts names hosts and its HTTP
// client is fapihttp's hardened one: that client, its transport wrapped
// so statuslist.Fetcher uses it as it is (UncheckedTransport) rather
// than replacing its dialer with statuslist's own address policy, which
// can allow private addresses only all together. The hardened dialer
// then applies its own policy: public addresses, and private ones of the
// listed hosts alone, checked on the address it dials, so a name that
// resolves elsewhere by the time it's dialled is refused too. nil, with
// no hosts listed or another client (Development's), keeps statuslist's
// policy.
func statusHTTP(cfg Config, client *http.Client) *http.Client {
	if len(cfg.AllowedPrivateHosts) == 0 {
		return nil
	}
	if _, ok := fapihttp.HardeningOf(client); !ok {
		return nil
	}
	wrapped := *client
	wrapped.Transport = hardenedTransport{client.Transport}
	return &wrapped
}

// hardenedTransport is fapihttp.NewClient's transport, hidden from
// statuslist.Fetcher's *http.Transport check so it keeps its own
// dial-time address policy.
type hardenedTransport struct{ http.RoundTripper }

// statusFetcher is the Fetcher status and identifier lists are fetched
// with, reading at most maxBytes: through statusHTTP when there is one;
// otherwise the wallet's client under statuslist's own address policy,
// loopback allowed in Development, and private addresses too there when
// Config.AllowedPrivateHosts names hosts, as Development's client
// reaches them for every other request.
func (w *Wallet) statusFetcher(maxBytes int) statuslist.Fetcher {
	if w.statusHTTP != nil {
		return statuslist.Fetcher{HTTP: w.statusHTTP, UncheckedTransport: true, MaxBytes: maxBytes}
	}
	return statuslist.Fetcher{
		HTTP: w.deps.HTTP, MaxBytes: maxBytes,
		AllowLoopback: w.cfg.Development, AllowPrivate: w.cfg.Development && len(w.cfg.AllowedPrivateHosts) > 0,
	}
}
