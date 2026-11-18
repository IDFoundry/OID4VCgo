package demotls

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// defaultPort is the port a Host header without one names: every demo
// server is HTTPS.
const defaultPort = "443"

// ServedHosts are the names a server listening on addr and known by
// urls answers to, as a browser's Host header names them (host:port,
// lower case): each URL's host, and the address itself. A loopback or
// unspecified address adds this machine's loopback names for its port —
// 127.0.0.1 and localhost, and [::1] unless the address is IPv4
// loopback.
func ServedHosts(addr string, urls ...string) []string {
	var hosts []string
	add := func(hostport string) {
		if h := canonicalHost(hostport); !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			add(u.Host)
		}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return hosts
	}
	ip := net.ParseIP(host)
	switch {
	case host == "" || host == "localhost" || ip.IsUnspecified() || ip.IsLoopback():
		add(net.JoinHostPort("127.0.0.1", port))
		add(net.JoinHostPort("localhost", port))
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
			add(net.JoinHostPort("::1", port))
		}
		if ip.IsLoopback() {
			add(addr)
		}
	default:
		add(addr)
	}
	return hosts
}

// canonicalHost is hostport as ServedHosts lists it: lower case, with
// the default port when it names none.
func canonicalHost(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"), defaultPort
	}
	return net.JoinHostPort(strings.ToLower(host), port)
}

// HostGuard returns next, refusing (421 Misdirected Request) a request
// whose Host isn't one of hosts (ServedHosts). A page at another name
// that its DNS rebinds to this machine's loopback address reaches the
// demo's servers with its own name as the Host: refused, it can read
// nothing of theirs, whether or not the browser accepts the
// certificate for that name.
func HostGuard(next http.Handler, hosts []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" || !slices.Contains(hosts, canonicalHost(r.Host)) {
			log.Printf("demotls: 421 for Host %q", r.Host) // #nosec G706 -- quoted: a request can't forge a log line
			http.Error(w, "this server doesn't serve that host name", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
