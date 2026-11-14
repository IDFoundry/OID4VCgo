// Command splitproxy puts two instances of one of OID4VCgo's servers
// (an issuer's, or a verifier's) behind one HTTPS URL, as a load
// balancer does, and splits the requests between them deliberately,
// so that what one instance issues another must accept: an interop
// run's two-instance leg. It terminates TLS with the server's own
// certificate, and dials each instance over TLS.
//
//	splitproxy -addr 127.0.0.1:PORT -cert cert.pem -key key.pem -backend-ca ca.pem \
//	  -backend a=https://127.0.0.1:P1 -backend b=https://127.0.0.1:P2 \
//	  -route /par=a -route /authorize=b ... [-dpop-nonce-split]
//
// Each request goes to the instance of the longest -route its path
// starts with (a route matches its path, and the paths under it), or,
// with none, to each instance in turn. With -dpop-nonce-split, a
// request carrying a DPoP proof without a nonce claim goes to the
// other instance than its route's: there it's answered with a DPoP
// nonce challenge, and the retry carrying that nonce goes to its
// route's instance, which must accept a nonce the other issued. A
// request's X-Interop-Instance header, naming an instance, overrides
// both: a run's control sends a request to the instance it chooses. It
// isn't passed on.
//
// Every response carries X-Interop-Instance, naming the instance that
// served it, and each request is logged as one line,
//
//	splitproxy: instance=a POST /par 201 why=route
//
// why being route, turn, dpop-nonce-split or override: what a run
// reads to prove that the split happened.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// instanceHeader names the instance, on a request (which one to use)
// and on a response (which one served it).
const instanceHeader = "X-Interop-Instance"

// Why a request went to the instance it did.
const (
	whyRoute    = "route"
	whyTurn     = "turn"
	whyDPoP     = "dpop-nonce-split"
	whyOverride = "override"
)

// listFlag is a repeatable flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func main() {
	addr := flag.String("addr", "", "the address to listen on")
	certFile := flag.String("cert", "", "the TLS certificate (PEM) to serve, the instances' own")
	keyFile := flag.String("key", "", "its private key (PEM)")
	backendCA := flag.String("backend-ca", "", "the CA (PEM) the instances' TLS certificates chain to")
	serverName := flag.String("backend-server-name", "", "the name the instances' TLS certificates are checked for (default: each URL's host)")
	dpopSplit := flag.Bool("dpop-nonce-split", false, "send a request whose DPoP proof carries no nonce to the other instance than its route's")
	var backends, routes listFlag
	flag.Var(&backends, "backend", "name=https://host:port, an instance (exactly two)")
	flag.Var(&routes, "route", "/path=name, the instance a path and the paths under it go to")
	flag.Parse()

	if err := run(*addr, *certFile, *keyFile, *backendCA, *serverName, *dpopSplit, backends, routes); err != nil {
		log.Fatal(err)
	}
}

func run(addr, certFile, keyFile, backendCA, serverName string, dpopSplit bool, backends, routes []string) error {
	if addr == "" || certFile == "" || keyFile == "" || backendCA == "" {
		return errors.New("-addr, -cert, -key and -backend-ca are required")
	}
	caPEM, err := os.ReadFile(backendCA) // #nosec G304 -- the operator's own flag
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("%s holds no PEM certificate", backendCA)
	}
	s, err := newSplitter(backends, routes, dpopSplit, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr: addr, Handler: s,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("splitproxy: listening on %s, instances %s", addr, strings.Join(s.names, ", "))
	return srv.ListenAndServeTLS("", "")
}

// route is one -route: a path prefix and its instance.
type route struct {
	prefix, instance string
}

// splitter is the proxy's handler.
type splitter struct {
	names     []string
	proxies   map[string]*httputil.ReverseProxy
	routes    []route // longest prefix first
	dpopSplit bool

	mu   sync.Mutex
	turn int
}

func newSplitter(backends, routes []string, dpopSplit bool, tlsConfig *tls.Config) (*splitter, error) {
	if len(backends) != 2 {
		return nil, errors.New("exactly two -backend instances are required")
	}
	s := &splitter{proxies: map[string]*httputil.ReverseProxy{}, dpopSplit: dpopSplit}
	for _, b := range backends {
		name, raw, ok := strings.Cut(b, "=")
		target, err := url.Parse(raw)
		if !ok || name == "" || err != nil || target.Scheme != "https" || target.Host == "" {
			return nil, fmt.Errorf("-backend %q: want name=https://host:port", b)
		}
		if _, dup := s.proxies[name]; dup {
			return nil, fmt.Errorf("-backend %q: instance %s named twice", b, name)
		}
		s.names = append(s.names, name)
		s.proxies[name] = newProxy(name, target, tlsConfig)
	}
	for _, r := range routes {
		prefix, name, ok := strings.Cut(r, "=")
		if !ok || !strings.HasPrefix(prefix, "/") || s.proxies[name] == nil {
			return nil, fmt.Errorf("-route %q: want /path=instance, naming a -backend", r)
		}
		s.routes = append(s.routes, route{prefix: prefix, instance: name})
	}
	sort.SliceStable(s.routes, func(i, j int) bool { return len(s.routes[i].prefix) > len(s.routes[j].prefix) })
	return s, nil
}

// newProxy forwards to target, the instance name, keeping the
// request's Host (the issuer's or verifier's own URL) and naming the
// instance on the response.
func newProxy(name string, target *url.URL, tlsConfig *tls.Config) *httputil.ReverseProxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig.Clone()
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			r.Out.Header.Del(instanceHeader)
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set(instanceHeader, name)
			return nil
		},
	}
}

// pick is the instance r goes to, and why.
func (s *splitter) pick(r *http.Request) (string, string) {
	if name := r.Header.Get(instanceHeader); name != "" && s.proxies[name] != nil {
		return name, whyOverride
	}
	for _, rt := range s.routes {
		if r.URL.Path != rt.prefix && !strings.HasPrefix(r.URL.Path, strings.TrimSuffix(rt.prefix, "/")+"/") {
			continue
		}
		if s.dpopSplit && proofWithoutNonce(r.Header.Get("DPoP")) {
			return s.other(rt.instance), whyDPoP
		}
		return rt.instance, whyRoute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn++
	return s.names[s.turn%len(s.names)], whyTurn
}

// other is the instance that isn't name.
func (s *splitter) other(name string) string {
	if s.names[0] == name {
		return s.names[1]
	}
	return s.names[0]
}

// proofWithoutNonce reports whether proof, a DPoP header's value, is a
// JWT whose payload has no nonce claim; read unverified, as routing
// only needs to know which the instance will answer.
func proofWithoutNonce(proof string) bool {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	_, has := claims["nonce"]
	return !has
}

// statusRecorder keeps the status a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (s *splitter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, why := s.pick(r)
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.proxies[name].ServeHTTP(rec, r)
	// The path alone: a query can carry codes and handles. The method
	// and path are the request's, quoted or one of the server's own.
	log.Printf("splitproxy: instance=%s %s %q %d why=%s", name, methodName(r.Method), r.URL.Path, rec.status, why) // #nosec G706 -- quoted: a request can't forge a log line
}

// methodName is method, if it's one the servers serve, or "OTHER".
func methodName(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodHead, http.MethodOptions:
		return method
	}
	return "OTHER"
}
