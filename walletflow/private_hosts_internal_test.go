package walletflow

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// productionConfig is the smallest Config New takes outside Development
// for a wallet that only presents.
func productionConfig(hosts ...string) Config {
	return Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb", AllowedPrivateHosts: hosts}
}

func memoryDeps() Dependencies {
	return Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()}
}

// TestNew_AllowedPrivateHostsRefusesNonNames: each entry names one host
// exactly, so New refuses an address, a wildcard, a port, a trailing
// dot and a loopback name, in Development too.
func TestNew_AllowedPrivateHostsRefusesNonNames(t *testing.T) {
	t.Parallel()
	for _, host := range []string{
		"", " ", "10.0.0.5", "fd00::1", "[fd00::1]", "*.internal", "*", "issuer.internal:8443",
		"issuer.internal.", ".internal", "localhost", "LocalHost", "wallet.localhost", "https://issuer.internal",
		"issuer internal", "user@issuer.internal", "fe80::1%en0",
	} {
		for _, development := range []bool{false, true} {
			cfg := productionConfig("issuer.internal", host)
			cfg.Development = development
			if _, err := New(cfg, memoryDeps()); err == nil || !strings.Contains(err.Error(), "AllowedPrivateHosts") {
				t.Errorf("Development %t, host %q: err = %v, want refused", development, host, err)
			}
		}
	}
	for _, host := range []string{"issuer.internal", "Issuer2-API", "verifier_1.corp.example"} {
		if _, err := New(productionConfig(host), memoryDeps()); err != nil {
			t.Errorf("host %q: %v", host, err)
		}
	}
}

// TestNew_AllowedPrivateHostsWiring: outside Development the wallet's
// own client, its own fetches (wallet.Config.Fetch) and its status list
// fetches all take the list, as a copy the caller can't change later;
// without hosts, status lists keep statuslist's own address policy.
func TestNew_AllowedPrivateHostsWiring(t *testing.T) {
	t.Parallel()
	hosts := []string{"issuer.internal", "verifier.internal"}
	w, err := New(productionConfig(hosts...), memoryDeps())
	if err != nil {
		t.Fatal(err)
	}
	hosts[0] = "elsewhere.internal"
	h, ok := fapihttp.HardeningOf(w.deps.HTTP)
	if !ok {
		t.Fatal("the wallet's client isn't fapihttp's hardened one")
	}
	if got := h.AllowedPrivateHosts(); !slices.Equal(got, []string{"issuer.internal", "verifier.internal"}) {
		t.Errorf("transport's AllowedPrivateHosts = %v", got)
	}
	if h.AllowsLoopback() {
		t.Error("the transport allows loopback outside Development")
	}
	if !slices.Equal(w.cfg.AllowedPrivateHosts, []string{"issuer.internal", "verifier.internal"}) {
		t.Errorf("Config.AllowedPrivateHosts = %v: the caller's change reached the wallet", w.cfg.AllowedPrivateHosts)
	}
	f := w.statusFetcher(123)
	if _, wrapped := f.HTTP.Transport.(hardenedTransport); !wrapped || !f.UncheckedTransport || f.AllowLoopback || f.AllowPrivate || f.MaxBytes != 123 {
		t.Errorf("status fetcher = %+v, want the hardened transport, as it is", f)
	}
	if _, ok := fapihttp.HardeningOfTransport(f.HTTP.Transport.(hardenedTransport).RoundTripper); !ok {
		t.Error("the status fetcher's transport isn't the hardened one")
	}

	plain, err := New(productionConfig(), memoryDeps())
	if err != nil {
		t.Fatal(err)
	}
	if f := plain.statusFetcher(0); plain.statusHTTP != nil || f.UncheckedTransport || f.AllowPrivate || f.HTTP != plain.deps.HTTP {
		t.Errorf("without hosts, status fetcher = %+v, want statuslist's own policy over the wallet's client", f)
	}

	dev := productionConfig("issuer.internal")
	dev.Development = true
	dw, err := New(dev, memoryDeps())
	if err != nil {
		t.Fatal(err)
	}
	if f := dw.statusFetcher(0); !f.AllowLoopback || !f.AllowPrivate || f.UncheckedTransport {
		t.Errorf("in Development, status fetcher = %+v, want loopback and private allowed", f)
	}
}

// TestNew_AllowedPrivateHostsCallersHTTP: outside Development, a
// caller's client must allow exactly Config's hosts, compared without
// case or order, so one list holds for every request.
func TestNew_AllowedPrivateHostsCallersHTTP(t *testing.T) {
	t.Parallel()
	client := func(hosts ...string) *http.Client {
		c, err := fapihttp.NewClient(fapihttp.TransportConfig{DialTimeout: time.Second, TLSHandshakeTimeout: time.Second, AllowedPrivateHosts: hosts})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, tc := range []struct {
		name        string
		config      []string
		transport   []string
		development bool
		ok          bool
	}{
		{name: "same", config: []string{"a.internal", "B.internal"}, transport: []string{"b.internal", "a.internal"}, ok: true},
		{name: "neither", ok: true},
		{name: "config only", config: []string{"a.internal"}},
		{name: "transport has more", config: []string{"a.internal"}, transport: []string{"a.internal", "b.internal"}},
		{name: "different", config: []string{"a.internal"}, transport: []string{"b.internal"}},
		{name: "transport only", transport: []string{"a.internal"}, ok: true},
		{name: "development", config: []string{"a.internal"}, development: true, ok: true},
	} {
		cfg := productionConfig(tc.config...)
		cfg.Development = tc.development
		deps := memoryDeps()
		deps.HTTP = client(tc.transport...)
		_, err := New(cfg, deps)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err = %v, want ok %t", tc.name, err, tc.ok)
		}
	}
}

// TestAllowedPrivateHosts_RefusedAddresses: listing a host lifts only
// its private addresses. The wallet's client and its status fetcher
// still refuse an unlisted private address, a listed name that resolves
// to loopback (checked on the address dialled, as after a DNS rebind),
// link-local and shared addresses, and http.
func TestAllowedPrivateHosts_RefusedAddresses(t *testing.T) {
	t.Parallel()
	// localhost and the literals can't be listed through Config (New
	// refuses them); listed here, they show the transport refuses what
	// the allowance never lifts.
	listed := []string{"localhost", "169.254.169.254", "100.64.0.1", "issuer.internal"}
	client, err := defaultHTTPClient(false, nil, listed)
	if err != nil {
		t.Fatal(err)
	}
	w := &Wallet{cfg: Config{AllowedPrivateHosts: listed}, deps: Dependencies{HTTP: client}, statusHTTP: statusHTTP(Config{AllowedPrivateHosts: listed}, client)}
	if w.statusHTTP == nil {
		t.Fatal("no status client")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a refused request reached the server")
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	for _, target := range []string{
		"https://10.0.0.1/", "https://192.168.0.1/", "https://[fd00::1]/", // unlisted private
		"https://localhost:" + port + "/",                 // listed, resolves to loopback
		"https://127.0.0.1:" + port + "/",                 // loopback
		"https://169.254.169.254/", "https://100.64.0.1/", // listed, but link-local and shared
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := w.deps.HTTP.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("GET %s succeeded, want refused", target)
		} else if !errors.Is(err, fapihttp.ErrSSRFBlocked) {
			t.Errorf("GET %s: %v, want fapihttp.ErrSSRFBlocked", target, err)
		}
		if _, err := w.statusFetcher(0).Fetch(ctx, target+"statuslists/1", statuslist.TokenMediaType); err == nil || !errors.Is(err, fapihttp.ErrSSRFBlocked) {
			t.Errorf("status list at %s: %v, want fapihttp.ErrSSRFBlocked", target, err)
		}
		cancel()
	}
	if _, err := w.statusFetcher(0).Fetch(context.Background(), "http://issuer.internal/statuslists/1", statuslist.TokenMediaType); err == nil || !strings.Contains(err.Error(), "isn't an https URL") {
		t.Errorf("status list over http: %v, want refused", err)
	}
}

// TestAllowedPrivateHosts_ReachesListedPrivateHost: a status list on a
// listed host at a private address is fetched through the hardened
// transport, where statuslist's own policy, without AllowPrivate,
// refuses it. It needs one of this machine's own private addresses to
// serve from, so is skipped on a machine without one.
func TestAllowedPrivateHosts_ReachesListedPrivateHost(t *testing.T) {
	t.Parallel()
	ip := privateInterfaceAddress(t)
	ca, caKey := testcert.CA(t, "private hosts test CA")
	leaf, leafKey := testcert.Issue(t, &x509.Certificate{
		IPAddresses: []net.IP{ip}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, caKey)
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Skipf("can't listen on %s: %v", ip, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", statuslist.TokenMediaType)
		_, _ = rw.Write([]byte("token"))
	}))
	srv.Listener = ln
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// The address stands in for a listed name: the transport matches the
	// URL's host against the list, and a test can't make a name resolve.
	listed := []string{ip.String()}
	client, err := fapihttp.NewClient(fapihttp.TransportConfig{DialTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, RootCAs: roots, AllowedPrivateHosts: listed})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{AllowedPrivateHosts: listed}
	w := &Wallet{cfg: cfg, deps: Dependencies{HTTP: client}, statusHTTP: statusHTTP(cfg, client)}
	got, err := w.statusFetcher(0).Fetch(context.Background(), srv.URL+"/statuslists/1", statuslist.TokenMediaType)
	if err != nil || string(got) != "token" {
		t.Fatalf("status list on a listed private host: %q, %v", got, err)
	}

	unlisted := &Wallet{deps: Dependencies{HTTP: client}}
	if _, err := unlisted.statusFetcher(0).Fetch(context.Background(), srv.URL+"/statuslists/1", statuslist.TokenMediaType); err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Errorf("without AllowedPrivateHosts, statuslist's policy: %v, want refused", err)
	}
}

// privateInterfaceAddress is one of this machine's private IPv4
// addresses, or skips the test.
func privateInterfaceAddress(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("interface addresses: %v", err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			return n.IP.To4()
		}
	}
	t.Skip("no private IPv4 address on this machine")
	return nil
}
