package main

import (
	"crypto/tls"
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

// proof is a DPoP proof-shaped JWT whose payload is payload; its
// header and signature aren't read.
func proof(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

func TestPick(t *testing.T) {
	s, err := newSplitter([]string{"a=https://127.0.0.1:1", "b=https://127.0.0.1:2"},
		[]string{"/par=a", "/authorize=b", "/credential=b"}, true, &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path, dpop, override, instance, why string
	}{
		"a route":                        {path: "/par", instance: "a", why: whyRoute},
		"a path under a route":           {path: "/authorize/decision", instance: "b", why: whyRoute},
		"not a route's prefix":           {path: "/credential-offer/x", instance: "", why: whyTurn},
		"a proof with a nonce":           {path: "/par", dpop: proof(`{"nonce":"n"}`), instance: "a", why: whyRoute},
		"a proof without one":            {path: "/par", dpop: proof(`{"jti":"j"}`), instance: "b", why: whyDPoP},
		"a proof without one, elsewhere": {path: "/credential", dpop: proof(`{}`), instance: "a", why: whyDPoP},
		"not a JWT":                      {path: "/par", dpop: "x", instance: "a", why: whyRoute},
		"an override":                    {path: "/par", dpop: proof(`{}`), override: "a", instance: "a", why: whyOverride},
		"an override naming no instance": {path: "/par", override: "c", instance: "a", why: whyRoute},
		"a payload that isn't JSON":      {path: "/par", dpop: "e30.bm90.c2ln", instance: "a", why: whyRoute},
		"a payload that isn't base64url": {path: "/par", dpop: "e30.!.c2ln", instance: "a", why: whyRoute},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", c.path, nil)
			if c.dpop != "" {
				r.Header.Set("DPoP", c.dpop)
			}
			if c.override != "" {
				r.Header.Set(instanceHeader, c.override)
			}
			instance, why := s.pick(r)
			if why != c.why || (c.instance != "" && instance != c.instance) {
				t.Errorf("pick = %s (%s), want %s (%s)", instance, why, c.instance, c.why)
			}
		})
	}
	// The rest go to each instance in turn.
	first, _ := s.pick(httptest.NewRequest("GET", "/jwks", nil))
	second, _ := s.pick(httptest.NewRequest("GET", "/jwks", nil))
	if first == second {
		t.Errorf("two requests without a route both went to %s", first)
	}
}

func TestNewSplitter(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	for name, c := range map[string]struct{ backends, routes []string }{
		"one instance":            {[]string{"a=https://127.0.0.1:1"}, nil},
		"an instance named twice": {[]string{"a=https://127.0.0.1:1", "a=https://127.0.0.1:2"}, nil},
		"not https":               {[]string{"a=http://127.0.0.1:1", "b=https://127.0.0.1:2"}, nil},
		"no name":                 {[]string{"https://127.0.0.1:1", "b=https://127.0.0.1:2"}, nil},
		"a route to no instance":  {[]string{"a=https://127.0.0.1:1", "b=https://127.0.0.1:2"}, []string{"/par=c"}},
		"a route without a path":  {[]string{"a=https://127.0.0.1:1", "b=https://127.0.0.1:2"}, []string{"par=a"}},
	} {
		if _, err := newSplitter(c.backends, c.routes, false, cfg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
