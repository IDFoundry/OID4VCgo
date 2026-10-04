package main

import "testing"

// A service's URL must be an https origin: it's the issuer's identifier,
// and what a phone reaches through a tunnel.
func TestServiceURLs(t *testing.T) {
	local := serviceURLs{issuer: localIssuerURL, verifier: localVerifierURL, provider: localProviderURL}
	if err := local.check(); err != nil || local.public() {
		t.Errorf("the defaults: check %v, public %v; want valid and local", err, local.public())
	}
	public := serviceURLs{issuer: "https://issuer.idfoundry.dev", verifier: "https://verifier.idfoundry.dev/", provider: "https://provider.idfoundry.dev"}
	if err := public.check(); err != nil || !public.public() {
		t.Errorf("public URLs: check %v, public %v; want valid and public", err, public.public())
	}
	for _, bad := range []string{"http://issuer.example.com", "https://", "https://issuer.example.com/path", "https://issuer.example.com?x=1", "issuer.example.com"} {
		u := local
		u.issuer = bad
		if err := u.check(); err == nil {
			t.Errorf("check accepted -issuer-url %q", bad)
		}
	}
}
