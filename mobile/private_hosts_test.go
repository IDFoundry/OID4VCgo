package mobile

import (
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/fapihttp"
)

// allowed_private_hosts reaches walletflow, which refuses an entry that
// isn't a host name as invalid_input, and RefreshCRLs's own client.
func TestNewWallet_AllowedPrivateHosts(t *testing.T) {
	ks, cs := newGoKeyStore(), newGoCredentialStore()
	for _, hosts := range []string{`["10.0.0.5"]`, `["*.internal"]`, `["localhost"]`, `["issuer.internal:443"]`} {
		_, err := NewWallet(`{"client_id":"c","redirect_uri":"com.example.wallet:/cb","allowed_private_hosts":`+hosts+`}`, ks, cs, nil)
		if code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "AllowedPrivateHosts") {
			t.Errorf("allowed_private_hosts %s: %v, want invalid_input", hosts, err)
		}
	}
	w, err := NewWallet(`{"client_id":"c","redirect_uri":"com.example.wallet:/cb","allowed_private_hosts":["issuer.internal"]}`, ks, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := refreshClient(w.crls.refreshCfg)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := fapihttp.HardeningOf(client)
	if !ok || !slices.Equal(h.AllowedPrivateHosts(), []string{"issuer.internal"}) || h.AllowsLoopback() {
		t.Errorf("RefreshCRLs's client: hardened %t, %+v, want issuer.internal's private addresses and no loopback", ok, h)
	}
}
