package wallet_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// A signed DC API request, in either signed form, is refused when it
// has expired, isn't valid yet, or is addressed to another audience:
// the same checks a redirect-flow Request Object gets.
func TestParseDCAPIRequest_ChecksTimesAndAudience(t *testing.T) {
	f := newDCAPIForms(t)
	now := time.Now()
	for name, tc := range map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"expired":           {func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() }, "expired"},
		"not yet valid":     {func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }, "isn't valid yet"},
		"another audience":  {func(c map[string]any) { c["aud"] = "https://another-wallet.example" }, "aud"},
		"audience a number": {func(c map[string]any) { c["aud"] = 1 }, "aud"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
				Request: resign(t, f.key, f.built.RequestObject, tc.mutate), Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("signed: err = %v, want one mentioning %q", err, tc.want)
			}
			_, err = wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
				Protocol: wallet.DCAPIProtocolMultiSigned, Data: f.multiSigned(t, tc.mutate, signer{key: f.key, cert: f.cert}),
				Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("multi-signed: err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
	// The unchanged request parses in both forms.
	if _, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
		Request: resign(t, f.key, f.built.RequestObject, func(map[string]any) {}), Origin: testDCAPIOrigin, VerifierTrust: f.trust,
	}); err != nil {
		t.Errorf("signed, unchanged: %v", err)
	}
	data, _ := json.Marshal(map[string]string{"request": f.built.RequestObject})
	if _, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolSigned, Data: data, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
	}); err != nil {
		t.Errorf("signed data, unchanged: %v", err)
	}
	if _, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolMultiSigned, Data: f.multiSigned(t, nil, signer{key: f.key, cert: f.cert}), Origin: testDCAPIOrigin, VerifierTrust: f.trust,
	}); err != nil {
		t.Errorf("multi-signed, unchanged: %v", err)
	}
}
