package mobile

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/proximity"
)

// status_max_age_seconds bounds how long ago a status or identifier
// list CheckStatus accepts may have been signed, and status_any_age
// declines the bound: outside development, a Wallet receiving
// credentials and a reader checking status need one of them. Both, or
// a bound outside 0 to a year, is invalid_input in development too.
func TestStatusMaxAge_Configuration(t *testing.T) {
	ca, _ := testcert.CA(t, "IACA")
	roots := jsonString(pemOf("CERTIFICATE", ca.Raw))
	// Production takes only fapihttp's hardened client, which the
	// wallet builds itself: not a test environment's.
	prev := testHTTP.Swap(nil)
	defer testHTTP.Store(prev)
	reader := func(keys string) error {
		_, err := NewProximityReader(`{"issuer_roots": `+roots+`, "any_issuer_for_any_type": true, "no_revocation_check": ["issuer", "status"], `+keys+`}`, nil)
		return err
	}
	wallet := func(keys string) error {
		_, err := NewWallet(`{"issuer_roots": `+roots+`, "credential_issuers": ["https://issuer.example"], "no_revocation_check": ["issuer", "status"], `+keys+`}`,
			newGoKeyStore(), newGoCredentialStore(), nil)
		return err
	}
	for name, tc := range map[string]struct {
		make    func(string) error
		keys    string
		refused string // "" for taken
	}{
		"reader, bounded":                 {reader, `"status": "check", "status_max_age_seconds": 86400`, ""},
		"reader, any age":                 {reader, `"status": "check", "status_any_age": true`, ""},
		"reader, age open":                {reader, `"status": "check"`, "status_max_age_seconds is unset"},
		"reader, declining status":        {reader, `"status": "decline"`, ""},
		"reader, both":                    {reader, `"status": "check", "status_max_age_seconds": 86400, "status_any_age": true`, "not both"},
		"reader, negative":                {reader, `"status": "check", "status_max_age_seconds": -1`, "not between 0 and 31622400"},
		"reader, over a year":             {reader, `"status": "check", "status_max_age_seconds": 31622401`, "not between 0 and 31622400"},
		"reader, development, age open":   {reader, `"status": "check", "development": true`, ""},
		"reader, development, both":       {reader, `"development": true, "status_max_age_seconds": 60, "status_any_age": true`, "not both"},
		"wallet, bounded":                 {wallet, `"status_max_age_seconds": 86400`, ""},
		"wallet, any age":                 {wallet, `"status_any_age": true`, ""},
		"wallet, age open":                {wallet, `"locales": ["en"]`, "status_max_age_seconds is unset"},
		"wallet, both":                    {wallet, `"status_max_age_seconds": 86400, "status_any_age": true`, "not both"},
		"wallet, negative":                {wallet, `"status_max_age_seconds": -1`, "not between 0 and 31622400"},
		"wallet, development, age open":   {wallet, `"development": true`, ""},
		"wallet, development, over limit": {wallet, `"development": true, "status_max_age_seconds": 31622401`, "not between 0 and 31622400"},
	} {
		err := tc.make(tc.keys)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (code(err) != CodeInvalidInput || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want invalid_input naming %q", name, err, tc.refused)
		}
	}
	// A wallet that receives nothing checks no status.
	if _, err := NewWallet(`{"locales": ["en"]}`, newGoKeyStore(), newGoCredentialStore(), nil); err != nil {
		t.Errorf("a wallet receiving nothing: %v", err)
	}
	wcfg, err := walletConfig(config{Development: true, StatusMaxAgeSeconds: 3600})
	if err != nil || wcfg.StatusMaxAge != time.Hour || wcfg.StatusAnyAge {
		t.Errorf("walletflow.Config.StatusMaxAge = %v, StatusAnyAge %v, %v", wcfg.StatusMaxAge, wcfg.StatusAnyAge, err)
	}
	if wcfg, err = walletConfig(config{Development: true, StatusAnyAge: true}); err != nil || wcfg.StatusMaxAge != 0 || !wcfg.StatusAnyAge {
		t.Errorf("status_any_age: walletflow.Config.StatusMaxAge = %v, StatusAnyAge %v, %v", wcfg.StatusMaxAge, wcfg.StatusAnyAge, err)
	}
}

// A reader's CheckStatus refuses a status list or an identifier list
// signed longer ago than status_max_age_seconds, however far off its
// exp is, and accepts one within it, or of any age with status_any_age.
// teststatuslist signs each list a minute before it's served, valid for
// an hour.
func TestProximityReader_StatusMaxAge(t *testing.T) {
	signer := teststatuslist.NewSigner(t)
	roots := jsonString(pemOf("CERTIFICATE", signer.CA.Raw))
	prev := testHTTP.Load()
	defer testHTTP.Store(prev)
	for _, tc := range []struct {
		age     string
		refused bool
	}{
		{`"status_max_age_seconds": 30`, true},
		{`"status_max_age_seconds": 3600`, false},
		{`"status_any_age": true`, false},
	} {
		statusURI, idsURI, client := signer.ServeLists(t, teststatuslist.WellFormed)
		testHTTP.Store(client)
		r, err := NewProximityReader(`{"issuer_roots": `+roots+`, "any_issuer_for_any_type": true, "no_revocation_check": ["issuer", "status"], "status": "check", `+tc.age+`}`, nil)
		if err != nil {
			t.Fatal(err)
		}
		for kind, status := range map[string]*mdoc.Status{
			"status list":     {StatusList: &mdoc.StatusListRef{Idx: 3, URI: statusURI, Certificate: signer.CA.Raw}},
			"identifier list": {IdentifierList: &mdoc.IdentifierListRef{ID: []byte{2}, URI: idsURI, Certificate: signer.CA.Raw}},
		} {
			got, err := r.checkStatus(context.Background(), proximity.Verified{Status: status, IssuerChain: []*x509.Certificate{signer.CA}})
			switch {
			case tc.refused && (err == nil || !strings.Contains(err.Error(), "over the 30s allowed")):
				t.Errorf("%s, %s: %q, %v, want it refused for its age", kind, tc.age, got, err)
			case !tc.refused && (err != nil || got != "valid"):
				t.Errorf("%s, %s: %q, %v, want valid", kind, tc.age, got, err)
			}
		}
	}
}
