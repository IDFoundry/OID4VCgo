//go:build mobiletest

package mobile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// detail is err's Detail, "" for none.
func detail(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return ""
}

// CheckStatus checks a held credential's issuer certificate against the
// lists held now, and its summary says why its status is what it is:
// invalid with issuer_certificate_revoked once a CRL names its signer,
// unknown with no_current_crl without a current one, valid again once a
// newer CRL no longer names it. The stored record keeps the reason and
// the copies' issuer_untrusted.
func TestSessions_CheckStatusIssuerCertificate(t *testing.T) {
	env, err := startTestEnv(walletflowtest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	var cfg config
	if err := json.Unmarshal([]byte(env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Revocation = []string{"issuer"}
	text, err := marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := harness{env: env, keys: newGoKeyStore(), creds: newGoCredentialStore()}
	if h.w, err = NewWallet(text, h.keys, h.creds, env.Provider()); err != nil {
		t.Fatal(err)
	}
	setCRL := func(revoked bool) {
		t.Helper()
		list, err := env.IssuerCRL(revoked)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.w.SetCRLs(list); err != nil {
			t.Fatal(err)
		}
	}
	setCRL(false)
	held := h.receive(t)

	type status struct {
		Value  string `json:"value"`
		Reason string `json:"reason"`
	}
	check := func(step, value, reason string, presentable bool) {
		t.Helper()
		for _, c := range held {
			out, err := h.w.CheckStatus(NewOperation(0), c.ID)
			if err != nil {
				t.Fatalf("%s: %s: %v", step, c.Format, err)
			}
			got := decode[struct {
				ABI         int     `json:"abi"`
				Status      *status `json:"status"`
				Presentable bool    `json:"presentable"`
			}](t, out)
			if got.Status == nil || got.Status.Value != value || got.Status.Reason != reason || got.Presentable != presentable {
				t.Errorf("%s: %s: CheckStatus = %s; want %s (%q), presentable %v", step, c.Format, out, value, reason, presentable)
			}
			if reason == "" && strings.Contains(out, `"reason"`) {
				t.Errorf("%s: %s: an empty reason is written: %s", step, c.Format, out)
			}
		}
	}
	check("clean CRL", walletflow.StatusValid, "", true)

	setCRL(true)
	check("signer revoked", walletflow.StatusInvalid, walletflow.ReasonIssuerCertificateRevoked, false)
	for _, c := range held {
		h.creds.mu.Lock()
		raw := h.creds.records[c.ID]
		h.creds.mu.Unlock()
		var r credentialRecord
		if err := json.Unmarshal(raw, &r); err != nil || r.Status == nil || r.Status.Reason != walletflow.ReasonIssuerCertificateRevoked || len(r.Copies) == 0 || !r.Copies[0].IssuerUntrusted {
			t.Errorf("%s: the record doesn't keep the reason and issuer_untrusted (%v): %s", c.Format, err, raw)
		}
	}

	if err := h.w.SetCRLs(""); err != nil {
		t.Fatal(err)
	}
	check("no CRL", walletflow.StatusUnknown, walletflow.ReasonNoCurrentCRL, false)

	setCRL(false)
	check("hold lifted", walletflow.StatusValid, "", true)
}

// revocationDetail gives an error caused by a revocation check its
// detail, and leaves one with a detail of its own, or another cause,
// as it is.
func TestRevocationDetail(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.Join(errors.New("issuer certificate"), certrevocation.ErrRevoked), "[protocol:certificate_revoked] "},
		{errors.Join(errors.New("issuer certificate"), certrevocation.ErrNoCurrentCRL), "[protocol:no_current_crl] "},
		{errors.New("something else"), "[protocol] "},
	} {
		if got := classify(tc.err); !strings.HasPrefix(got.Error(), tc.want) {
			t.Errorf("classify(%v) = %v, want %s…", tc.err, got, tc.want)
		}
	}
	own := &Error{Code: CodeInvalidInput, Detail: DetailNotConfigured, Message: "x"}
	if got := revocationDetail(own, certrevocation.ErrRevoked); got.Error() != "[invalid_input:not_configured] x" {
		t.Errorf("a detail of its own replaced: %v", got)
	}
}
