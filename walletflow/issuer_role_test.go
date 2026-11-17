package walletflow_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// An SD-JWT VC signed with a TLS server's certificate under IssuerRoots
// isn't received when no IssuerLeafPolicy is set: the wallet makes the
// issuer check a Verifier makes by default
// (verifier.DefaultSDJWTIssuerLeafPolicy). verifier.AnyIssuerLeaf
// opts out, and an issuer certificate that denotes no other role is
// received by default.
func TestIssuance_SDJWTDefaultIssuerRole(t *testing.T) {
	tlsOnly := walletflowtest.Options{IssuerSignerExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for name, tc := range map[string]struct {
		opts   walletflowtest.Options
		policy func(*x509.Certificate, [][]*x509.Certificate) error
		want   bool
	}{
		"TLS server certificate":                {tlsOnly, nil, false},
		"TLS server certificate, AnyIssuerLeaf": {tlsOnly, verifier.AnyIssuerLeaf, true},
		"document signer certificate":           {walletflowtest.Options{}, nil, true},
	} {
		f := newFixture(t, tc.opts)
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
			IssuerRoots: f.env.IssuerRoots, IssuerLeafPolicy: tc.policy,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = tryReceive(t, f, w, walletflowtest.SDJWTConfigurationID)
		if (err == nil) != tc.want {
			t.Fatalf("%s: RequestCredentials: %v, want accepted %t", name, err, tc.want)
		}
		if err != nil && !strings.Contains(err.Error(), "TLS") {
			t.Errorf("%s: error = %v, want it to say the certificate is a TLS one", name, err)
		}
		held, _ := f.store.List(context.Background())
		if (len(held) != 0) != tc.want {
			t.Errorf("%s: stored %d credentials", name, len(held))
		}
	}
}

// CheckStatus re-checks a held SD-JWT VC's issuer chain with the policy
// receipt applies: with no IssuerLeafPolicy, the default issuer check.
// A credential received under verifier.AnyIssuerLeaf, signed with a TLS
// server's certificate, is issuer_untrusted once the wallet uses the
// default, and stays valid while it keeps the opt-out.
func TestCheckStatus_SDJWTDefaultIssuerRole(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{IssuerSignerExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	walletWith := func(policy func(*x509.Certificate, [][]*x509.Certificate) error) *walletflow.Wallet {
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
			IssuerRoots: f.env.IssuerRoots, IssuerLeafPolicy: policy,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	optOut := walletWith(verifier.AnyIssuerLeaf)
	if err := tryReceive(t, f, optOut, walletflowtest.SDJWTConfigurationID); err != nil {
		t.Fatalf("receive under AnyIssuerLeaf: %v", err)
	}
	held, err := f.store.List(ctx)
	if err != nil || len(held) != 1 {
		t.Fatalf("held = %d, %v", len(held), err)
	}
	id := held[0].ID

	c, err := optOut.CheckStatus(ctx, id)
	if err != nil {
		t.Fatalf("CheckStatus under AnyIssuerLeaf: %v", err)
	}
	if c.Status.Value == walletflow.StatusInvalid {
		t.Errorf("under AnyIssuerLeaf: status %+v, want the credential kept", c.Status)
	}
	c, err = walletWith(nil).CheckStatus(ctx, id)
	if err != nil {
		t.Fatalf("CheckStatus with the default policy: %v", err)
	}
	if c.Status.Value != walletflow.StatusInvalid || c.Status.Reason != walletflow.ReasonIssuerUntrusted {
		t.Errorf("with the default policy: status %+v, want invalid, %s", c.Status, walletflow.ReasonIssuerUntrusted)
	}
}
