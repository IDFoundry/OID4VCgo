package walletflow_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// An mdoc is checked against the mdoc-specific trust where it's set —
// MdocIssuerRootsByDocType's roots for its type, else MdocIssuerRoots,
// and MdocIssuerLeafPolicy — and an SD-JWT VC against IssuerRoots and
// IssuerLeafPolicy alone.
func TestMdocIssuerTrust(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	other, _ := testcert.CA(t, "another issuer CA")
	others := x509.NewCertPool()
	others.AddCert(other)
	accept := func(*x509.Certificate, [][]*x509.Certificate) error { return nil }
	refuse := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("refused") }
	for name, tc := range map[string]struct {
		cfg             walletflow.Config
		sdjwtOK, mdocOK bool
	}{
		"shared roots":                              {walletflow.Config{IssuerRoots: f.env.IssuerRoots}, true, true},
		"mdoc roots in place of IssuerRoots":        {walletflow.Config{IssuerRoots: others, MdocIssuerRoots: f.env.IssuerRoots}, false, true},
		"an SD-JWT issuer's roots don't sign mdocs": {walletflow.Config{IssuerRoots: f.env.IssuerRoots, MdocIssuerRoots: others}, true, false},
		"mdoc roots alone":                          {walletflow.Config{MdocIssuerRoots: f.env.IssuerRoots}, false, true},
		"roots for the document type": {walletflow.Config{IssuerRoots: others, MdocIssuerRoots: others,
			MdocIssuerRootsByDocType: map[string]*x509.CertPool{walletflowtest.DocType: f.env.IssuerRoots}}, false, true},
		"another type's roots": {walletflow.Config{IssuerRoots: f.env.IssuerRoots,
			MdocIssuerRootsByDocType: map[string]*x509.CertPool{walletflowtest.DocType: others}}, true, false},
		"a type named with no roots": {walletflow.Config{IssuerRoots: f.env.IssuerRoots,
			MdocIssuerRootsByDocType: map[string]*x509.CertPool{walletflowtest.DocType: nil}}, true, false},
		"IssuerLeafPolicy applies to an mdoc under IssuerRoots": {walletflow.Config{IssuerRoots: f.env.IssuerRoots, IssuerLeafPolicy: refuse}, false, false},
		"MdocIssuerLeafPolicy replaces it":                      {walletflow.Config{IssuerRoots: f.env.IssuerRoots, IssuerLeafPolicy: refuse, MdocIssuerLeafPolicy: accept}, false, true},
		"MdocIssuerLeafPolicy applies to mdocs only":            {walletflow.Config{IssuerRoots: f.env.IssuerRoots, MdocIssuerLeafPolicy: refuse}, true, false},
		"IssuerLeafPolicy doesn't apply under mdoc roots":       {walletflow.Config{IssuerRoots: f.env.IssuerRoots, IssuerLeafPolicy: refuse, MdocIssuerRoots: f.env.IssuerRoots}, false, true},
	} {
		cfg := tc.cfg
		cfg.ClientID, cfg.RedirectURI, cfg.Development = walletflowtest.ClientID, walletflowtest.RedirectURI, true
		cfg.CredentialIssuers = []string{f.env.IssuerURL}
		w, err := walletflow.New(cfg, walletflow.Dependencies{
			Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), Provider: f.env.Provider, HTTP: f.env.HTTP,
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for configID, want := range map[string]bool{walletflowtest.SDJWTConfigurationID: tc.sdjwtOK, walletflowtest.MdocConfigurationID: tc.mdocOK} {
			if err := tryReceive(t, f, w, configID); (err == nil) != want {
				t.Errorf("%s / %s: %v, want accepted %t", name, configID, err, want)
			}
		}
	}
}

// tryReceive has w receive configID through the authorization code
// grant, returning RequestCredentials' error.
func tryReceive(t *testing.T, f fixture, w *walletflow.Wallet, configID string) error {
	t.Helper()
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, configID))
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	_, err = s.RequestCredentials(ctx)
	return err
}
