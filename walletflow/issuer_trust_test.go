package walletflow_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// A credential is checked against the trust for its format and type
// where it's set: an SD-JWT VC against IssuerRootsByVCT's roots for its
// vct, else IssuerRoots, and IssuerLeafPolicy; an mdoc against
// MdocIssuerRootsByDocType's roots for its type, else MdocIssuerRoots,
// and MdocIssuerLeafPolicy, else IssuerRoots and IssuerLeafPolicy.
func TestIssuerTrust(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	vct := f.env.VCT()
	others := otherRoots(t)
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
		"roots for the vct": {walletflow.Config{IssuerRoots: others,
			IssuerRootsByVCT: map[string]*x509.CertPool{vct: f.env.IssuerRoots}}, true, false},
		"another vct's roots": {walletflow.Config{IssuerRoots: f.env.IssuerRoots,
			IssuerRootsByVCT: map[string]*x509.CertPool{vct: others}}, false, true},
		"a vct named with no roots": {walletflow.Config{IssuerRoots: f.env.IssuerRoots,
			IssuerRootsByVCT: map[string]*x509.CertPool{vct: nil}}, false, true},
		"vct roots alone": {walletflow.Config{IssuerRootsByVCT: map[string]*x509.CertPool{vct: f.env.IssuerRoots}}, true, false},
		"a vct not named": {walletflow.Config{IssuerRoots: f.env.IssuerRoots,
			IssuerRootsByVCT: map[string]*x509.CertPool{"urn:example:other": others}}, true, true},
		"IssuerLeafPolicy applies under the vct's roots": {walletflow.Config{IssuerRootsByVCT: map[string]*x509.CertPool{vct: f.env.IssuerRoots},
			IssuerLeafPolicy: refuse, MdocIssuerRoots: f.env.IssuerRoots}, false, true},
	} {
		for configID, want := range map[string]bool{walletflowtest.SDJWTConfigurationID: tc.sdjwtOK, walletflowtest.MdocConfigurationID: tc.mdocOK} {
			if err := receiveUnder(t, f, tc.cfg, configID); (err == nil) != want {
				t.Errorf("%s / %s: %v, want accepted %t", name, configID, err, want)
			}
		}
	}
}

// With IssuerRootsByVCT set, an SD-JWT VC's aka_vcts, the types it says
// it's of too, must be its issuer's to issue: its chain must verify
// under each one's roots, IssuerRootsByVCT's for a type it names, else
// IssuerRoots, or the credential is refused.
func TestIssuerRootsByVCT_AkaVCTs(t *testing.T) {
	const pid = "urn:example:pid"
	f := newFixture(t, walletflowtest.Options{AlterBatch: func(batch []*issuer.CredentialInstance) {
		for _, c := range batch {
			if c.SDJWTClaims != nil {
				c.SDJWTClaims.AkaVCTs = []string{pid}
			}
		}
	}})
	others := otherRoots(t)
	for name, tc := range map[string]struct {
		cfg walletflow.Config
		ok  bool
	}{
		"no IssuerRootsByVCT": {walletflow.Config{IssuerRoots: f.env.IssuerRoots}, true},
		"another issuer's type": {walletflow.Config{IssuerRoots: f.env.IssuerRoots,
			IssuerRootsByVCT: map[string]*x509.CertPool{pid: others}}, false},
		"its issuer's type": {walletflow.Config{IssuerRoots: f.env.IssuerRoots,
			IssuerRootsByVCT: map[string]*x509.CertPool{pid: f.env.IssuerRoots}}, true},
		"a type with no roots": {walletflow.Config{IssuerRootsByVCT: map[string]*x509.CertPool{f.env.VCT(): f.env.IssuerRoots}}, false},
	} {
		if err := receiveUnder(t, f, tc.cfg, walletflowtest.SDJWTConfigurationID); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want accepted %t", name, err, tc.ok)
		}
	}
}

// CheckStatus checks a held SD-JWT VC's issuer chain against the roots
// configured for its vct and its aka_vcts now, as receipt does: one
// under another type's roots is untrusted, and one whose vct is named
// with no roots has nothing to check.
func TestCheckStatus_IssuerRootsByVCT(t *testing.T) {
	const loyalty, pid = "urn:example:loyalty", "urn:example:pid"
	ca, caKey := testcert.CA(t, "attestation provider CA")
	leaf, leafKey := testcert.Leaf(t, "attestation provider", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	others := otherRoots(t)
	until := time.Now().Add(time.Hour)
	exp := until.Unix()
	compact, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{VCT: loyalty, AkaVCTs: []string{pid}, Exp: &exp},
		sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	c := walletflow.StoredCredential{
		ID: "sdjwt-1", CredentialIssuer: "https://issuer.example", Format: sdjwtvc.CredentialFormat, VCT: loyalty,
		Credential: compact, Claims: map[string]any{"vct": loyalty, "aka_vcts": []any{pid}}, ValidUntil: until,
	}
	for name, tc := range map[string]struct {
		byVCT         map[string]*x509.CertPool
		issuerRoots   *x509.CertPool
		value, reason string
	}{
		"IssuerRoots alone":       {nil, roots, walletflow.StatusValid, ""},
		"its type's roots":        {map[string]*x509.CertPool{loyalty: roots, pid: roots}, nil, walletflow.StatusValid, ""},
		"another type's roots":    {map[string]*x509.CertPool{loyalty: others}, roots, walletflow.StatusInvalid, walletflow.ReasonIssuerUntrusted},
		"an aka type's others":    {map[string]*x509.CertPool{pid: others}, roots, walletflow.StatusInvalid, walletflow.ReasonIssuerUntrusted},
		"an aka type with none":   {map[string]*x509.CertPool{loyalty: roots}, nil, walletflow.StatusInvalid, walletflow.ReasonIssuerUntrusted},
		"its type named, no pool": {map[string]*x509.CertPool{loyalty: nil}, roots, "", ""},
	} {
		w := walletHoldingWith(t, walletflow.Config{
			Development: true, CredentialIssuers: []string{"https://issuer.example"}, IssuerRoots: tc.issuerRoots, IssuerRootsByVCT: tc.byVCT,
		}, nil, c)
		checked, err := w.CheckStatus(context.Background(), c.ID)
		if err != nil || checked.Status.Value != tc.value || checked.Status.Reason != tc.reason {
			t.Errorf("%s: CheckStatus = %+v, %v; want %q (%q)", name, checked.Status, err, tc.value, tc.reason)
		}
	}
}

// otherRoots is a pool of a CA that signs none of the tests'
// credentials.
func otherRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	other, _ := testcert.CA(t, "another issuer CA")
	pool := x509.NewCertPool()
	pool.AddCert(other)
	return pool
}

// receiveUnder has a wallet configured with cfg, over f's issuer,
// receive configID through the authorization code grant, returning
// RequestCredentials' error.
func receiveUnder(t *testing.T, f fixture, cfg walletflow.Config, configID string) error {
	t.Helper()
	cfg.ClientID, cfg.RedirectURI, cfg.Development = walletflowtest.ClientID, walletflowtest.RedirectURI, true
	cfg.CredentialIssuers = []string{f.env.IssuerURL}
	w, err := walletflow.New(cfg, walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), Provider: f.env.Provider, HTTP: f.env.HTTP,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tryReceive(t, f, w, configID)
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
