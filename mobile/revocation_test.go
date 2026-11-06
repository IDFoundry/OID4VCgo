package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func pemOf(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// "crls" takes PEM X509 CRL blocks and nothing else, and SetCRLs
// replaces the lists only with ones that parse.
func TestCRLs_Parse(t *testing.T) {
	ca, caKey := testcert.CA(t, "revocation test CA")
	list := testcert.CRL(t, ca, caKey)
	crl := pemOf("X509 CRL", list.Raw)

	for name, text := range map[string]string{"empty": "", "one": crl, "two": crl + "\n" + crl} {
		if _, err := parseCRLs(text); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, text := range map[string]string{
		"a certificate":      pemOf("CERTIFICATE", ca.Raw),
		"a CRL and a cert":   crl + pemOf("CERTIFICATE", ca.Raw),
		"not PEM":            "not PEM",
		"trailing text":      crl + "trailing",
		"a CRL that's junk":  pemOf("X509 CRL", []byte{0x30, 0x00}),
		"too many":           strings.Repeat(crl, maxCRLs+1),
		"a truncated header": "-----BEGIN X509 CRL-----\n",
	} {
		if _, err := parseCRLs(text); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}

	s, err := newCRLSet(crl, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.set(pemOf("CERTIFICATE", ca.Raw)); err == nil {
		t.Error("set took a certificate")
	}
	if got, _ := s.checker().Lists(context.Background()); len(got) != 1 {
		t.Errorf("after a refused set, %d lists, want the 1 kept", len(got))
	}
	if _, err := newCRLSet("not PEM", ""); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "crls") {
		t.Errorf("newCRLSet: %v, want invalid_input naming crls", err)
	}
}

// SetCRLs refuses a CA's list older than the one it holds — by CRL
// number, or by thisUpdate where either has none — so a replayed list
// can't un-revoke a certificate; a newer list, another CA's, or removing
// them all is taken. The CA is one the configuration has (here in
// crl_issuers): only its lists are verified, and so held to that.
func TestCRLs_RefusesAnOlderList(t *testing.T) {
	ca, caKey := testcert.CA(t, "revocation test CA")
	other, otherKey := testcert.CA(t, "another CA")
	at := func(n int64, hoursAgo int) string {
		tmpl := &x509.RevocationList{Number: big.NewInt(n), ThisUpdate: time.Now().Add(-time.Duration(hoursAgo) * time.Hour)}
		return pemOf("X509 CRL", testcert.CRLFromTemplate(t, tmpl, ca, caKey).Raw)
	}
	s, err := newCRLSet(at(5, 2), pemOf("CERTIFICATE", ca.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.set(at(4, 1)); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("a lower CRL number: %v, want refused as older", err)
	}
	if got, _ := s.checker().Lists(context.Background()); len(got) != 1 || got[0].Number.Int64() != 5 {
		t.Errorf("after a refused set, %v, want number 5 kept", got)
	}
	for _, step := range []struct{ name, text string }{ // in order
		{"the same list", at(5, 2)},
		{"a newer list", at(6, 1)},
		{"another CA's", pemOf("X509 CRL", testcert.CRL(t, other, otherKey).Raw)},
		{"removing them", ""},
		{"after removing", at(1, 3)},
	} {
		if err := s.set(step.text); err != nil {
			t.Errorf("%s: %v", step.name, err)
		}
	}
}

// A leaf pinned in verifier_roots, with "verifier" in "revocation", is
// checked against its CA's CRL, verified with the CA's certificate from
// "crl_issuers": without it, it fails closed; with it, it passes until
// the CRL lists it.
func TestCRLIssuers_PinnedLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "verifier CA")
	leaf, _ := testcert.Leaf(t, "pinned verifier", ca, caKey)
	check := func(crl *x509.RevocationList, issuers string) error {
		t.Helper()
		cfg := config{Development: true, VerifierRoots: pemOf("CERTIFICATE", leaf.Raw),
			CRLs: pemOf("X509 CRL", crl.Raw), CRLIssuers: issuers, Revocation: []string{"verifier"}}
		wcfg, err := walletConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := walletRevocation(cfg, &wcfg); err != nil {
			t.Fatal(err)
		}
		vt, _ := wcfg.VerifierTrust.(wallet.X5CVerifierRoots)
		return vt.Revocation.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{leaf}})
	}
	issuers := pemOf("CERTIFICATE", ca.Raw)
	if err := check(testcert.CRL(t, ca, caKey), ""); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
		t.Errorf("without crl_issuers: %v, want ErrNoCurrentCRL", err)
	}
	if err := check(testcert.CRL(t, ca, caKey), issuers); err != nil {
		t.Errorf("with crl_issuers: %v", err)
	}
	if err := check(testcert.CRL(t, ca, caKey, leaf.SerialNumber), issuers); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked, with crl_issuers: %v, want ErrRevoked", err)
	}

	// NewWallet takes the key; it holds CA certificates and nothing else.
	keys, creds := &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}
	if _, err := NewWallet(`{"development":true,"crl_issuers":`+jsonString(issuers)+`}`, keys, creds, nil); err != nil {
		t.Errorf("NewWallet with crl_issuers: %v", err)
	}
	for name, text := range map[string]string{
		"a leaf":        pemOf("CERTIFICATE", leaf.Raw),
		"a CRL":         pemOf("X509 CRL", testcert.CRL(t, ca, caKey).Raw),
		"trailing text": issuers + "trailing",
		"too many":      strings.Repeat(issuers, maxCRLs+1),
	} {
		if _, err := NewWallet(`{"development":true,"crl_issuers":`+jsonString(text)+`}`, keys, creds, nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "crl_issuers") {
			t.Errorf("crl_issuers %s: %v, want invalid_input naming crl_issuers", name, err)
		}
	}
	if _, err := NewProximityReader(`{"development":true,"issuer_roots":`+jsonString(issuers)+`,"crl_issuers":`+jsonString(pemOf("CERTIFICATE", leaf.Raw))+`}`, nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "crl_issuers") {
		t.Errorf("a reader's crl_issuers with a leaf: %v, want invalid_input", err)
	}
}

// "revocation" sets each role it names, over the same lists, and
// refuses a role it doesn't know or names twice.
func TestWalletRevocation_Roles(t *testing.T) {
	ca, _ := testcert.CA(t, "verifier root")
	cfg := config{Development: true, VerifierRoots: pemOf("CERTIFICATE", ca.Raw),
		Revocation: []string{"issuer", "issuer_metadata", "registrar", "mdoc_reader", "verifier", "status"}}
	wcfg, err := walletConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walletRevocation(cfg, &wcfg); err != nil {
		t.Fatal(err)
	}
	vt, _ := wcfg.VerifierTrust.(wallet.X5CVerifierRoots)
	if wcfg.IssuerRevocation == nil || wcfg.IssuerMetadataRevocation == nil || wcfg.RegistrarRevocation == nil ||
		wcfg.MdocReaderRevocation == nil || wcfg.StatusRevocation == nil || vt.Revocation == nil {
		t.Errorf("a named role has no revocation check: %+v", wcfg)
	}

	cfg.Revocation = []string{"issuer"}
	wcfg, _ = walletConfig(cfg)
	if _, err := walletRevocation(cfg, &wcfg); err != nil {
		t.Fatal(err)
	}
	if vt, _ := wcfg.VerifierTrust.(wallet.X5CVerifierRoots); wcfg.IssuerRevocation == nil || wcfg.StatusRevocation != nil || vt.Revocation != nil {
		t.Error("revocation [issuer] set another role's check, or not the issuer's")
	}

	for name, roles := range map[string][]string{"unknown": {"holder"}, "twice": {"issuer", "issuer"}} {
		cfg.Revocation = roles
		if _, err := walletRevocation(cfg, &wcfg); code(err) != CodeInvalidInput {
			t.Errorf("%s: %v, want invalid_input", name, err)
		}
	}
}

// Outside development, each role whose roots are set must be named in
// "revocation" or "no_revocation_check": one in neither is
// invalid_input naming the roots' key and both lists, one in both is
// refused, and one declined gets certrevocation.NoCheck. Development
// takes a role in neither.
func TestWalletRevocation_ExplicitChoice(t *testing.T) {
	pool := func(name string) string {
		ca, _ := testcert.CA(t, name)
		return pemOf("CERTIFICATE", ca.Raw)
	}
	base := config{
		IssuerRoots: pool("issuer root"), VerifierRoots: pool("verifier root"), RegistrarRoots: pool("registrar root"),
		MdocReaderRoots: pool("reader root"), IssuerMetadataRoots: pool("metadata root"),
	}
	all := []string{"issuer", "issuer_metadata", "registrar", "mdoc_reader", "verifier", "status"}
	keys := map[string]string{
		"issuer": "issuer_roots", "status": "issuer_roots", "issuer_metadata": "issuer_metadata_roots",
		"registrar": "registrar_roots", "mdoc_reader": "mdoc_reader_roots", "verifier": "verifier_roots",
	}
	run := func(cfg config) (revocationCheckers, error) {
		wcfg, err := walletConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, err = walletRevocation(cfg, &wcfg)
		vt, _ := wcfg.VerifierTrust.(wallet.X5CVerifierRoots)
		return revocationCheckers{wcfg.IssuerRevocation, wcfg.StatusRevocation, wcfg.IssuerMetadataRevocation,
			wcfg.RegistrarRevocation, wcfg.MdocReaderRevocation, vt.Revocation}, err
	}

	cfg := base
	cfg.NoRevocationCheck = all
	got, err := run(cfg)
	if err != nil {
		t.Fatalf("every role declined: %v", err)
	}
	for i, c := range got {
		if _, ok := c.(certrevocation.NoCheck); !ok {
			t.Errorf("declined role %d checks with %T, want certrevocation.NoCheck", i, c)
		}
	}
	for _, role := range all {
		cfg := base
		cfg.Revocation = []string{role}
		for _, r := range all {
			if r != role {
				cfg.NoRevocationCheck = append(cfg.NoRevocationCheck, r)
			}
		}
		if _, err := run(cfg); err != nil {
			t.Errorf("%s checked, the rest declined: %v", role, err)
		}
		cfg.Revocation = nil
		_, err := run(cfg)
		if code(err) != CodeInvalidInput || !strings.Contains(err.Error(), keys[role]) ||
			!strings.Contains(err.Error(), "no_revocation_check") || !strings.Contains(err.Error(), `"`+role+`"`) {
			t.Errorf("%s in neither list: %v, want invalid_input naming %s and no_revocation_check", role, err, keys[role])
		}
		cfg.Development = true
		if _, err := run(cfg); err != nil {
			t.Errorf("%s in neither list, in development: %v", role, err)
		}
		cfg.Development = false
		cfg.Revocation = []string{role}
		cfg.NoRevocationCheck = all
		if _, err := run(cfg); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "both") {
			t.Errorf("%s in both lists: %v, want invalid_input", role, err)
		}
	}
	// A role whose roots aren't set needs neither.
	if _, err := run(config{}); err != nil {
		t.Errorf("no roots: %v", err)
	}
	for name, roles := range map[string][]string{"unknown": {"holder"}, "twice": {"issuer", "issuer"}} {
		cfg := base
		cfg.NoRevocationCheck = roles
		if _, err := run(cfg); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "no_revocation_check") {
			t.Errorf("no_revocation_check %s: %v, want invalid_input", name, err)
		}
	}
}

// revocationCheckers are a walletflow.Config's revocation Checkers:
// the issuer's, status lists', issuer metadata's, registrars', mdoc
// readers' and Verifiers'.
type revocationCheckers [6]certrevocation.Checker

// A reader's "revocation" knows "issuer" and "status" only, and its
// SetCRLs refuses what isn't a CRL.
func TestNewProximityReader_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "IACA")
	roots := pemOf("CERTIFICATE", ca.Raw)
	r, err := NewProximityReader(`{"issuer_roots": `+jsonString(roots)+`, "revocation": ["issuer", "status"], "any_issuer_for_any_type": true, "status": "check"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.statusRevocation == nil {
		t.Error("revocation [status] set no status list check")
	}
	if err := r.SetCRLs(pemOf("X509 CRL", testcert.CRL(t, ca, caKey).Raw)); err != nil {
		t.Errorf("SetCRLs: %v", err)
	}
	if err := r.SetCRLs(roots); code(err) != CodeInvalidInput {
		t.Errorf("SetCRLs(a certificate): %v, want invalid_input", err)
	}
	if _, err := NewProximityReader(`{"development": true, "issuer_roots": `+jsonString(roots)+`, "revocation": ["verifier"]}`, nil); code(err) != CodeInvalidInput {
		t.Errorf("revocation [verifier] on a reader: %v, want invalid_input", err)
	}
}

func jsonString(s string) string {
	text, _ := marshal(s)
	return text
}

// A list naming a CA the configuration has that the CA didn't sign —
// forged with the CA's name and key identifier, and a huge CRL number —
// is refused by SetCRLs, dropped from "crls" at construction, and never
// a floor: the CA's genuine lists, older by number, are still taken, by
// SetCRLs and RefreshCRLs alike. Another CA's list, met only on a chain,
// is kept but can't hold a later one to it.
func TestCRLs_ForgedListIsNoFloor(t *testing.T) {
	ca, caKey := testcert.CA(t, "refresh CA")
	fakeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fakeTmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: ca.Subject, SubjectKeyId: ca.SubjectKeyId,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCRLSign | x509.KeyUsageCertSign}
	fakeDER, err := x509.CreateCertificate(rand.Reader, fakeTmpl, fakeTmpl, &fakeKey.PublicKey, fakeKey)
	if err != nil {
		t.Fatal(err)
	}
	fake, err := x509.ParseCertificate(fakeDER)
	if err != nil {
		t.Fatal(err)
	}
	forged := testcert.CRLFromTemplate(t, &x509.RevocationList{Number: big.NewInt(1 << 62), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(24 * time.Hour)}, fake, fakeKey)
	genuine, newer := crlAt(t, ca, caKey, 5, 0, 24*time.Hour), crlAt(t, ca, caKey, 6, 0, 24*time.Hour)
	caPEM := pemOf("CERTIFICATE", ca.Raw)

	t.Run("known CA", func(t *testing.T) {
		s, err := newCRLSet(pemOf("X509 CRL", genuine.Raw), caPEM)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.set(pemOf("X509 CRL", forged.Raw)); err == nil || !strings.Contains(err.Error(), "didn't sign") {
			t.Errorf("set took the forged list: %v", err)
		}
		if err := s.set(pemOf("X509 CRL", newer.Raw)); err != nil {
			t.Errorf("a genuine newer list: %v", err)
		}
		if _, err := s.merge(forged); err == nil {
			t.Error("merge took the forged list")
		}
	})
	t.Run("held from before", func(t *testing.T) {
		// "crls" an earlier version held, with the forged list in it: the
		// CA is known only once the distribution points are configured.
		s, err := newCRLSet(pemOf("X509 CRL", forged.Raw), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.configureRefresh(crlRefreshConfig{points: []crlDistributionPoint{{URL: "http://ca.example/ca.crl", Issuer: caPEM}}}); err != nil {
			t.Fatal(err)
		}
		if got := s.pem(); got != "" {
			t.Errorf("the forged list is still held: %q", got)
		}
		if changed, err := s.merge(genuine); err != nil || !changed {
			t.Errorf("RefreshCRLs' genuine list: %v, %v", changed, err)
		}
	})
	t.Run("unknown CA", func(t *testing.T) {
		s, err := newCRLSet(pemOf("X509 CRL", genuine.Raw), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.set(pemOf("X509 CRL", forged.Raw)); err != nil {
			t.Fatalf("an unverifiable list: %v, want kept, for checks to verify", err)
		}
		if err := s.set(pemOf("X509 CRL", genuine.Raw)); err != nil {
			t.Errorf("the genuine list after the forged one: %v, want taken", err)
		}
		if err := s.set(pemOf("X509 CRL", forged.Raw)); err != nil {
			t.Fatal(err)
		}
		if err := s.configureRefresh(crlRefreshConfig{points: []crlDistributionPoint{{URL: "http://ca.example/ca.crl", Issuer: caPEM}}}); err != nil {
			t.Fatal(err)
		}
		if changed, err := s.merge(newer); err != nil || !changed {
			t.Errorf("RefreshCRLs' genuine list after the forged one: %v, %v", changed, err)
		}
		if got := s.pem(); got != pemOf("X509 CRL", newer.Raw) {
			t.Errorf("crls %q, want the genuine list alone", got)
		}
	})
}
