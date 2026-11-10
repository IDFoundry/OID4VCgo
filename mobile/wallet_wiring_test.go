package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Each role's *_require_eku reaches the policy walletflow checks that
// role's certificates with: a certificate under its roots without the
// usage is refused, one with it accepted. roleEKU's own test checks the
// policy; this checks walletConfig hands it on.
func TestWalletConfig_RoleEKUsReachWalletflow(t *testing.T) {
	ca, _ := testcert.CA(t, "role root")
	roots := pemOf("CERTIFICATE", ca.Raw)
	const oid = "1.3.6.1.4.1.99999.7"
	usage := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}
	with, without := ekuCert(t, nil, []asn1.ObjectIdentifier{usage}), ekuCert(t, nil, nil)
	for name, tc := range map[string]struct {
		cfg    config
		policy func(walletflow.Config) func(*x509.Certificate, [][]*x509.Certificate) error
	}{
		"verifier_require_eku": {
			config{Development: true, VerifierRoots: roots, VerifierRequireEKU: oid},
			func(c walletflow.Config) func(*x509.Certificate, [][]*x509.Certificate) error {
				vt, _ := c.VerifierTrust.(wallet.X5CVerifierRoots)
				return vt.LeafPolicy
			},
		},
		"issuer_require_eku": {
			config{Development: true, IssuerRoots: roots, IssuerRequireEKU: oid},
			func(c walletflow.Config) func(*x509.Certificate, [][]*x509.Certificate) error {
				return c.IssuerLeafPolicy
			},
		},
		"issuer_metadata_require_eku": {
			config{Development: true, IssuerMetadataRoots: roots, IssuerMetadataRequireEKU: oid},
			func(c walletflow.Config) func(*x509.Certificate, [][]*x509.Certificate) error {
				return c.IssuerMetadataLeafPolicy
			},
		},
		"registrar_require_eku": {
			config{Development: true, RegistrarRoots: roots, RegistrarRequireEKU: oid},
			func(c walletflow.Config) func(*x509.Certificate, [][]*x509.Certificate) error {
				return c.RegistrarLeafPolicy
			},
		},
	} {
		wcfg, err := walletConfig(tc.cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		policy := tc.policy(wcfg)
		if policy == nil {
			t.Errorf("%s: no leaf policy", name)
			continue
		}
		if err := policy(without, nil); err == nil {
			t.Errorf("%s: a certificate without the usage accepted", name)
		}
		if err := policy(with, nil); err != nil {
			t.Errorf("%s: a certificate with the usage: %v", name, err)
		}
	}
}

// Outside development, walletConfig refuses roles' roots sharing an
// anchor without the EKUs telling their certificates apart
// (checkRoleRoots), as NewWallet does.
func TestWalletConfig_ProductionRefusesSharedRoots(t *testing.T) {
	ca, _ := testcert.CA(t, "shared root")
	shared := pemOf("CERTIFICATE", ca.Raw)
	if _, err := walletConfig(config{IssuerRoots: shared, VerifierRoots: shared}); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "verifier_require_eku") {
		t.Errorf("walletConfig: %v, want invalid_input naming verifier_require_eku", err)
	}
	cfg := `{"issuer_roots":` + jsonString(shared) + `,"verifier_roots":` + jsonString(shared) +
		`,"no_revocation_check":["issuer","status","verifier"]}`
	if _, err := NewWallet(cfg, newGoKeyStore(), newGoCredentialStore(), nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "verifier_require_eku") {
		t.Errorf("NewWallet: %v, want invalid_input naming verifier_require_eku", err)
	}
}

// Left out, require_issuer_name and allow_foreign_iss keep walletflow's
// defaults: the issuer's name isn't required, and a foreign iss is
// refused.
func TestWalletConfig_IssuerNameDefaults(t *testing.T) {
	wcfg, err := walletConfig(config{Development: true})
	if err != nil {
		t.Fatal(err)
	}
	if wcfg.AllowForeignIss || wcfg.RequireIssuerName {
		t.Errorf("AllowForeignIss %v, RequireIssuerName %v; want both false", wcfg.AllowForeignIss, wcfg.RequireIssuerName)
	}
}

// Outside development and tests, the wallet leaves walletflow its own
// client, so tls_pins must reach walletflow.Config for it to pin.
func TestWalletHTTP_ProductionPinsReachWalletflow(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	pins := map[string][]string{"issuer.example": {pin}}
	var wcfg walletflow.Config
	client, err := walletHTTP(config{TLSPins: pins}, &wcfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client != nil {
		t.Error("a client made, want walletflow's own")
	}
	if len(wcfg.TLSPins) != 1 || len(wcfg.TLSPins["issuer.example"]) != 1 || wcfg.TLSPins["issuer.example"][0] != pin {
		t.Errorf("walletflow.Config.TLSPins = %v, want %v", wcfg.TLSPins, pins)
	}
}

// ephemeralKeys is a goKeyStore that says its keys don't survive the
// app quitting.
type ephemeralKeys struct{ *goKeyStore }

func (ephemeralKeys) Durable() bool { return false }

// Outside development, a wallet receiving credentials needs each store
// durable: the KeyStore (its KeyCustody), and the CredentialStore that
// keeps refresh grants (with request_refresh) and authorizations in
// progress (with a redirect_uri). Each is refused on its own.
func TestNewWallet_ProductionNeedsEachStoreDurable(t *testing.T) {
	ca, _ := testcert.CA(t, "issuer root")
	prev := testHTTP.Swap(nil)
	defer testHTTP.Store(prev)
	ephemeralCreds := func() *goCredentialStore {
		s := newGoCredentialStore()
		s.ephemeral = true
		return s
	}
	for name, tc := range map[string]struct {
		keys    KeyStore
		creds   *goCredentialStore
		refresh bool
		refused string // "" for taken
	}{
		"all durable":                    {newGoKeyStore(), newGoCredentialStore(), true, ""},
		"keys not durable":               {ephemeralKeys{newGoKeyStore()}, newGoCredentialStore(), false, "Dependencies.Keys"},
		"grants not durable":             {newGoKeyStore(), ephemeralCreds(), true, "Dependencies.Grants"},
		"authorizations not durable":     {newGoKeyStore(), ephemeralCreds(), false, "Dependencies.Authorizations"},
		"keys not durable, with refresh": {ephemeralKeys{newGoKeyStore()}, newGoCredentialStore(), true, "Dependencies.Keys"},
		"all durable, no refresh":        {newGoKeyStore(), newGoCredentialStore(), false, ""},
	} {
		cfg, _ := json.Marshal(map[string]any{
			"client_id": "wallet", "redirect_uri": "com.example.wallet:/callback", "issuer_roots": pemOf("CERTIFICATE", ca.Raw),
			"no_revocation_check": []string{"issuer", "status"}, "request_refresh": tc.refresh,
		})
		_, err := NewWallet(string(cfg), tc.keys, tc.creds, nil)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want refused naming %s", name, err, tc.refused)
		}
	}
}

// crlWithoutNumber is a CRL from ca, signed with key, issued at
// thisUpdate, with no CRL number (no extensions at all), which
// x509.CreateRevocationList can't make.
func crlWithoutNumber(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, thisUpdate time.Time) *x509.RevocationList {
	t.Helper()
	ecdsaWithSHA256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	tbs, err := asn1.Marshal(struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time `asn1:"utc"`
		NextUpdate time.Time `asn1:"utc"`
	}{1, ecdsaWithSHA256, asn1.RawValue{FullBytes: ca.RawSubject}, thisUpdate.UTC(), thisUpdate.Add(24 * time.Hour).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, ecdsaWithSHA256, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if list.Number != nil || list.CheckSignatureFrom(ca) != nil {
		t.Fatalf("crlWithoutNumber: number %v, signature %v", list.Number, list.CheckSignatureFrom(ca))
	}
	return list
}

// Where a CA's lists carry no CRL number, an earlier thisUpdate is the
// older list, refused as one with a lower number is.
func TestCRLs_RefusesAnOlderListWithoutNumbers(t *testing.T) {
	ca, caKey := testcert.CA(t, "revocation test CA")
	now := time.Now().Truncate(time.Second)
	s, err := newCRLSet(pemOf("X509 CRL", crlWithoutNumber(t, ca, caKey, now).Raw), pemOf("CERTIFICATE", ca.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.set(pemOf("X509 CRL", crlWithoutNumber(t, ca, caKey, now.Add(-time.Hour)).Raw)); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("an earlier thisUpdate: %v, want refused as older", err)
	}
	if err := s.set(pemOf("X509 CRL", crlWithoutNumber(t, ca, caKey, now.Add(time.Minute)).Raw)); err != nil {
		t.Errorf("a later thisUpdate: %v", err)
	}
}

// forgedCRL is a list naming ca, with its subject and key identifier and
// a huge CRL number, signed by another key.
func forgedCRL(t *testing.T, ca *x509.Certificate) *x509.RevocationList {
	t.Helper()
	fakeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: ca.Subject, SubjectKeyId: ca.SubjectKeyId,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &fakeKey.PublicKey, fakeKey)
	if err != nil {
		t.Fatal(err)
	}
	fake, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testcert.CRLFromTemplate(t, &x509.RevocationList{Number: big.NewInt(1 << 62)}, fake, fakeKey)
}

// A CA certificate in the roots of a role "revocation" names is one the
// wallet knows, though not in crl_issuers: SetCRLs refuses a list naming
// it that it didn't sign, and takes its genuine one.
func TestSetCRLs_RootsOfCheckedRolesAreKnown(t *testing.T) {
	for _, tc := range []struct{ key, role string }{
		{"issuer_roots", "issuer"},
		{"mdoc_issuer_roots", "status"},
		{"verifier_roots", "verifier"},
		{"registrar_roots", "registrar"},
		{"mdoc_reader_roots", "mdoc_reader"},
		{"issuer_metadata_roots", "issuer_metadata"},
	} {
		ca, caKey := testcert.CA(t, tc.role+" root")
		cfg, _ := json.Marshal(map[string]any{"development": true, tc.key: pemOf("CERTIFICATE", ca.Raw), "revocation": []string{tc.role}})
		w, err := NewWallet(string(cfg), newGoKeyStore(), newGoCredentialStore(), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.key, err)
		}
		if err := w.SetCRLs(pemOf("X509 CRL", forgedCRL(t, ca).Raw)); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "didn't sign") {
			t.Errorf("%s: a forged list: %v, want invalid_input", tc.key, err)
		}
		if err := w.SetCRLs(pemOf("X509 CRL", testcert.CRL(t, ca, caKey).Raw)); err != nil {
			t.Errorf("%s: the genuine list: %v", tc.key, err)
		}
	}
}
