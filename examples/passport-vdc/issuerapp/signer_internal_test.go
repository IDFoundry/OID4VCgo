package issuerapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// testCRLURL is the distribution point the tests' identities name.
const testCRLURL = "https://issuer.example" + CRLPath

// TestIdentity_KeepsCAKey: the CA keeps its key, saved with the
// identity, to sign its CRL, and it and its signers name the CRL's
// distribution point.
func TestIdentity_KeepsCAKey(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	id, err := loadOrCreateIdentity(dir, now, testCRLURL)
	if err != nil {
		t.Fatal(err)
	}
	if id.caKey == nil || !id.caKey.PublicKey.Equal(id.caCert.PublicKey) || id.caCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatal("the CA has no key of its own, or can't sign a CRL")
	}
	for _, c := range []*x509.Certificate{id.caCert, id.documentSignerCert, id.metadataSignerCert} {
		if !slices.Equal(c.CRLDistributionPoints, []string{testCRLURL}) {
			t.Errorf("%q names CRL distribution points %v, want %s", c.Subject.CommonName, c.CRLDistributionPoints, testCRLURL)
		}
	}
	again, err := loadOrCreateIdentity(dir, now, testCRLURL)
	if err != nil {
		t.Fatal(err)
	}
	if !again.caCert.Equal(id.caCert) || again.caKey == nil || !again.caKey.Equal(id.caKey) {
		t.Error("the CA key wasn't kept across a reload")
	}
}

// TestIdentity_MigratesWithoutCAKey: an identity file from before the
// CA kept its key, which can't sign a CRL, is replaced by a new CA that
// can; so is one naming another distribution point.
func TestIdentity_MigratesWithoutCAKey(t *testing.T) {
	now := time.Now()
	for name, write := range map[string]func(issuerIdentity) issuerIdentity{
		"no CA key":        func(id issuerIdentity) issuerIdentity { id.caKey = nil; return id },
		"another CRL's DP": func(id issuerIdentity) issuerIdentity { return id },
	} {
		dir := t.TempDir()
		crlURL := testCRLURL
		if name == "another CRL's DP" {
			crlURL = "https://elsewhere.example" + CRLPath
		}
		old, err := newIssuerIdentity(now, crlURL)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveIdentity(dir, write(old)); err != nil {
			t.Fatal(err)
		}
		migrated, err := loadOrCreateIdentity(dir, now, testCRLURL)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if migrated.caCert.Equal(old.caCert) || migrated.caKey == nil || !slices.Equal(migrated.caCert.CRLDistributionPoints, []string{testCRLURL}) {
			t.Errorf("%s: the old identity was kept, or its replacement can't publish a CRL", name)
		}
		if again, err := loadOrCreateIdentity(dir, now, testCRLURL); err != nil || !again.caCert.Equal(migrated.caCert) {
			t.Errorf("%s: the replacement wasn't saved: %v", name, err)
		}
	}
}

// TestIdentity_RefusesAnotherCAKey: a CA key that isn't the CA
// certificate's is a damaged file, not a silent new CA.
func TestIdentity_RefusesAnotherCAKey(t *testing.T) {
	dir := t.TempDir()
	id, err := newIssuerIdentity(time.Now(), testCRLURL)
	if err != nil {
		t.Fatal(err)
	}
	id.caKey = id.documentSigner
	if err := saveIdentity(dir, id); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateIdentity(dir, time.Now(), testCRLURL); err == nil {
		t.Error("an identity whose CA key isn't its CA's was accepted")
	}
}

// TestRevokeDocumentSigner_Persists: revoking the document signer puts
// it on the CA's CRL and a new signer in its place, and a restart keeps
// both.
func TestRevokeDocumentSigner_Persists(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	app, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := app.IssuerCertificate()
	if err := app.RevokeDocumentSigner(); err != nil {
		t.Fatalf("RevokeDocumentSigner: %v", err)
	}
	rotated := app.IssuerCertificate()
	if rotated.Equal(old) || rotated.CheckSignatureFrom(app.IssuerCACertificate()) != nil ||
		!slices.Equal(rotated.CRLDistributionPoints, old.CRLDistributionPoints) {
		t.Fatal("the new document signer is the old one, isn't the CA's, or names another CRL")
	}
	revoked := func(a *App) bool {
		return slices.ContainsFunc(a.RevokedSigners(), func(r democrl.Revoked) bool { return r.Serial == old.SerialNumber.String() })
	}
	if !revoked(app) {
		t.Error("the old document signer isn't on the CRL")
	}

	restarted, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.IssuerCertificate().Equal(rotated) || !restarted.IssuerCACertificate().Equal(app.IssuerCACertificate()) {
		t.Error("a restart didn't keep the CA and the new document signer")
	}
	if !revoked(restarted) {
		t.Error("a restart dropped the revocation")
	}
	list, err := restarted.crl.List()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(list.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool { return e.SerialNumber.Cmp(old.SerialNumber) == 0 }) {
		t.Error("the CRL served after a restart doesn't list the revoked signer")
	}
	if _, err := democrl.Open(filepath.Join(dir, crlFile), app.IssuerCACertificate(), app.id.caKey, nil); err != nil {
		t.Errorf("the CRL state file: %v", err)
	}
}

// stateConfigs are an issuer's Configs keeping its state in dir: its
// status list's indices in a file there, or in a database.
var stateConfigs = map[string]func(t *testing.T, dir string) Config{
	"file": testConfig,
	"database": func(t *testing.T, dir string) Config {
		t.Helper()
		cfg := testConfig(t, dir)
		db, sealer, err := OpenDatabase(filepath.Join(dir, "stores.db"), filepath.Join(dir, "stores.key"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		cfg.Database, cfg.DatabaseSealer = db, sealer
		return cfg
	},
}

// TestRevokeDocumentSigner_RevokesItsCredentialsAcrossRestart: the
// signer's credentials are revoked on the saved status list, so a
// restart keeps them revoked; an entry saved before entries named their
// signer is the signer's in use at start; one a request under way
// allocates for the revoked signer is revoked from the start; one
// revoked by its handle stays revoked; and the new signer's credentials
// stay valid. Its indices are kept in the state directory, or in the
// database.
func TestRevokeDocumentSigner_RevokesItsCredentialsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	for name, config := range stateConfigs {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config(t, dir)
			app, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			old := signerID(app.IssuerCertificate())
			sdjwt, err := app.statusList.allocate(ctx, "dc+sd-jwt", false, old, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			mdocIdx, err := app.statusList.allocate(ctx, "mso_mdoc", false, old, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			// Saved before entries named their signer.
			legacy, err := app.statusList.allocate(ctx, "mso_mdoc", false, "", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			app, err = New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := app.statusList.entries[legacy].Signer; got != old {
				t.Fatalf("an entry without a signer is %q's, want the signer in use at start, %q", got, old)
			}

			if err := app.RevokeDocumentSigner(); err != nil {
				t.Fatal(err)
			}
			inFlight, err := app.statusList.allocate(ctx, "dc+sd-jwt", false, old, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := app.statusList.allocate(ctx, "mso_mdoc", false, signerID(app.IssuerCertificate()), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			byHandle, err := app.statusList.allocate(ctx, "dc+sd-jwt", false, signerID(app.IssuerCertificate()), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if found, err := app.statusList.revokeHandle(ctx, app.statusList.entries[byHandle].Handle); !found || err != nil {
				t.Fatalf("revokeHandle = %v, %v", found, err)
			}

			restarted, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			bits := statusesOf(t, restarted.statusList)
			for name, idx := range map[string]int{"SD-JWT VC": sdjwt, "mdoc": mdocIdx, "legacy": legacy, "in flight": inFlight, "by handle": byHandle} {
				if bits[idx] != 1 || !restarted.statusList.entries[idx].Revoked {
					t.Errorf("%s credential: status %d after a restart, want revoked", name, bits[idx])
				}
			}
			if bits[fresh] != 0 || restarted.statusList.entries[fresh].Revoked {
				t.Error("the new signer's credential was revoked")
			}
			_, err = os.Stat(filepath.Join(dir, statusIndicesFile))
			if inFile := err == nil; inFile != (cfg.Database == nil) {
				t.Errorf("%s exists: %v, want it only without a database", statusIndicesFile, inFile)
			}
		})
	}
}

// TestStatusPublishers_ServeAllocatorStatuses: the JWT and CWT
// publishers both serve the Allocator's statuses, a revocation as soon
// as they're invalidated.
func TestStatusPublishers_ServeAllocatorStatuses(t *testing.T) {
	ctx := context.Background()
	app, err := New(testConfig(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := app.statusList.allocate(ctx, "mso_mdoc", false, signerID(app.IssuerCertificate()), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	published := func() (jwt, cwt statuslist.StatusType) {
		t.Helper()
		s := app.current()
		pub := s.key.Public()
		token, err := s.jwtList.Token(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		ref := app.statusList.ref(idx)
		if jwt, _, err = statuslist.Check(string(token), pub, oid4vci.ES256, ref, statuslist.VerifyOptions{}); err != nil {
			t.Fatalf("the JWT list: %v", err)
		}
		if token, err = s.cwtList.Token(ctx, true); err != nil {
			t.Fatal(err)
		}
		ref.URI = app.mdocStatusListURI
		if cwt, _, err = statuslist.CheckCWT(token, pub, haip.RecommendedCOSEAlgorithm, ref, statuslist.VerifyOptions{}); err != nil {
			t.Fatalf("the CWT list: %v", err)
		}
		return jwt, cwt
	}
	if jwt, cwt := published(); jwt != statuslist.StatusValid || cwt != statuslist.StatusValid {
		t.Fatalf("published statuses %v (JWT), %v (CWT), want valid", jwt, cwt)
	}
	if err := app.statusList.allocator.SetStatus(ctx, app.statusList.ref(idx), statuslist.StatusInvalid); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*statuslist.Publisher{app.current().jwtList, app.current().cwtList} {
		p.Invalidate()
	}
	if jwt, cwt := published(); jwt != statuslist.StatusInvalid || cwt != statuslist.StatusInvalid {
		t.Errorf("published statuses %v (JWT), %v (CWT) after SetStatus, want invalid", jwt, cwt)
	}
}

// testConfig is an issuer's Config for tests that build an App
// directly, keeping its state in dir.
func testConfig(t *testing.T, dir string) Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := democert.Create(&x509.Certificate{
		Subject: pkix.Name{CommonName: "test Wallet Provider CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		IssuerURL: "https://issuer.example", CSCAPool: &cms.GenericCertPool{}, StateDir: dir,
		Wallet: WalletClient{
			ClientID: "wallet", RedirectURIs: []string{"https://wallet.example/callback"},
			ProviderIssuer: "https://provider.example", ProviderCA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Raw}),
		},
	}
}
