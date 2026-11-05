package walletflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// durableKeyStore is a MemoryKeyStore declaring durable custody, as a
// production KeyStore (the Secure Enclave's, kept in the Keychain) does.
type durableKeyStore struct{ *MemoryKeyStore }

func (durableKeyStore) KeyCustody() keys.KeyCustody { return keys.KeyCustody{Durable: true} }

// durableAuthorizations is a MemoryAuthorizationStore claiming to be
// Durable, standing in for a persistent one.
type durableAuthorizations struct{ *MemoryAuthorizationStore }

func (durableAuthorizations) Durable() bool { return true }

// attestingProvider is a WalletProvider the client never calls here.
type attestingProvider struct{}

func (attestingProvider) WalletAttestation(context.Context, string, crypto.PublicKey) (string, error) {
	return "", nil
}

func (attestingProvider) KeyAttestation(context.Context, crypto.PublicKey, []*ecdsa.PublicKey, string) (string, error) {
	return "", nil
}

// productionWallet is a production wallet over deps' stores.
func productionWallet(t *testing.T, deps Dependencies) *Wallet {
	t.Helper()
	w, err := New(declined(Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb", IssuerRoots: x509.NewCertPool()}), deps)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// At production assurance, an issuance's fapigo/client builds — over a
// durable AuthorizationStore and KeyStore — and receiving credentials is
// refused, saying why, without them.
func TestProductionAssurance(t *testing.T) {
	ctx := context.Background()
	durable := Dependencies{
		Keys: durableKeyStore{NewMemoryKeyStore()}, Credentials: NewMemoryCredentialStore(),
		Provider: attestingProvider{}, Authorizations: durableAuthorizations{NewMemoryAuthorizationStore()},
	}
	w := productionWallet(t, durable)
	if err := w.checkIssuance(); err != nil {
		t.Fatalf("checkIssuance: %v", err)
	}
	s := &Issuance{w: w, offer: oid4vci.CredentialOffer{CredentialIssuer: "https://issuer.example"}}
	var err error
	if s.instanceKey, err = newKey(ctx, w.deps.Keys, KeyPurposeInstance); err != nil {
		t.Fatal(err)
	}
	if s.dpopKey, err = w.newDPoPKey(ctx); err != nil {
		t.Fatal(err)
	}
	issuer, endpoints, err := wallet.AuthorizationServerMetadata{
		Issuer: "https://as.example", AuthorizationEndpoint: "https://as.example/authorize",
		TokenEndpoint: "https://as.example/token", PushedAuthorizationRequestEndpoint: "https://as.example/par",
	}.ClientEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.oauthClient(issuer, endpoints, "https://as.example", client.StaticAttestation("eyJ.attestation.jwt")); err != nil {
		t.Fatalf("the OAuth client doesn't build at production assurance: %v", err)
	}

	for name, change := range map[string]func(*Dependencies){
		"custody":            func(d *Dependencies) { d.Keys = NewMemoryKeyStore() },
		"crypto/rand.Reader": func(d *Dependencies) { d.Random = strings.NewReader("not random") },
		"system clock":       func(d *Dependencies) { d.Clock = time.Now },
	} {
		deps := durable
		change(&deps)
		// Refused by New, not first when a holder tries to receive one.
		if _, err := New(declined(Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb", IssuerRoots: x509.NewCertPool()}), deps); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("without %s: New = %v", name, err)
		}
	}
	// A Durable Authorizations store is the authorization code grant's
	// alone: nothing else keeps an authorization across a suspension. A
	// wallet with a RedirectURI is refused one in New; one without
	// receives only pre-authorized codes.
	deps := durable
	deps.Authorizations = NewMemoryAuthorizationStore()
	if _, err := New(declined(Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb", IssuerRoots: x509.NewCertPool()}), deps); err == nil || !strings.Contains(err.Error(), "Durable") {
		t.Errorf("an authorization code wallet without a Durable Authorizations: New = %v", err)
	}
	w, err = New(declined(Config{ClientID: "wallet", IssuerRoots: x509.NewCertPool()}), deps)
	if err != nil {
		t.Fatalf("a pre-authorized code wallet without a Durable Authorizations: New = %v", err)
	}
	if err := w.checkIssuance(); err != nil {
		t.Errorf("a pre-authorized code wallet without a Durable Authorizations: checkIssuance = %v", err)
	}
	if err := w.checkAuthorizationCode(); err == nil {
		t.Error("checkAuthorizationCode passed without a RedirectURI")
	}
}

// durableGrants is a MemoryGrantStore claiming to be Durable.
type durableGrants struct{ *MemoryGrantStore }

func (durableGrants) Durable() bool { return true }

// At production assurance, asking for refresh tokens needs a durable
// GrantStore: a refresh token kept only in memory is lost on a restart.
func TestProductionAssurance_RefreshNeedsDurableGrants(t *testing.T) {
	deps := Dependencies{
		Keys: durableKeyStore{NewMemoryKeyStore()}, Credentials: NewMemoryCredentialStore(),
		Provider: attestingProvider{}, Authorizations: durableAuthorizations{NewMemoryAuthorizationStore()},
	}
	cfg := declined(Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb", IssuerRoots: x509.NewCertPool(), RequestRefresh: true})
	if _, err := New(cfg, deps); err == nil || !strings.Contains(err.Error(), "Durable Dependencies.Grants") {
		t.Errorf("with a memory GrantStore: New = %v", err)
	}
	deps.Grants = durableGrants{NewMemoryGrantStore()}
	w, err := New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.checkIssuance(); err != nil {
		t.Errorf("with a durable GrantStore: checkIssuance = %v", err)
	}
}

// A Config value with no meaning is refused, not taken as the default.
func TestNew_RefusesMeaninglessChoices(t *testing.T) {
	deps := Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()}
	for name, cfg := range map[string]Config{
		"issuance profile": {IssuanceProfile: 9, Development: true},
		"copy policy":      {CopyPolicy: 9, Development: true},
		"batch size":       {BatchSize: -3, Development: true},
	} {
		if _, err := New(cfg, deps); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// In production, two roles whose pools may share an anchor need a leaf
// policy on each: otherwise a Verifier's certificate could sign
// credentials, or an issuer's pass for a Verifier.
func TestNew_RoleSeparation(t *testing.T) {
	deps := Dependencies{Keys: durableKeyStore{NewMemoryKeyStore()}, Credentials: NewMemoryCredentialStore(), Authorizations: durableAuthorizations{NewMemoryAuthorizationStore()}}
	issuerCA, _ := testcert.CA(t, "issuer CA")
	verifierCA, _ := testcert.CA(t, "verifier CA")
	otherIssuerCA, _ := testcert.CA(t, "another issuer CA")
	reissuedIssuerCA, _ := testcert.CA(t, "issuer CA")
	shared, verifiers := x509.NewCertPool(), x509.NewCertPool()
	shared.AddCert(issuerCA)
	verifiers.AddCert(verifierCA)
	// issuers holds shared's anchor and one more; reissued holds a
	// certificate with the same subject as shared's, under another key.
	issuers, reissued, sharedCopy := x509.NewCertPool(), x509.NewCertPool(), x509.NewCertPool()
	issuers.AddCert(issuerCA)
	issuers.AddCert(otherIssuerCA)
	reissued.AddCert(reissuedIssuerCA)
	sharedCopy.AddCert(issuerCA)
	policy := func(*x509.Certificate, [][]*x509.Certificate) error { return nil }
	for name, tc := range map[string]struct {
		cfg Config
		ok  bool
	}{
		"one pool for issuers and Verifiers":       {Config{IssuerRoots: shared, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared}}, false},
		"one pool, only the issuer narrowed":       {Config{IssuerRoots: shared, IssuerLeafPolicy: policy, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared}}, false},
		"one pool, both narrowed":                  {Config{IssuerRoots: shared, IssuerLeafPolicy: policy, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared, LeafPolicy: policy}}, true},
		"one pool, Verifiers' by pointer":          {Config{IssuerRoots: shared, VerifierTrust: &wallet.X5CVerifierRoots{Roots: shared}}, false},
		"one pool by pointer, both narrowed":       {Config{IssuerRoots: shared, IssuerLeafPolicy: policy, VerifierTrust: &wallet.X5CVerifierRoots{Roots: shared, LeafPolicy: policy}}, true},
		"separate pools":                           {Config{IssuerRoots: shared, VerifierTrust: wallet.X5CVerifierRoots{Roots: verifiers}}, true},
		"one pool for issuers and readers, in dev": {Config{IssuerRoots: shared, MdocReaderRoots: shared, Development: true}, true},
		"one pool for metadata and Verifiers":      {Config{IssuerRoots: verifiers, IssuerMetadataRoots: shared, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared, LeafPolicy: policy}}, false},
		"one pool for credentials and metadata":    {Config{IssuerRoots: shared, IssuerLeafPolicy: policy, IssuerMetadataRoots: shared}, false},
		"one pool for metadata, both narrowed":     {Config{IssuerRoots: shared, IssuerLeafPolicy: policy, IssuerMetadataRoots: shared, IssuerMetadataLeafPolicy: policy}, true},
		"separate metadata pool":                   {Config{IssuerRoots: shared, IssuerMetadataRoots: verifiers}, true},
		"overlapping pools":                        {Config{IssuerRoots: issuers, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared}}, false},
		"overlapping pools, only one narrowed":     {Config{IssuerRoots: issuers, IssuerLeafPolicy: policy, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared}}, false},
		"overlapping pools, both narrowed":         {Config{IssuerRoots: issuers, IssuerLeafPolicy: policy, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared, LeafPolicy: policy}}, true},
		"overlapping registrar pool":               {Config{IssuerRoots: verifiers, RegistrarRoots: issuers, MdocReaderRoots: shared, MdocReaderLeafPolicy: policy}, false},
		"equal pools built twice":                  {Config{IssuerRoots: shared, IssuerMetadataRoots: sharedCopy}, false},
		"a reissued anchor's subject":              {Config{IssuerRoots: shared, VerifierTrust: wallet.X5CVerifierRoots{Roots: reissued}}, false},
		"overlapping pools, in dev":                {Config{IssuerRoots: issuers, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared}, Development: true}, true},
		"one pool for both credential formats":     {Config{IssuerRoots: shared, MdocIssuerRoots: shared, MdocIssuerRootsByDocType: map[string]*x509.CertPool{"a": shared}}, true},
		"one pool for mdoc issuers and Verifiers":  {Config{IssuerRoots: verifiers, MdocIssuerRoots: shared, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared, LeafPolicy: policy}}, false},
		"one pool for mdoc issuers, both narrowed": {Config{MdocIssuerRoots: shared, MdocIssuerLeafPolicy: policy, VerifierTrust: wallet.X5CVerifierRoots{Roots: shared, LeafPolicy: policy}}, true},
		"a document type's pool and readers":       {Config{IssuerRoots: verifiers, MdocIssuerRootsByDocType: map[string]*x509.CertPool{"a": issuers}, MdocReaderRoots: shared, MdocReaderLeafPolicy: policy}, false},
	} {
		_, err := New(declined(tc.cfg), deps)
		refused := err != nil && strings.Contains(err.Error(), "may share a trust anchor")
		if refused == tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A system pool whose roots the platform keeps, unlisted, may hold any
// role's anchor, so another role beside it needs a leaf policy on each.
func TestNew_RoleSeparationSystemPool(t *testing.T) {
	system, err := x509.SystemCertPool()
	if err != nil || !opaqueSystemPool(system) {
		t.Skip("this platform's system pool lists its roots")
	}
	deps := Dependencies{Keys: durableKeyStore{NewMemoryKeyStore()}, Credentials: NewMemoryCredentialStore(), Authorizations: durableAuthorizations{NewMemoryAuthorizationStore()}}
	verifierCA, _ := testcert.CA(t, "verifier CA")
	verifiers := x509.NewCertPool()
	verifiers.AddCert(verifierCA)
	policy := func(*x509.Certificate, [][]*x509.Certificate) error { return nil }
	if _, err := New(declined(Config{IssuerRoots: system, VerifierTrust: wallet.X5CVerifierRoots{Roots: verifiers}}), deps); err == nil || !strings.Contains(err.Error(), "may share a trust anchor") {
		t.Errorf("system IssuerRoots beside VerifierTrust: %v", err)
	}
	if _, err := New(declined(Config{IssuerRoots: system, IssuerLeafPolicy: policy, VerifierTrust: wallet.X5CVerifierRoots{Roots: verifiers, LeafPolicy: policy}}), deps); err != nil {
		t.Errorf("system IssuerRoots, both narrowed: %v", err)
	}
}

// In production, New takes only a native app's redirect URI, the only
// kind a resumed issuance's fapigo/client accepts at production
// assurance: an https one would fail only once ResumeIssuance runs.
func TestProductionRedirectURI(t *testing.T) {
	deps := redirectDeps()
	for uri, ok := range map[string]bool{
		"com.example.wallet:/cb":    true,
		"http://127.0.0.1/cb":       true,
		"http://[::1]:8080/cb":      true,
		"https://wallet.example/cb": false,
		"http://wallet.example/cb":  false,
		"http://localhost/cb":       false,
		"/cb":                       false,
	} {
		w, err := New(declined(Config{ClientID: "wallet", RedirectURI: uri, IssuerRoots: x509.NewCertPool()}), deps)
		switch {
		case ok && err != nil:
			t.Errorf("New(RedirectURI %q) = %v, want it taken", uri, err)
		case !ok && (err == nil || !strings.Contains(err.Error(), "Config.RedirectURI")):
			t.Errorf("New(RedirectURI %q) = %v, want it refused", uri, err)
		}
		if w == nil {
			continue
		}
		// Every redirect New takes, a resumed issuance's client takes too.
		if err := issuanceClient(t, w, true); err != nil {
			t.Errorf("RedirectURI %q: a resumed issuance's client doesn't build: %v", uri, err)
		}
	}
	dev, err := New(Config{ClientID: "wallet", RedirectURI: "https://wallet.example/cb", IssuerRoots: x509.NewCertPool(), Development: true}, deps)
	if err != nil || dev == nil {
		t.Fatalf("New(Development, https RedirectURI) = %v, want it taken", err)
	}
}
