package verifier_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/registration"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func TestNewAcceptsValidConfig(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(v.ClientID(), "x509_hash:") {
		t.Errorf("ClientID() = %q, want an x509_hash: prefix", v.ClientID())
	}
}

func TestNewRejectsMissingFields(t *testing.T) {
	cases := map[string]func(cfg *verifier.Config, deps *verifier.Dependencies){
		"missing client_certificate": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.ClientCertificate = nil
		},
		"missing response_uri": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.ResponseURI = verifier.Config{}.ResponseURI
		},
		"missing signing_alg": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.SigningAlg = ""
		},
		"unsupported signing_alg": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.SigningAlg = jose.Alg("RS256")
		},
		"missing enc_values_supported": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.EncValuesSupported = nil
		},
		"missing vp_formats_supported": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.VPFormatsSupported = nil
		},
		"missing signer": func(_ *verifier.Config, deps *verifier.Dependencies) {
			deps.Signer = nil
		},
		"missing random": func(_ *verifier.Config, deps *verifier.Dependencies) {
			deps.Random = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t)
			mutate(&cfg, &deps)
			if _, err := verifier.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsSignerCertificateMismatch(t *testing.T) {
	cfg, deps := validConfig(t)
	otherSigner, _ := testSignerAndCert(t)
	deps.Signer = otherSigner
	if _, err := verifier.New(cfg, deps); err == nil {
		t.Fatalf("New = nil error, want error")
	}
}

// nonComparablePublicKey is a crypto.PublicKey (any type at all
// satisfies that interface) that deliberately has no Equal method —
// standing in for a custom, non-stdlib crypto.Signer (an HSM/KMS-backed
// one, say) whose own Public() result isn't one of Go's own key types.
type nonComparablePublicKey struct{}

// nonComparableSigner is a crypto.Signer returning
// nonComparablePublicKey — Sign is never called in this test, so it's
// left unimplemented (a nil-safe panic-on-call stand-in is unnecessary
// here since New never signs anything itself).
type nonComparableSigner struct{}

func (nonComparableSigner) Public() crypto.PublicKey { return nonComparablePublicKey{} }
func (nonComparableSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("not called by this test")
}

// TestNewRejectsSignerWithoutEqualMethod is the regression test for a
// real bug found in a repo-wide security review: New used to do a
// direct (unchecked) type assertion to compare Dependencies.Signer's
// own public key against Config.ClientCertificate's — every stdlib
// key type implements the required Equal method, so this never panics
// with an ordinary ecdsa/rsa/ed25519 signer, but a custom
// crypto.Signer (again, an HSM/KMS-backed one is exactly the kind of
// thing a security-conscious integrator reaches for) whose own public
// key type doesn't implement it caused New to panic instead of
// returning the documented config-mismatch error.
func TestNewRejectsSignerWithoutEqualMethod(t *testing.T) {
	cfg, deps := validConfig(t)
	deps.Signer = nonComparableSigner{}
	if _, err := verifier.New(cfg, deps); err == nil {
		t.Fatalf("New = nil error, want error (not a panic)")
	}
}

func TestNewComputesStableClientID(t *testing.T) {
	cfg, deps := validConfig(t)
	v1, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v2, err := verifier.New(cfg, verifier.Dependencies{Signer: deps.Signer, Random: rand.Reader})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v1.ClientID() != v2.ClientID() {
		t.Errorf("ClientID() differs across two New calls with the same cert: %q vs %q", v1.ClientID(), v2.ClientID())
	}
}

func TestSDJWTVCFormatSupport(t *testing.T) {
	got := verifier.SDJWTVCFormatSupport([]string{"ES256"}, []string{"ES256"})
	want := map[string]any{
		"dc+sd-jwt": map[string]any{
			"sd-jwt_alg_values": []string{"ES256"},
			"kb-jwt_alg_values": []string{"ES256"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SDJWTVCFormatSupport() = %#v, want %#v", got, want)
	}
}

func TestMdocFormatSupport(t *testing.T) {
	got := verifier.MdocFormatSupport()
	want := map[string]any{"mso_mdoc": map[string]any{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MdocFormatSupport() = %#v, want %#v", got, want)
	}
}

// A registration carried in verifier_info must name this Verifier's
// client_id: one issued for another certificate would make every
// Wallet reject the request, so New says so instead.
func TestNewChecksCarriedRegistrationSubject(t *testing.T) {
	registrarKey, registrarCert := testSignerAndCert(t)
	for name, tc := range map[string]struct {
		clientID func(cfg verifier.Config) string
		ok       bool
	}{
		"this Verifier's": {func(cfg verifier.Config) string { return verifier.ClientIDForCertificate(cfg.ClientCertificate) }, true},
		"another's":       {func(verifier.Config) string { return "x509_hash:someone-else" }, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t)
			token, err := registration.Issue(registration.Registration{
				Registrar: "https://registrar.example", ClientID: tc.clientID(cfg), Name: "Example",
				Expires: time.Now().Add(time.Hour),
			}, registrarKey, []*x509.Certificate{registrarCert})
			if err != nil {
				t.Fatal(err)
			}
			cfg.VerifierInfo = []verifier.VerifierInfo{{Format: registration.Format, Data: token}}
			v, err := verifier.New(cfg, deps)
			if tc.ok && (err != nil || v.ClientID() != verifier.ClientIDForCertificate(cfg.ClientCertificate)) {
				t.Errorf("New = %v", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "ClientIDForCertificate")) {
				t.Errorf("New with another client_id's registration: %v, want refused", err)
			}
		})
	}
}
