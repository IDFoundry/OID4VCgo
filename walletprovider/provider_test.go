package walletprovider_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

func TestNewRefuses(t *testing.T) {
	type mutation = func(*testing.T, *walletprovider.Config, *walletprovider.Dependencies)
	leafWith := func(tmpl *x509.Certificate) mutation {
		return func(t *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) {
			ca, caKey := testcert.CA(t, "CA")
			leaf, key := testcert.Issue(t, tmpl, ca, caKey)
			d.Signer, d.Chain = key, []*x509.Certificate{leaf}
		}
	}
	id, _ := url.Parse(identifier)
	cases := []struct {
		name   string
		mutate mutation
		want   string
	}{
		{"no identifier", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) { c.Identifier = "" }, "Identifier"},
		{"http identifier", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.Identifier = "http://provider.example"
		}, "Identifier"},
		{"no client IDs", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) { c.ClientIDs = nil }, "ClientIDs"},
		{"empty client ID", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.ClientIDs = []string{""}
		}, "ClientIDs"},
		{"http status list", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.StatusListBaseURI = "http://provider.example/status"
		}, "StatusListBaseURI"},
		{"status list base with a query", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.StatusListBaseURI = "https://provider.example/status?list=1"
		}, "StatusListBaseURI"},
		{"status list base with an empty query", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.StatusListBaseURI = "https://provider.example/status?"
		}, "StatusListBaseURI"},
		{"status list base ending in a slash", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.StatusListBaseURI = "https://provider.example/status/"
		}, "StatusListBaseURI"},
		{"status list period shorter than a Wallet Attestation", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.WalletAttestationTTL, c.StatusListPeriod = 3*time.Hour, 2*time.Hour
		}, "StatusListPeriod"},
		{"status list period shorter than a Key Attestation", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.KeyAttestationTTL, c.StatusListPeriod = 12*time.Hour, 6*time.Hour
		}, "StatusListPeriod"},
		{"status list period over a year", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.StatusListPeriod = walletprovider.MaxStatusListPeriod + time.Second
		}, "StatusListPeriod"},
		{"status list period not whole seconds", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.StatusListPeriod = 3*time.Hour + time.Millisecond
		}, "StatusListPeriod"},
		{"http wallet link", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.WalletLink = "http://wallet.example"
		}, "WalletLink"},
		{"wallet attestation for days", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.WalletAttestationTTL = 72 * time.Hour
		}, "WalletAttestationTTL"},
		{"key attestation for days", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.KeyAttestationTTL = 72 * time.Hour
		}, "KeyAttestationTTL"},
		{"long challenges", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.ChallengeTTL = time.Hour
		}, "ChallengeTTL"},
		{"list size not a multiple of 4", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.StatusListSize = 1023
		}, "StatusListSize"},
		{"no platforms", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) { c.Policy.Platforms = nil }, "Platforms"},
		{"platform without levels", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.Policy.Platforms[walletprovider.PlatformIOS] = walletprovider.PlatformPolicy{}
		}, "SecurityLevels"},
		{"user authentication claimed unconditionally", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.Policy.KeyStorage = append(c.Policy.KeyStorage, walletprovider.KeyStorageRule{
				Platform: walletprovider.PlatformAndroid, SecurityLevel: walletprovider.SecurityLevelTEE,
				UserAuthenticationLevels: []attestation.AttackPotentialResistance{attestation.ISO18045High},
			})
		}, "without requiring"},
		{"rule claiming nothing", func(_ *testing.T, c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.Policy.KeyStorage = []walletprovider.KeyStorageRule{{Platform: walletprovider.PlatformIOS, SecurityLevel: walletprovider.SecurityLevelSecureEnclave}}
		}, "claims nothing"},
		{"no evidence verifiers", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.Evidence = nil }, "nothing is attested without platform evidence"},
		{"duplicate evidence kind", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) {
			d.Evidence = append(d.Evidence, walletprovidertest.FakeVerifier{})
		}, "more than once"},
		{"no instance store", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.Instances = nil }, "Instances"},
		{"typed nil instance store", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) {
			d.Instances = (*walletprovider.MemoryInstanceStore)(nil)
		}, "Instances"},
		{"no instance key store", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.InstanceKeys = nil }, "InstanceKeys"},
		{"no challenge store", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.Challenges = nil }, "Challenges"},
		{"no index store", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.StatusIndices = nil }, "StatusIndices"},
		{"no random source", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.Random = nil }, "Random"},
		{"no signer", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.Signer = nil }, "Signer"},
		{"no chain", func(_ *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) { d.Chain = nil }, "Chain"},
		{"chain of another key", func(t *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) {
			d.Signer = newKey(t)
		}, "isn't the signer's"},
		{"self-signed signer", func(t *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) {
			leaf, key := testcert.SelfSignedLeaf(t, "Wallet Provider")
			d.Signer, d.Chain = key, []*x509.Certificate{leaf}
		}, "self-signed"},
		{"chain with the anchor", func(t *testing.T, _ *walletprovider.Config, d *walletprovider.Dependencies) {
			ca, caKey := testcert.CA(t, "CA")
			leaf, key := testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "WP"}, URIs: []*url.URL{id}}, ca, caKey)
			d.Signer, d.Chain = key, []*x509.Certificate{leaf, ca}
		}, "trust anchor"},
		{"signer certificate not naming the identifier", leafWith(&x509.Certificate{Subject: pkix.Name{CommonName: "WP"}}), "URI subject alternative name"},
		{"signer certificate for TLS", leafWith(&x509.Certificate{
			Subject: pkix.Name{CommonName: "WP"}, URIs: []*url.URL{id}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}), "extended key usage"},
		{"signer certificate not for signing", leafWith(&x509.Certificate{
			Subject: pkix.Name{CommonName: "WP"}, URIs: []*url.URL{id}, KeyUsage: x509.KeyUsageKeyEncipherment,
		}), "digital signatures"},
		{"expired signer certificate", leafWith(&x509.Certificate{
			Subject: pkix.Name{CommonName: "WP"}, URIs: []*url.URL{id},
			NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
		}), "isn't valid now"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{t: time.Now()}
			cfg, deps := baseConfig(), baseDeps(t, c)
			tc.mutate(t, &cfg, &deps)
			_, err := walletprovider.New(cfg, deps)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

func TestNewAcceptsAnIntermediate(t *testing.T) {
	ca, caKey := testcert.CA(t, "Root")
	inter, interKey := testcert.Intermediate(t, "Intermediate", ca, caKey)
	id, _ := url.Parse(identifier)
	leaf, key := testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "WP"}, URIs: []*url.URL{id}}, inter, interKey)
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Signer, d.Chain = key, []*x509.Certificate{leaf, inter}
	})
	in, _ := h.register(kindFake)
	jwt, err := h.walletAttestation(in.ID, &newKey(t).PublicKey, kindFake)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := jose.DecodeUnverified(jwt)
	if err != nil {
		t.Fatal(err)
	}
	want := []any{base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(inter.Raw)}
	if !reflect.DeepEqual(header["x5c"], want) {
		t.Fatalf("x5c is %v, want the signer's certificate and the intermediate", header["x5c"])
	}
}

// failingReader fails every read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestChallengeRandomFailure(t *testing.T) {
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) { d.Random = failingReader{} })
	if _, err := h.p.Challenge(t.Context(), walletprovider.PurposeInstance); err == nil {
		t.Fatal("Challenge succeeded without randomness")
	}
}
