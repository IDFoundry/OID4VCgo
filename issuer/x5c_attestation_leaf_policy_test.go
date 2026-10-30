package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// attestationProviderURL is the Wallet Provider the test attestations
// name, and their signing certificates too.
var attestationProviderURL = &url.URL{Scheme: "https", Host: "provider.example"}

// otherRoleLeaves are certificates an ecosystem CA shared with Wallet
// Providers issues for other roles, which DefaultAttestationLeafPolicy
// refuses to take as a Wallet Provider's.
func otherRoleLeaves() map[string]*x509.Certificate {
	tmpl := func(ku x509.KeyUsage, eku []x509.ExtKeyUsage, unknown ...asn1.ObjectIdentifier) *x509.Certificate {
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: "other role"}, URIs: []*url.URL{attestationProviderURL},
			KeyUsage: ku, ExtKeyUsage: eku, UnknownExtKeyUsage: unknown,
		}
	}
	ds := x509.KeyUsageDigitalSignature
	return map[string]*x509.Certificate{
		"a TLS server's":                  tmpl(ds, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
		"a TLS client's beside a private": tmpl(ds, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}),
		"an OCSP signer's":                tmpl(ds, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}),
		"an mdoc reader's":                tmpl(ds, nil, asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}),
		"an mDL document signer's":        tmpl(ds, nil, mdoc.MDLDocumentSignerEKU),
		"one not for digital signatures":  tmpl(x509.KeyUsageKeyEncipherment, nil),
		"a code signer's":                 tmpl(ds, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}),
		"a time stamping authority's":     tmpl(ds, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}),
		"an email protection certificate": tmpl(ds, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}),
	}
}

// signKeyAttestation is a key attestation for attested, signed with key
// under leaf, claiming iso_18045_high key storage.
func signKeyAttestation(t *testing.T, key *ecdsa.PrivateKey, leaf *x509.Certificate, attested *ecdsa.PrivateKey, nonce string) string {
	t.Helper()
	exp := time.Now().Add(time.Hour).Unix()
	ka, err := attestation.Issue(key, jose.ES256, attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(leaf.Raw)}}, attestation.Claims{
		Issuer: attestationProviderURL.String(), IssuedAt: time.Now().Unix(), ExpiresAt: &exp, Nonce: nonce,
		AttestedKeys: []json.RawMessage{jwkJSON(t, &attested.PublicKey)},
		KeyStorage:   []attestation.AttackPotentialResistance{"iso_18045_high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ka
}

// By default, X5CAttestationVerifier and X5CProofBindingKeyResolver
// refuse a certificate issued for another role under their roots;
// AnyAttestationLeaf takes it, and a Wallet Provider's certificate
// passes either way.
func TestDefaultAttestationLeafPolicy(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared ecosystem CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	provider, _ := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "wallet provider"}, URIs: []*url.URL{attestationProviderURL}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, caKey)
	cases := otherRoleLeaves()
	cases["a Wallet Provider's"] = nil
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			leaf, key := provider, (*ecdsa.PrivateKey)(nil)
			if tmpl != nil {
				leaf, key = testcert.Issue(t, tmpl, ca, caKey)
			}
			wantRefused := tmpl != nil
			if err := issuer.DefaultAttestationLeafPolicy(leaf, nil); wantRefused != (err != nil) {
				t.Errorf("DefaultAttestationLeafPolicy = %v, want refused %v", err, wantRefused)
			}
			if key == nil || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				// Chain verification refuses the latter whatever the policy.
				return
			}
			parsed, err := attestation.Parse(signKeyAttestation(t, key, leaf, testP256Key(t), ""))
			if err != nil {
				t.Fatal(err)
			}
			for _, binding := range []issuer.AttestationIssuerBinding{issuer.AttestationIssuerUnbound, issuer.AttestationIssuerInCertificate} {
				v := issuer.X5CAttestationVerifier{Roots: roots, Revocation: certrevocation.NoCheck{}, IssuerBinding: binding}
				if _, _, err := v.ResolveAttestationKey(context.Background(), parsed); err == nil || !strings.Contains(err.Error(), "leaf certificate policy") {
					t.Errorf("binding %d: key attestation accepted (%v)", binding, err)
				}
				v.LeafPolicy = issuer.AnyAttestationLeaf
				if _, _, err := v.ResolveAttestationKey(context.Background(), parsed); err != nil {
					t.Errorf("binding %d, AnyAttestationLeaf: %v", binding, err)
				}
			}
			header := map[string]any{"x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)}}
			r := issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
			if _, _, err := r.ResolveProofBindingKey(context.Background(), header); err == nil {
				t.Error("X5CProofBindingKeyResolver accepted the proof's certificate")
			}
			r.LeafPolicy = issuer.AnyAttestationLeaf
			if _, _, err := r.ResolveProofBindingKey(context.Background(), header); err != nil {
				t.Errorf("X5CProofBindingKeyResolver, AnyAttestationLeaf: %v", err)
			}
		})
	}
}

// DefaultAttestationLeafPolicy refuses a leaf whose every path runs
// through an intermediate CA restricted to TLS certificates.
func TestDefaultAttestationLeafPolicy_Intermediate(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	tlsCA, tlsCAKey := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "TLS CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, root, rootKey)
	leaf, _ := testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, KeyUsage: x509.KeyUsageDigitalSignature}, tlsCA, tlsCAKey)
	if err := issuer.DefaultAttestationLeafPolicy(leaf, [][]*x509.Certificate{{leaf, tlsCA, root}}); err == nil {
		t.Error("a leaf under a TLS-only CA was accepted")
	}
	if err := issuer.DefaultAttestationLeafPolicy(leaf, [][]*x509.Certificate{{leaf, root}}); err != nil {
		t.Errorf("a leaf directly under the root: %v", err)
	}
}

// A TLS server's certificate under roots shared with Wallet Providers
// can't vouch, at the Credential Endpoint, for a software key as stored
// in secure hardware.
func TestCredentialEndpoint_RefusesKeyAttestationFromOtherRole(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared ecosystem CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf, leafKey := testcert.Issue(t, otherRoleLeaves()["a TLS server's"], ca, caKey)
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		jwtType := c.ProofTypesSupported[oid4vci.ProofTypeJWT]
		jwtType.KeyAttestationsRequired = &oid4vci.KeyAttestationRequirement{KeyStorage: []string{"iso_18045_high"}}
		c.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: jwtType}
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: roots, Revocation: certrevocation.NoCheck{}, IssuerBinding: issuer.AttestationIssuerInCertificate}
	})
	softwareKey := testP256Key(t)
	n := f.issueNonce(t)
	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {jwtProofWithKeyAttestation(t, softwareKey, n, signKeyAttestation(t, leafKey, leaf, softwareKey, n))}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err == nil || len(resp.Credentials) != 0 {
		t.Fatalf("issued %d credential(s), err %v; want the key attestation refused", len(resp.Credentials), err)
	}
}

// Under AssuranceProduction an X5CAttestationVerifier needs an explicit
// binding decision: a binding, or SingleWalletProvider with
// AttestationIssuerUnbound, which no other binding takes.
func TestNewProductionRequiresAttestationBinding(t *testing.T) {
	cfg, deps := productionIssuer(t)
	unbound := issuer.X5CAttestationVerifier{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}
	for name, av := range map[string]issuer.AttestationVerifier{"by value": unbound, "by pointer": &unbound} {
		deps.AttestationVerifier = av
		if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "SingleWalletProvider") {
			t.Errorf("%s: New with AttestationIssuerUnbound = %v, want it refused", name, err)
		}
	}
	inCertificate := unbound
	inCertificate.IssuerBinding = issuer.AttestationIssuerInCertificate
	deps.AttestationVerifier = inCertificate
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Errorf("New with AttestationIssuerInCertificate: %v", err)
	}
	inCertificate.SingleWalletProvider = true
	deps.AttestationVerifier = inCertificate
	if _, err := issuer.New(validConfig(t), withAttestationVerifier(validDependencies(t), inCertificate)); err == nil || !strings.Contains(err.Error(), "SingleWalletProvider") {
		t.Errorf("New with SingleWalletProvider and a binding = %v, want it refused", err)
	}
	unbound.SingleWalletProvider = true
	deps.AttestationVerifier = unbound
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Errorf("New with SingleWalletProvider: %v", err)
	}
}

func withAttestationVerifier(deps issuer.Dependencies, av issuer.AttestationVerifier) issuer.Dependencies {
	deps.AttestationVerifier = av
	return deps
}
