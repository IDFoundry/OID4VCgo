package issuer_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// TestRequestCredential_StatusListAttestationStatus: a key attestation
// whose status list entry is VALID is accepted; one revoked or
// suspended is invalid_proof; one whose list can't be fetched, or is
// signed by another key than the attestation's, is a server error.
func TestRequestCredential_StatusListAttestationStatus(t *testing.T) {
	ca, caKey := testcert.CA(t, "wallet provider CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for name, tc := range map[string]struct {
		idx     int
		publish bool
		other   bool
		want    string
	}{
		"valid":                  {idx: 0, publish: true, want: "valid"},
		"invalid":                {idx: 1, publish: true, want: "revoked"},
		"suspended":              {idx: 2, publish: true, want: "revoked"},
		"list unavailable":       {idx: 0, want: "unknown"},
		"list signed by another": {idx: 0, publish: true, other: true, want: "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := teststatuslist.ServeJWT(t)
			cache := statuslist.NewCache(statuslist.CacheOptions{})
			f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
				deps.AttestationStatus = issuer.StatusListAttestationStatus{
					Checker:       statuslist.Checker{Fetcher: srv.Fetcher, Roots: roots, Cache: cache},
					RequireStatus: true,
				}
			})
			if tc.publish {
				key, chain := f.attestationSigner, []*x509.Certificate{testcert.LeafFor(t, "attester", &f.attestationSigner.PublicKey, ca, caKey)}
				if tc.other {
					leaf, otherKey := testcert.Leaf(t, "another attester", ca, caKey)
					key, chain = otherKey, []*x509.Certificate{leaf}
				}
				srv.Publish(t, key, chain, 0, uint8(statuslist.StatusInvalid), uint8(statuslist.StatusSuspended))
			}
			holderKey := testP256Key(t)
			nonce := f.issueNonce(t)
			exp := time.Now().Add(time.Hour).Unix()
			att, err := attestation.Issue(f.attestationSigner, jose.ES256, attestation.Header{}, attestation.Claims{
				IssuedAt: time.Now().Unix(), ExpiresAt: &exp, Nonce: nonce,
				AttestedKeys: []json.RawMessage{jwkJSON(t, &holderKey.PublicKey)}, Status: srv.Claim(tc.idx),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
				SDJWTClaims:               testSDJWTClaims(),
			})
			assertAttestationStatusOutcome(t, tc.want, err)
		})
	}
}

// TestNewChecksStatusListAttestationStatus: New runs
// StatusListAttestationStatus's CheckConfiguration, refusing an
// unhardened Fetcher, a missing Cache or a missing Revocation under
// AssuranceProduction, and options that would replace its binding at
// every level.
func TestNewChecksStatusListAttestationStatus(t *testing.T) {
	adequate := statuslist.Checker{
		Roots: x509.NewCertPool(), Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
		Cache: statuslist.NewCache(statuslist.CacheOptions{}),
	}
	for name, tc := range map[string]struct {
		production bool
		mutate     func(c *statuslist.Checker)
		want       string
	}{
		"production":                {true, func(*statuslist.Checker) {}, ""},
		"unhardened fetcher":        {true, func(c *statuslist.Checker) { c.Fetcher.AllowPrivate = true }, "HardenedForProduction"},
		"no cache":                  {true, func(c *statuslist.Checker) { c.Cache = nil }, "Cache"},
		"no revocation":             {true, func(c *statuslist.Checker) { c.Options.Revocation = nil }, "Revocation"},
		"unhardened in development": {false, func(c *statuslist.Checker) { c.Fetcher.AllowPrivate = true }, ""},
		"unbound signer":            {false, func(c *statuslist.Checker) { c.Options.UnboundSigner = statuslist.AnyListSigner }, "UnboundSigner"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionAssuredConfigAndDeps(t)
			if !tc.production {
				cfg.Assurance = issuer.AssuranceDevelopment
			}
			deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}, SingleWalletProvider: true}
			c := adequate
			tc.mutate(&c)
			deps.AttestationStatus = &issuer.StatusListAttestationStatus{Checker: c}
			_, err := issuer.New(cfg, deps)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("New: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), "attestation_status") || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("New = %v, want an attestation_status error naming %s", err, tc.want)
			}
		})
	}
}
