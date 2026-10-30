package issuer_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// x5cProof is a jwt proof conveying its key by x5c, a's signing
// certificate.
func x5cProof(t *testing.T, a *attesterCRLs, nonce string) string {
	t.Helper()
	payload := fmt.Sprintf(`{"aud":%q,"iat":%d,"nonce":%q}`, testIssuer, time.Now().Unix(), nonce)
	proof, err := jose.Sign(jose.ES256, a.leafKey, map[string]any{
		"typ": "openid4vci-proof+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(a.leaf.Raw)},
	}, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// deferProofs defers a request with proofs, returning the
// transaction_id.
func deferProofs(t *testing.T, f deferralFixture, proofs ...string) string {
	t.Helper()
	resp, err := f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs},
		Defer:                     &issuer.Deferral{},
	})
	if err != nil {
		t.Fatalf("RequestCredential (deferred): %v", err)
	}
	return resp.TransactionID
}

// deferX5CProof defers a request whose one jwt proof conveys its key by
// x5c, a's signing certificate, returning the transaction_id.
func deferX5CProof(t *testing.T, f deferralFixture, a *attesterCRLs) string {
	t.Helper()
	return deferProofs(t, f, x5cProof(t, a, f.issueNonce(t)))
}

// TestDeferral_RechecksX5CProofKeyBesideJWK: in a batch whose proofs
// convey one key by x5c and another by jwk, only the x5c one has a
// header to check again: the batch issues while it's valid, and is
// denied once it's revoked.
func TestDeferral_RechecksX5CProofKeyBesideJWK(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		a := newAttesterCRLs(t)
		f := newDeferralFixture(t, proofKeysUnder(a))
		ctx := context.Background()
		n := f.issueNonce(t)
		txID := deferProofs(t, f, x5cProof(t, a, n), buildJWTProof(t, testP256Key(t), testIssuer, n))
		record, err := f.store.Get(ctx, txID)
		if err != nil || len(record.ProofKeyHeaders) != 2 || record.ProofKeyHeaders[0] == nil || record.ProofKeyHeaders[1] != nil {
			t.Fatalf("record.ProofKeyHeaders = %q, %v; want the x5c proof's header, then none", record.ProofKeyHeaders, err)
		}
		if revoked {
			a.revoke(t)
		}
		err = f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
		if revoked != errors.Is(err, issuer.ErrDeferredProofKey) || (!revoked && err != nil) {
			t.Errorf("revoked %v: IssueDeferredCredential = %v", revoked, err)
		}
	}
}

// proofKeysUnder makes deps resolve x5c-conveyed proof keys under a's
// CA, checking a's CRLs.
func proofKeysUnder(a *attesterCRLs) func(*issuer.Config, *issuer.Dependencies) {
	return func(_ *issuer.Config, deps *issuer.Dependencies) {
		roots := x509.NewCertPool()
		roots.AddCert(a.provider.ca)
		deps.ProofBindingKeys = issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: a}
	}
}

// TestDeferral_RechecksX5CProofKey: a binding key a jwt proof conveyed
// by x5c is resolved again when the deferred transaction is issued. A
// certificate revoked while it was pending denies it; one whose
// revocation can't be decided now leaves it pending, to issue once it
// can; one still valid issues.
func TestDeferral_RechecksX5CProofKey(t *testing.T) {
	a := newAttesterCRLs(t)
	outcomes := a.undecided(t)
	outcomes["revoked"] = func() { a.revoke(t) }
	outcomes["valid"] = func() {}
	for name, set := range outcomes {
		t.Run(name, func(t *testing.T) {
			f := newDeferralFixture(t, proofKeysUnder(a))
			a.restore(t)
			ctx := context.Background()
			txID := deferX5CProof(t, f, a)
			if record, err := f.store.Get(ctx, txID); err != nil || len(record.ProofKeyHeaders) != 1 || record.ProofKeyHeaders[0] == nil {
				t.Fatalf("record = %+v, %v; want the proof's header kept", record, err)
			}

			set()
			err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
			switch name {
			case "valid":
				if err != nil {
					t.Fatalf("IssueDeferredCredential: %v", err)
				}
			case "revoked":
				if !errors.Is(err, issuer.ErrDeferredProofKey) || !errors.Is(err, certrevocation.ErrRevoked) {
					t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredProofKey for the revoked certificate", err)
				}
				_, pollErr := f.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: txID})
				assertIssuerError(t, pollErr, issuer.ErrorCredentialRequestDenied)
			default:
				if !errors.Is(err, issuer.ErrDeferredProofKeyTrustUnknown) || errors.Is(err, issuer.ErrDeferredProofKey) {
					t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredProofKeyTrustUnknown, the transaction kept", err)
				}
				a.restore(t)
				if err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
					t.Fatalf("IssueDeferredCredential once revocation can be checked: %v", err)
				}
			}
		})
	}
}

// TestDeferral_X5CProofKeyNeedsResolver: a transaction whose proof key
// was resolved through ProofBindingKeys can't be issued by an issuer
// without one, which can't check it again: it's denied.
func TestDeferral_X5CProofKeyNeedsResolver(t *testing.T) {
	a := newAttesterCRLs(t)
	var cfg issuer.Config
	var deps issuer.Dependencies
	f := newDeferralFixture(t, proofKeysUnder(a), func(c *issuer.Config, d *issuer.Dependencies) { cfg, deps = *c, *d })
	txID := deferX5CProof(t, f, a)

	// Another Issuer over the same store, without the resolver.
	deps.ProofBindingKeys = nil
	other, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New without ProofBindingKeys: %v", err)
	}
	if err := other.IssueDeferredCredential(context.Background(), txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); !errors.Is(err, issuer.ErrDeferredProofKey) {
		t.Fatalf("IssueDeferredCredential without ProofBindingKeys = %v, want ErrDeferredProofKey", err)
	}
}

// TestDeferral_JWKProofKeyKeepsNoHeader: a key conveyed by jwk carries
// no trust to check again, so the transaction keeps no proof header.
func TestDeferral_JWKProofKeyKeepsNoHeader(t *testing.T) {
	f := newDeferralFixture(t)
	txID, _ := f.deferOne(t)
	record, err := f.store.Get(context.Background(), txID)
	if err != nil || record.ProofKeyHeaders != nil {
		t.Fatalf("record.ProofKeyHeaders = %v, %v; want none", record.ProofKeyHeaders, err)
	}
}
