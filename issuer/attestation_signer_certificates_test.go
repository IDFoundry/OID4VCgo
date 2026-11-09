package issuer_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// An AttestationStatusChecker sees a key attestation's x5c chain as its
// SignerCertificates only when the chain's leaf holds the key the
// attestation verified with: an x5c naming another key, which a key
// resolver that ignores x5c would let through, says nothing about who
// signed it, and a checker binding the status list's signer to it would
// trust whoever that is.
func TestRequestCredential_AttestationSignerCertificatesHoldTheKey(t *testing.T) {
	ca, caKey := testcert.CA(t, "attester CA")
	for name, tc := range map[string]struct {
		leafKeyIsSigners bool
		wantCerts        bool
	}{
		"x5c of the signer's key": {true, true},
		"x5c of another key":      {false, false},
	} {
		t.Run(name, func(t *testing.T) {
			var checked []issuer.VerifiedKeyAttestation
			f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
				deps.AttestationStatus = attestationStatusFunc(func(_ context.Context, c issuer.VerifiedKeyAttestation) error {
					checked = append(checked, c)
					return nil
				})
			})
			leafPub := testP256Key(t).Public()
			if tc.leafKeyIsSigners {
				leafPub = f.attestationSigner.Public()
			}
			leaf := testcert.LeafFor(t, "attester", leafPub, ca, caKey)
			key := testP256Key(t)
			// Signed directly: attestation.Issue refuses an x5c whose leaf
			// isn't the signer's.
			payload, err := json.Marshal(map[string]any{
				"iat": time.Now().Unix(), "nonce": f.issueNonce(t), "attested_keys": []json.RawMessage{jwkJSON(t, &key.PublicKey)},
			})
			if err != nil {
				t.Fatal(err)
			}
			att, err := jose.Sign(jose.ES256, f.attestationSigner, map[string]any{
				"typ": attestation.TypHeader, "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
			}, payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
				SDJWTClaims:               testSDJWTClaims(),
			}); err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
			if len(checked) != 1 {
				t.Fatalf("status checker saw %d attestations, want 1", len(checked))
			}
			got := checked[0].SignerCertificates
			switch {
			case tc.wantCerts && (len(got) != 1 || !got[0].Equal(leaf)):
				t.Errorf("SignerCertificates = %v, want the x5c leaf", subjects(got))
			case !tc.wantCerts && got != nil:
				t.Errorf("SignerCertificates = %v, want nil", subjects(got))
			}
		})
	}
}

func subjects(certs []*x509.Certificate) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Subject.CommonName
	}
	return out
}
