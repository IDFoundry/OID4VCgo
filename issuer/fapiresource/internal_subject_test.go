package fapiresource_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
)

// A resource verifier that reports no internal subject — one resolving
// only the subjects clients are given — is refused rather than giving
// every holder's Grant the same empty Subject, which would make their
// credentials, deferred transactions and notifications one holder's.
func TestVerifyRefusesTokenWithoutInternalSubject(t *testing.T) {
	ca, caKey := testcert.CA(t, "client CA")
	cert, _ := testcert.Leaf(t, "wallet", ca, caKey)
	endpoint, _ := url.Parse("https://issuer.example.com/credential")
	rv, err := resource.NewVerifier(resource.Config{
		ResourceURLs: issuerURLs(t), PairwiseResolution: resource.PairwiseClientSubjectsOnly,
		Assurance: resource.AssuranceDevelopment, Limits: resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: time.Minute},
	}, resource.Dependencies{
		AccessTokens: certBoundTokens{cert: cert, clientID: "wallet-1", claims: map[string]json.RawMessage{
			// A pairwise sub (fapigo's pairwise_sector claim), which a
			// verifier resolving only client subjects doesn't map back.
			"pairwise_sector": json.RawMessage(`"wallet.example.com"`),
		}}, Replay: memstore.NewReplayStore(),
		Revocation: resource.NoRevocation{}, Clock: resource.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := fapiresource.New(rv)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/credential", nil)
	r.Header.Set("Authorization", "Bearer token-1")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	grant, err := v.Verify(r, endpoint)
	if err == nil || !strings.Contains(err.Error(), "internal subject") {
		t.Errorf("Verify = %+v, %v; want refused for its missing internal subject", grant, err)
	}
}
