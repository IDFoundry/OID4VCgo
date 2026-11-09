package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// A Request Object signed by one trusted Verifier but naming another's
// client_id, in its payload and in the invocation link alike, is
// refused: the client_id is bound to the certificate that signed it.
// Otherwise Verifier A could obtain a presentation addressed to B and
// replay it to B.
func TestParseAuthorizationRequest_RefusesAnotherVerifiersClientID(t *testing.T) {
	f := newRequestFixture(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := newTestVerifierWith(t, otherKey, leafUnder(t, f.caCert, f.caKey, &otherKey.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))
	if other.ClientID() == f.clientID {
		t.Fatal("both Verifiers have the same client_id: the test proves nothing")
	}
	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: f.object, ClientID: f.clientID, VerifierTrust: f.trust,
	}); err != nil {
		t.Fatalf("the Verifier's own client_id: %v", err)
	}

	object := f.sign(t, f.key, nil, func(p map[string]any) { p["client_id"] = other.ClientID() })
	_, err = wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object, ClientID: other.ClientID(), VerifierTrust: f.trust,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match x5c leaf") {
		t.Errorf("ParseAuthorizationRequest = %v, want a client_id/x5c leaf mismatch", err)
	}
}
