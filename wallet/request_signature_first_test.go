package wallet_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// countingTrust is a VerifierTrust counting the chains it's asked to
// verify.
type countingTrust struct {
	wallet.VerifierTrust
	calls *int
}

func (c countingTrust) VerifyVerifierChain(chain [][]byte) (*x509.Certificate, error) {
	*c.calls++
	return c.VerifierTrust.VerifyVerifierChain(chain)
}

// A Request Object's signature is checked with its presented x5c leaf
// before its chain is verified: one whose signature fails costs no
// path building.
func TestParseAuthorizationRequest_SignatureBeforeChain(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	dot := strings.LastIndexByte(built.RequestObject, '.')
	tampered := built.RequestObject[:dot+1] + strings.Repeat("A", len(built.RequestObject)-dot-1)
	var calls int
	_, err = wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: tampered, ClientID: clientID, VerifierTrust: countingTrust{trust, &calls},
	})
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("err = %v, want a signature failure", err)
	}
	if calls != 0 {
		t.Errorf("the chain was verified %d times for a request whose signature fails", calls)
	}
	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: countingTrust{trust, &calls},
	}); err != nil || calls != 1 {
		t.Errorf("the genuine request: %v, %d chain verifications; want accepted after one", err, calls)
	}
}
