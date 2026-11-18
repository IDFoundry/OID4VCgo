package walletflow_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// A failed fetch of a by-reference offer's credential_offer_uri, or of a
// presentation request's request_uri, never quotes it: either serves
// what it refers to, a pre-authorized code included, to whoever reads
// the logs the error ends up in. The cause, a refused connection here,
// is still there to classify.
func TestStartIssuanceAndPresentation_FetchErrorOmitsTheReference(t *testing.T) {
	// A port nothing listens on: the connection is refused, as a TLS
	// failure, a reset or a timeout on a real network would fail it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	w, err := walletflow.New(walletflow.Config{
		Development: true, IssuerRoots: x509.NewCertPool(),
		CredentialIssuers: []string{"https://issuer.example"},
		VerifierTrust:     wallet.X5CVerifierRoots{Roots: x509.NewCertPool()},
	}, walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "Zr8-reference-0f3a"
	ctx := context.Background()
	_, issueErr := w.StartIssuance(ctx, "openid-credential-offer://?credential_offer_uri="+url.QueryEscape("https://"+addr+"/credential-offer/"+secret))
	_, presentErr := w.StartPresentation(ctx, "openid4vp://?client_id=x509_hash%3Aabc&request_uri="+url.QueryEscape("https://"+addr+"/request/"+secret))
	for _, err := range []error{issueErr, presentErr} {
		var urlErr *url.Error
		var opErr *net.OpError
		switch {
		case err == nil:
			t.Fatal("want a fetch failure")
		case strings.Contains(err.Error(), secret):
			t.Errorf("err = %v; the reference is in it", err)
		case !errors.As(err, &urlErr) || strings.Contains(urlErr.URL, secret):
			t.Errorf("err = %v; want a *url.Error without the reference", err)
		case !errors.As(err, &opErr):
			t.Errorf("err = %v; want the refused connection kept", err)
		}
	}
}
