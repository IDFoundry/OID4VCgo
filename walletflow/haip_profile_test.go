package walletflow_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// haipWallet is f's wallet under ProfileHAIP.
func (f fixture) haipWallet(t *testing.T) *walletflow.Wallet {
	t.Helper()
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		Development: true, IssuanceProfile: walletflow.ProfileHAIP,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// A wallet under ProfileHAIP receives a credential from a HAIP issuer:
// a Wallet Attestation, a DPoP-bound token and a key attestation.
func TestIssuance_HAIPProfile(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	s, err := f.haipWallet(t).StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Fatal(err)
	}
	if result, err := s.RequestCredentials(ctx); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	if n := f.env.Provider.KeyAttestations(); n != 1 {
		t.Errorf("Key Attestations = %d, want 1", n)
	}
}

// Under ProfileHAIP, an access token that isn't DPoP-bound is refused
// (HAIP 1.0 §4), from an issuer that is otherwise HAIP's; the default
// profile takes one (TestIssuance_BearerToken). The test issuer's Token
// Response is rewritten to say Bearer.
func TestIssuance_HAIPProfileRefusesBearerToken(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	httpClient := *f.env.HTTP
	httpClient.Transport = bearerTokenType{f.env.HTTP.Transport}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		Development: true, IssuanceProfile: walletflow.ProfileHAIP,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: &httpClient})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	err = s.RedeemPreAuthorizedCode(ctx, "493536")
	if err == nil {
		_, err = s.RequestCredentials(ctx)
	}
	if !errors.Is(err, walletflow.ErrProfileViolation) {
		t.Errorf("issuance = %v, want ErrProfileViolation", err)
	}
}

// bearerTokenType rewrites a Token Response's token_type DPoP to Bearer.
type bearerTokenType struct{ base http.RoundTripper }

func (b bearerTokenType) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := b.base.RoundTrip(req)
	if err != nil || res.Body == nil {
		return res, err
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	body = bytes.Replace(body, []byte(`"token_type":"DPoP"`), []byte(`"token_type":"Bearer"`), 1)
	res.Body, res.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
	res.Header.Del("Content-Length")
	return res, nil
}
