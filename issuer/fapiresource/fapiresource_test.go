package fapiresource_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
)

// noTokens resolves no access token.
type noTokens struct{}

func (noTokens) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	return resource.ResolvedAccessToken{}, errors.New("unknown token")
}

func TestNewRequiresVerifier(t *testing.T) {
	if _, err := fapiresource.New(nil); err == nil {
		t.Error("New(nil) succeeded, want an error")
	}
}

// TestVerifyRefusesMissingToken checks a request without an access
// token fails, and that the failure is written as resource.WriteError
// writes it. The success path is covered end to end
// by cmd/conformance-issuer's full-flow tests.
func TestVerifyRefusesMissingToken(t *testing.T) {
	rv, err := resource.NewVerifier(resource.Config{
		Limits: resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: time.Minute},
	}, resource.Dependencies{
		AccessTokens: noTokens{}, Replay: memstore.NewReplayStore(),
		Revocation: resource.NoRevocation{}, Clock: resource.SystemClock{},
	})
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	v, err := fapiresource.New(rv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	endpoint, _ := url.Parse("https://issuer.example.com/credential")
	_, err = v.Verify(httptest.NewRequest(http.MethodPost, "/credential", nil), endpoint)
	if err == nil {
		t.Fatal("Verify succeeded without an access token")
	}
	got, want := httptest.NewRecorder(), httptest.NewRecorder()
	v.WriteError(got, err)
	resource.WriteError(want, err)
	if got.Code != want.Code || got.Code < 400 || got.Body.String() != want.Body.String() {
		t.Errorf("WriteError = %d %q, want resource.WriteError's %d %q", got.Code, got.Body, want.Code, want.Body)
	}
}
