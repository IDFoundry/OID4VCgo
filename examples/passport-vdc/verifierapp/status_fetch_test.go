package verifierapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFetchStatusList_RefusesRedirects: the status list is fetched from
// exactly the https URI the credential names, never from wherever a
// redirect points (possibly plain http).
func TestFetchStatusList_RefusesRedirects(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/statuslists/1", http.StatusFound)
	}))
	defer redirector.Close()

	a := &App{cfg: Config{HTTP: redirector.Client()}}
	if _, err := a.fetchStatusList(context.Background(), redirector.URL+"/statuslists/1", false); err == nil {
		t.Error("a redirected status list fetch succeeded")
	}
	if followed {
		t.Error("the redirect was followed")
	}
	if _, err := a.fetchStatusList(context.Background(), target.URL+"/statuslists/1", false); err == nil {
		t.Error("a plain-http status list URI was fetched")
	}
}
