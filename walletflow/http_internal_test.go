package walletflow

import (
	"strings"
	"testing"
)

// TestNew_DefaultHTTPRefusesPrivateAddresses: without Dependencies.HTTP,
// the wallet's own requests — token, credential, response_uri — can't
// be pointed at its own network: the default client won't dial a
// private or loopback address outside Development.
func TestNew_DefaultHTTPRefusesPrivateAddresses(t *testing.T) {
	w, err := New(Config{ClientID: "wallet", RedirectURI: "app:/cb"}, Dependencies{
		Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"https://10.0.0.1/token", "https://127.0.0.1/token", "https://169.254.169.254/latest"} {
		resp, err := w.deps.HTTP.Get(target)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("GET %s succeeded, want refused", target)
		}
	}
}

// TestCleanText: an authorization callback's error text drops control
// characters and is cut short.
func TestCleanText(t *testing.T) {
	got := cleanText("denied\r\nINFO forged" + strings.Repeat("x", 1000))
	if strings.ContainsAny(got, "\r\n") || len([]rune(got)) != maxErrorTextRunes+1 || !strings.HasSuffix(got, "…") {
		t.Errorf("cleanText = %q", got)
	}
}
