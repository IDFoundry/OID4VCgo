package walletapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore_SaveAndList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	s := Store{Dir: dir}
	if got, err := s.List(); err != nil || len(got) != 0 {
		t.Fatalf("List on a missing store = %v, %v; want empty, nil", got, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t0 := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"passport_sdjwt", "passport/../mdoc"} {
		if _, err := s.Save(Received{ConfigurationID: id, Format: "f", Credential: "c", HolderKey: key}, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("Save(%s): %v", id, err)
		}
	}

	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].ConfigurationID != "passport_sdjwt" || got[1].ConfigurationID != "passport/../mdoc" {
		t.Fatalf("List = %+v", got)
	}
	for _, st := range got {
		if filepath.Dir(st.Path) != dir {
			t.Errorf("%s escaped the store directory", st.Path)
		}
		info, err := os.Stat(st.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v (%v), want 0600", st.Path, info.Mode().Perm(), err)
		}
		block, _ := pem.Decode([]byte(st.HolderKeyPEM))
		stored, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil || !stored.Equal(key) {
			t.Errorf("holder key didn't round-trip (%v)", err)
		}
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("store dir mode = %v (%v), want 0700", info.Mode().Perm(), err)
	}
}

func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestBrowserApprover_ReturnsCallback checks the redirect's query comes
// back with the flow's own session handle.
func TestBrowserApprover_ReturnsCallback(t *testing.T) {
	const query = "code=abc&state=xyz&iss=https%3A%2F%2Fissuer"
	redirect := "http://" + freeLoopbackPort(t) + "/callback"
	b := BrowserApprover{
		RedirectURI: redirect,
		// Stand in for the browser: after the holder approves, the
		// issuer redirects it to the wallet's callback.
		Show: func(string) {
			go func() {
				if resp, err := http.Get(redirect + "?" + query); err == nil {
					_ = resp.Body.Close()
				}
			}()
		},
		Timeout: 5 * time.Second,
	}
	cb, err := b.Approve(context.Background(), "https://issuer/authorize?request_uri=x")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if cb.Query != query {
		t.Errorf("callback = %+v, want query %q", cb, query)
	}
}

func TestBrowserApprover_TimesOut(t *testing.T) {
	b := BrowserApprover{RedirectURI: "http://" + freeLoopbackPort(t) + "/callback", Timeout: 50 * time.Millisecond}
	if _, err := b.Approve(context.Background(), "https://issuer/authorize"); err == nil {
		t.Error("Approve with no callback = nil error, want a timeout")
	}
}

func TestBrowserApprover_RejectsNonLoopbackRedirect(t *testing.T) {
	b := BrowserApprover{RedirectURI: "https://wallet.example/callback"}
	if _, err := b.Approve(context.Background(), "https://issuer/authorize"); err == nil {
		t.Error("Approve with an https redirect = nil error, want error")
	}
}

func TestReceive_RequiresConfig(t *testing.T) {
	if _, err := Receive(context.Background(), Config{}, "openid-credential-offer://", HeadlessApprover{}); err == nil {
		t.Error("Receive with empty config = nil error")
	}
}

func TestApprovalTag(t *testing.T) {
	page := []byte(`<form method="post" action="/authorize/decision">
<input type="hidden" name="interaction" value="t-1&#43;2">
</form>`)
	if got, err := ApprovalTag(page); err != nil || got != "t-1+2" {
		t.Errorf("ApprovalTag = %q, %v; want t-1+2", got, err)
	}
	for _, page := range []string{`<p>no form</p>`, `<input type="hidden" name="interaction" value="">`} {
		if _, err := ApprovalTag([]byte(page)); err == nil {
			t.Errorf("ApprovalTag(%q) found a tag", page)
		}
	}
}
