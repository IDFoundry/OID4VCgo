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

func TestBrowserApprover_ReturnsCallbackQuery(t *testing.T) {
	redirect := "http://" + freeLoopbackPort(t) + "/callback"
	b := BrowserApprover{
		RedirectURI: redirect,
		// Stand in for the browser: after the holder approves, the
		// issuer redirects it to the wallet's callback.
		Show: func(string) {
			go func() {
				resp, err := http.Get(redirect + "?code=abc&state=xyz&iss=https%3A%2F%2Fissuer")
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
		},
		Timeout: 5 * time.Second,
	}
	q, err := b.Approve(context.Background(), "https://issuer/authorize?request_uri=x")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if q != "code=abc&state=xyz&iss=https%3A%2F%2Fissuer" {
		t.Errorf("callback query = %q", q)
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
