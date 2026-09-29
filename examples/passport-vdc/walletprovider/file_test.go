package walletprovider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet-provider.pem")
	const issuer = "https://wallet-provider.example"
	first, created, err := LoadOrCreate(issuer, path)
	if err != nil || !created {
		t.Fatalf("first LoadOrCreate = %v, created %v; want a new provider", err, created)
	}
	second, created, err := LoadOrCreate(issuer, path)
	if err != nil || created {
		t.Fatalf("second LoadOrCreate = %v, created %v; want the saved provider", err, created)
	}
	if !second.Key.Equal(first.Key) || !second.CACertificate.Equal(first.CACertificate) {
		t.Error("the reloaded provider isn't the saved one")
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(issuer, path); err == nil {
		t.Error("a damaged key file was accepted")
	}
}
