package walletapp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Store keeps received credentials, one JSON file each, in a directory.
// Holder keys are stored unencrypted (files are 0600, the directory
// 0700): acceptable for a demo on your own machine, never for a real
// wallet.
type Store struct{ Dir string }

// Stored is a credential as kept in a Store.
type Stored struct {
	ConfigurationID string    `json:"configuration_id"`
	Format          string    `json:"format"`
	Credential      string    `json:"credential"`
	HolderKeyPEM    string    `json:"holder_key_pem"`
	ReceivedAt      time.Time `json:"received_at"`

	// Path is where it's stored; not serialized.
	Path string `json:"-"`
}

// Save writes r to the store and returns where.
func (s Store) Save(r Received, now time.Time) (string, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", fmt.Errorf("walletapp: store: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(r.HolderKey)
	if err != nil {
		return "", fmt.Errorf("walletapp: store: holder key: %w", err)
	}
	raw, err := json.MarshalIndent(Stored{
		ConfigurationID: r.ConfigurationID, Format: r.Format, Credential: r.Credential,
		HolderKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		ReceivedAt:   now.UTC(),
	}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("walletapp: store: %w", err)
	}
	name := fmt.Sprintf("%s-%s.json", now.UTC().Format("20060102T150405.000"), safeName(r.ConfigurationID))
	path := filepath.Join(s.Dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("walletapp: store: %w", err)
	}
	return path, nil
}

// List returns every stored credential, oldest first. A missing store
// directory is an empty store.
func (s Store) List() ([]Stored, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("walletapp: store: %w", err)
	}
	var out []Stored
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.Dir, e.Name())
		raw, err := os.ReadFile(path) // #nosec G304 -- inside the store directory
		if err != nil {
			return nil, fmt.Errorf("walletapp: store: %w", err)
		}
		var st Stored
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("walletapp: store: %s: %w", e.Name(), err)
		}
		st.Path = path
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.Before(out[j].ReceivedAt) })
	return out, nil
}

// safeName keeps a configuration ID usable as part of a file name.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
}
