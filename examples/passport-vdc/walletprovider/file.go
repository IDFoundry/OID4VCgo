package walletprovider

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// LoadOrCreate loads the Provider saved at path (as written by PEM), or
// creates one for issuer and saves it there. created reports which.
func LoadOrCreate(issuer, path string) (p *Provider, created bool, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	switch {
	case err == nil:
		p, err = Load(issuer, data)
		return p, false, err
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, fmt.Errorf("walletprovider: read %s: %w", path, err)
	}
	if p, err = New(issuer); err != nil {
		return nil, false, err
	}
	data, err = p.PEM()
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- operator-supplied path
		return nil, false, fmt.Errorf("walletprovider: write %s: %w", path, err)
	}
	return p, true, nil
}
