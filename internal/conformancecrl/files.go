package conformancecrl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// StartFiles starts the Publisher publisherPath holds and then the
// Trust trustPath holds (Trust.Start), both JSON a setup script wrote,
// returning the checker: for an interop wallet that serves and checks
// the run's CRLs in its own process. A publisher that stops serving is
// logged.
func StartFiles(ctx context.Context, publisherPath, trustPath string, logf func(format string, args ...any)) (certrevocation.Checker, error) {
	var pub Publisher
	if err := readJSON(publisherPath, &pub); err != nil {
		return nil, err
	}
	var trust Trust
	if err := readJSON(trustPath, &trust); err != nil {
		return nil, err
	}
	if err := pub.Start(func(err error) { logf("crl publisher: %v", err) }); err != nil {
		return nil, err
	}
	crls, err := trust.Start(ctx, logf)
	if err != nil {
		return nil, err
	}
	return crls, nil
}

// WriteFiles writes p and t as JSON to publisherPath and trustPath,
// for StartFiles.
func WriteFiles(p Publisher, publisherPath string, t Trust, trustPath string) error {
	for path, v := range map[string]any{publisherPath: p, trustPath: t} {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- a file the run's setup script wrote
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
