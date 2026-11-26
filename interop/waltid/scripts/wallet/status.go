package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// call is an issuer's API call, -revoke-call's file: a POST of Body,
// as JSON, to URL, with Token as its bearer token.
type call struct {
	URL   string          `json:"url"`
	Token string          `json:"token"`
	Body  json.RawMessage `json:"body"`
}

// revokeCall makes the call in the file path over client, as the
// issuer's operator revokes credentials after issuing them, and
// records it in res. Any answer but a 2xx fails it.
func revokeCall(ctx context.Context, client *http.Client, path string, res *result) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own file
	if err != nil {
		return err
	}
	var c call
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(c.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := client.Do(req) // #nosec G107 -- the operator's own issuer API
	if err != nil {
		return err
	}
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("revoke: %s: %.300s", resp.Status, answer)
	}
	res.Revoked = append(res.Revoked, "by the issuer's API: "+resp.Status)
	return nil
}

// checkedStatus is what Wallet.CheckStatus found of a credential: its
// status and why, or the error it failed with.
type checkedStatus struct {
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

// checkStatus checks each credential of got, recording each one's
// status in res.Received, which lists them in the same order. A check
// that fails is recorded, not returned: it's what the case looks at.
func checkStatus(ctx context.Context, w *walletflow.Wallet, got []walletflow.StoredCredential, res *result) error {
	if len(got) != len(res.Received) {
		return fmt.Errorf("received %d credentials, recorded %d", len(got), len(res.Received))
	}
	for i, c := range got {
		checked, err := w.CheckStatus(ctx, c.ID)
		st := &checkedStatus{Value: checked.Status.Value, Reason: checked.Status.Reason}
		if err != nil {
			st = &checkedStatus{Error: err.Error()}
		}
		res.Received[i].Status = st
	}
	return nil
}
