package wallet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// VerifierInfo is one attestation about the Verifier from its request's
// verifier_info (OpenID4VP 1.0 §5.1, §5.11), as received: its format,
// its data, and the credential queries it applies to. Nothing in it is
// verified here. A Wallet that uses one MUST validate its signature and
// binding first; registration.Verify does for this library's own
// registration format.
type VerifierInfo struct {
	Format string
	// Data is the attestation as JSON: a string, such as a JWT, or an
	// object.
	Data json.RawMessage
	// CredentialIDs are the credential queries it's relevant to, by
	// DCQL id; empty means every one.
	CredentialIDs []string
}

// DataString returns Data when it's a JSON string.
func (vi VerifierInfo) DataString() (string, bool) {
	var s string
	if err := json.Unmarshal(vi.Data, &s); err != nil {
		return "", false
	}
	return s, true
}

// AppliesTo reports whether vi is relevant to credential query id.
func (vi VerifierInfo) AppliesTo(id string) bool {
	return len(vi.CredentialIDs) == 0 || slices.Contains(vi.CredentialIDs, id)
}

type wireVerifierInfo struct {
	Format        string          `json:"format"`
	Data          json.RawMessage `json:"data"`
	CredentialIDs *[]string       `json:"credential_ids"`
}

// MaxVerifierInfo is the most verifier_info entries a request may
// carry: one per credential query is already generous.
const MaxVerifierInfo = 16

// parseVerifierInfo reads a request's verifier_info, nil when absent. It
// checks the structure §5.1 defines: a non-empty array of objects, each
// with a format, data that's a string or an object, and, if present,
// non-empty credential_ids naming credential queries of q; and that
// there are at most MaxVerifierInfo.
func parseVerifierInfo(raw json.RawMessage, q dcql.Query) ([]VerifierInfo, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var wire []wireVerifierInfo
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, errors.New("verifier_info must be an array of objects")
	}
	if len(wire) == 0 {
		return nil, errors.New("verifier_info must not be empty")
	}
	if len(wire) > MaxVerifierInfo {
		// A wallet verifies each recognized entry's signature chain:
		// an unbounded list would be that much work for one request.
		return nil, fmt.Errorf("verifier_info has %d entries, more than %d", len(wire), MaxVerifierInfo)
	}
	out := make([]VerifierInfo, 0, len(wire))
	for i, w := range wire {
		vi, err := w.parse(q)
		if err != nil {
			return nil, fmt.Errorf("verifier_info[%d]: %w", i, err)
		}
		out = append(out, vi)
	}
	return out, nil
}

// parse checks one verifier_info entry, for a request with query q.
func (w wireVerifierInfo) parse(q dcql.Query) (VerifierInfo, error) {
	if w.Format == "" {
		return VerifierInfo{}, errors.New("format is required")
	}
	data := bytes.TrimSpace(w.Data)
	if len(data) == 0 || (data[0] != '"' && data[0] != '{') || bytes.Equal(data, []byte(`""`)) || bytes.Equal(data, []byte("{}")) {
		return VerifierInfo{}, errors.New("data must be a non-empty string or object")
	}
	vi := VerifierInfo{Format: w.Format, Data: json.RawMessage(data)}
	if w.CredentialIDs == nil {
		return vi, nil
	}
	if len(*w.CredentialIDs) == 0 {
		return VerifierInfo{}, errors.New("credential_ids must not be empty")
	}
	for _, id := range *w.CredentialIDs {
		if !slices.ContainsFunc(q.Credentials, func(c dcql.CredentialQuery) bool { return c.ID == id }) {
			return VerifierInfo{}, fmt.Errorf("credential_ids names %q, no credential query of the request", id)
		}
	}
	vi.CredentialIDs = *w.CredentialIDs
	return vi, nil
}
