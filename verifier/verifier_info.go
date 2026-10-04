package verifier

import (
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// VerifierInfo is one attestation about the Verifier that its requests
// carry in verifier_info (OpenID4VP 1.0 §5.1, §5.11): its registration
// with a trusted registrar, say, which a Wallet can show the holder and
// check the request against. registration.Issue makes one in this
// library's own format (registration.Format).
type VerifierInfo struct {
	// Format identifies the attestation's format (REQUIRED).
	Format string `json:"format"`
	// Data is the attestation: a string, such as a JWT, or a JSON
	// object (REQUIRED).
	Data any `json:"data"`
	// CredentialIDs, if set, are the credential queries it's relevant
	// to, by DCQL id; unset means every one. A request whose query has
	// no credential query with one of these IDs isn't built.
	CredentialIDs []string `json:"credential_ids,omitempty"`
}

func validateVerifierInfo(infos []VerifierInfo) error {
	for i, vi := range infos {
		if vi.Format == "" {
			return fmt.Errorf("verifier_info[%d]: format is required", i)
		}
		switch d := vi.Data.(type) {
		case string:
			if d == "" {
				return fmt.Errorf("verifier_info[%d]: data is required", i)
			}
		case map[string]any:
			if len(d) == 0 {
				return fmt.Errorf("verifier_info[%d]: data is required", i)
			}
		default:
			return fmt.Errorf("verifier_info[%d]: data must be a string or a JSON object", i)
		}
		if vi.CredentialIDs != nil && len(vi.CredentialIDs) == 0 {
			return fmt.Errorf("verifier_info[%d]: credential_ids, if set, must be non-empty", i)
		}
	}
	return nil
}

// verifierInfoFor is Config.VerifierInfo for a request with query q, or
// nil when there's none: an entry naming a credential query q doesn't
// have is an error, since the Wallet couldn't apply it.
func (v *Verifier) verifierInfoFor(q dcql.Query) ([]VerifierInfo, error) {
	if len(v.cfg.VerifierInfo) == 0 {
		return nil, nil
	}
	for i, vi := range v.cfg.VerifierInfo {
		for _, id := range vi.CredentialIDs {
			if !slices.ContainsFunc(q.Credentials, func(c dcql.CredentialQuery) bool { return c.ID == id }) {
				return nil, fmt.Errorf("verifier_info[%d]: credential_ids names %q, which the query has no credential query for", i, id)
			}
		}
	}
	return v.cfg.VerifierInfo, nil
}
