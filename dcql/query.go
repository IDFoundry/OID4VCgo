package dcql

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// idPattern is the character set §6.1 ("id" in a Credential Query) and
// §6.3 ("id" in a Claims Query) both restrict their own id values to.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Query is a DCQL query object (§6) — an Authorization Request's own
// "dcql_query" parameter value.
type Query struct {
	// Credentials is REQUIRED: a non-empty array of Credential
	// Queries specifying the requested Credentials.
	Credentials []CredentialQuery `json:"credentials"`

	// CredentialSets is OPTIONAL (§6.2): additional constraints on
	// which combination of Credentials to actually return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// Validate checks q's own structural MUSTs (§6): Credentials
// non-empty with every entry individually valid and its own "id"
// unique within the request, and — if present — every CredentialSets
// entry individually valid and referencing only "id"s that actually
// exist in Credentials.
func (q Query) Validate() error {
	if len(q.Credentials) == 0 {
		return fmt.Errorf("dcql: query: credentials must be non-empty")
	}
	ids := make(map[string]bool, len(q.Credentials))
	for i, cq := range q.Credentials {
		if err := cq.Validate(); err != nil {
			return fmt.Errorf("dcql: query: credentials[%d]: %w", i, err)
		}
		if ids[cq.ID] {
			return fmt.Errorf("dcql: query: credentials[%d]: duplicate id %q", i, cq.ID)
		}
		ids[cq.ID] = true
	}
	for i, cs := range q.CredentialSets {
		if err := cs.Validate(ids); err != nil {
			return fmt.Errorf("dcql: query: credential_sets[%d]: %w", i, err)
		}
	}
	return nil
}

// CredentialQuery is one entry in Query.Credentials (§6.1).
type CredentialQuery struct {
	// ID is REQUIRED: a non-empty string of [A-Za-z0-9_-], unique
	// within the request.
	ID string `json:"id"`

	// Format is REQUIRED: a Credential Format Identifier. This
	// package doesn't restrict it to a closed set — OID4VP defines
	// more formats than this repo issues — see SDJWTVCMeta/MdocMeta
	// for the two this repo actually supports
	// ("dc+sd-jwt"/"mso_mdoc").
	Format string `json:"format"`

	// Meta is REQUIRED — format-specific, but always present as an
	// object (an empty object {} means "no specific constraints",
	// §6.1; it's never the JSON literal null). Use NewSDJWTVCMeta/
	// NewMdocMeta to build it, and the SDJWTVCMeta/MdocMeta accessor
	// methods to read it back.
	Meta json.RawMessage `json:"meta"`

	// Multiple is OPTIONAL, default false: whether more than one
	// match for this Credential Query may be returned.
	Multiple bool `json:"multiple,omitempty"`

	// TrustedAuthorities is OPTIONAL (§6.1.1).
	TrustedAuthorities []TrustedAuthoritiesQuery `json:"trusted_authorities,omitempty"`

	// RequireCryptographicHolderBinding is OPTIONAL, default true —
	// left as a *bool so a caller can distinguish "not set" (defaults
	// to true) from an explicit false. Use
	// RequiresCryptographicHolderBinding to read the effective value.
	// WARNING: an explicit false disables nonce/audience binding
	// checking on the matched Presentation (verifier's own
	// verifySDJWTVCPresentation skips RequireKeyBinding entirely) —
	// spec-permitted for formats/use-cases that don't need holder
	// binding, but it also means a captured bare presentation of that
	// credential becomes replayable against any Verifier. Only opt out
	// with that consequence in mind.
	RequireCryptographicHolderBinding *bool `json:"require_cryptographic_holder_binding,omitempty"`

	// Claims is OPTIONAL (§6.3).
	Claims []ClaimsQuery `json:"claims,omitempty"`

	// ClaimSets is OPTIONAL (§6.4.1) — each entry an array of
	// Claims[].ID values, alternative combinations, most-preferred
	// first.
	ClaimSets [][]string `json:"claim_sets,omitempty"`
}

// RequiresCryptographicHolderBinding reports c's own effective value —
// true unless RequireCryptographicHolderBinding was explicitly set to
// false (§6.1's own default).
func (c CredentialQuery) RequiresCryptographicHolderBinding() bool {
	return c.RequireCryptographicHolderBinding == nil || *c.RequireCryptographicHolderBinding
}

// Validate checks c's own structural MUSTs (§6.1/§6.1.1/§6.3/§6.4.1).
func (c CredentialQuery) Validate() error {
	if c.ID == "" || !idPattern.MatchString(c.ID) {
		return fmt.Errorf("dcql: credential query: id must be a non-empty string of [A-Za-z0-9_-]")
	}
	if c.Format == "" {
		return fmt.Errorf("dcql: credential query %q: format is required", c.ID)
	}
	if len(c.Meta) == 0 {
		return fmt.Errorf("dcql: credential query %q: meta is required (may be {})", c.ID)
	}
	var probe any
	if err := json.Unmarshal(c.Meta, &probe); err != nil {
		return fmt.Errorf("dcql: credential query %q: meta is not valid JSON: %w", c.ID, err)
	}
	if _, ok := probe.(map[string]any); !ok {
		return fmt.Errorf("dcql: credential query %q: meta must be a JSON object", c.ID)
	}

	claimIDs := make(map[string]bool, len(c.Claims))
	seenPaths := make(map[string]bool, len(c.Claims))
	requireClaimID := len(c.ClaimSets) > 0
	for i, cl := range c.Claims {
		if err := cl.Validate(requireClaimID); err != nil {
			return fmt.Errorf("dcql: credential query %q: claims[%d]: %w", c.ID, i, err)
		}
		if cl.ID != "" {
			if claimIDs[cl.ID] {
				return fmt.Errorf("dcql: credential query %q: claims[%d]: duplicate id %q", c.ID, i, cl.ID)
			}
			claimIDs[cl.ID] = true
		}
		pathKey, err := json.Marshal(cl.Path)
		if err != nil {
			return fmt.Errorf("dcql: credential query %q: claims[%d]: path: %w", c.ID, i, err)
		}
		if seenPaths[string(pathKey)] {
			return fmt.Errorf("dcql: credential query %q: claims[%d]: path references the same claim as an earlier entry", c.ID, i)
		}
		seenPaths[string(pathKey)] = true
	}
	for i, set := range c.ClaimSets {
		if len(set) == 0 {
			return fmt.Errorf("dcql: credential query %q: claim_sets[%d] must be non-empty", c.ID, i)
		}
		for _, ref := range set {
			if !claimIDs[ref] {
				return fmt.Errorf("dcql: credential query %q: claim_sets[%d] references unknown claim id %q", c.ID, i, ref)
			}
		}
	}
	for i, ta := range c.TrustedAuthorities {
		if err := ta.Validate(); err != nil {
			return fmt.Errorf("dcql: credential query %q: trusted_authorities[%d]: %w", c.ID, i, err)
		}
	}
	return nil
}

// TrustedAuthoritiesType is a Trusted Authorities Query's own "type"
// value (§6.1.1). DCQL defines three; this package doesn't restrict
// TrustedAuthoritiesQuery.Type to only these — a future extension may
// define more — but exports these three since they're the ones a
// caller is likely to actually construct.
type TrustedAuthoritiesType string

const (
	// TrustedAuthorityAKI is the base64url-encoded X.509
	// AuthorityKeyIdentifier (RFC 5280 §4.2.1.1) type (§6.1.1.1) —
	// the only one of the three HAIP §5 actually requires support
	// for.
	TrustedAuthorityAKI TrustedAuthoritiesType = "aki"

	// TrustedAuthorityETSITL is an ETSI TS 119 612 Trusted List
	// identifier (§6.1.1.2).
	TrustedAuthorityETSITL TrustedAuthoritiesType = "etsi_tl"

	// TrustedAuthorityOpenIDFederation is an OpenID Federation Entity
	// Identifier (§6.1.1.3).
	TrustedAuthorityOpenIDFederation TrustedAuthoritiesType = "openid_federation"
)

// TrustedAuthoritiesQuery is one entry in CredentialQuery's own
// TrustedAuthorities (§6.1.1).
type TrustedAuthoritiesQuery struct {
	// Type is REQUIRED.
	Type TrustedAuthoritiesType `json:"type"`

	// Values is REQUIRED: a non-empty array of values in Type's own
	// format.
	Values []string `json:"values"`
}

// Validate checks t's own structural MUSTs (§6.1.1).
func (t TrustedAuthoritiesQuery) Validate() error {
	if t.Type == "" {
		return fmt.Errorf("dcql: trusted authorities query: type is required")
	}
	if len(t.Values) == 0 {
		return fmt.Errorf("dcql: trusted authorities query: values must be non-empty")
	}
	return nil
}

// CredentialSetQuery is one entry in Query.CredentialSets (§6.2).
type CredentialSetQuery struct {
	// Options is REQUIRED: a non-empty array, each entry a non-empty
	// array of Credential Query "id"s representing one way to
	// satisfy this set, most-preferred first.
	Options [][]string `json:"options"`

	// Required is OPTIONAL, default true. Use IsRequired to read the
	// effective value.
	Required *bool `json:"required,omitempty"`
}

// IsRequired reports c's own effective value — true unless Required
// was explicitly set to false (§6.2's own default).
func (c CredentialSetQuery) IsRequired() bool {
	return c.Required == nil || *c.Required
}

// Validate checks c's own structural MUSTs (§6.2) and that every
// Credential Query id it references via Options actually exists in
// knownIDs (the parent Query's own Credentials[].ID set).
func (c CredentialSetQuery) Validate(knownIDs map[string]bool) error {
	if len(c.Options) == 0 {
		return fmt.Errorf("dcql: credential set query: options must be non-empty")
	}
	for i, opt := range c.Options {
		if len(opt) == 0 {
			return fmt.Errorf("dcql: credential set query: options[%d] must be non-empty", i)
		}
		for _, id := range opt {
			if !knownIDs[id] {
				return fmt.Errorf("dcql: credential set query: options[%d] references unknown credential id %q", i, id)
			}
		}
	}
	return nil
}

// ClaimsQuery is one entry in CredentialQuery's own Claims (§6.3).
type ClaimsQuery struct {
	// ID is REQUIRED iff the parent CredentialQuery has ClaimSets;
	// OPTIONAL otherwise. A non-empty string of [A-Za-z0-9_-], unique
	// within the parent CredentialQuery's own Claims.
	ID string `json:"id,omitempty"`

	// Path is REQUIRED: a Claims Path Pointer (§7).
	Path Path `json:"path"`

	// Values is OPTIONAL: a best-effort exact-match filter over the
	// claim Path selects — "MUST NOT rely on it for security checks"
	// (§6.3, §6.4.1). Each element is a string, integer, or boolean.
	Values []any `json:"values,omitempty"`
}

// Validate checks c's own structural MUSTs (§6.3). requireID is true
// when the parent CredentialQuery has ClaimSets, in which case ID is
// REQUIRED rather than OPTIONAL.
func (c ClaimsQuery) Validate(requireID bool) error {
	if requireID && c.ID == "" {
		return fmt.Errorf("dcql: claims query: id is required when the parent credential query has claim_sets")
	}
	if c.ID != "" && !idPattern.MatchString(c.ID) {
		return fmt.Errorf("dcql: claims query: id must consist of [A-Za-z0-9_-]")
	}
	if err := c.Path.Validate(); err != nil {
		return fmt.Errorf("dcql: claims query: %w", err)
	}
	return nil
}
