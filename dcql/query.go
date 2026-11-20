package dcql

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
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
	if err := q.checkSize(); err != nil {
		return err
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

// Bounds on a query's size, which Validate enforces. Matching a query
// against held credentials costs time in its size (each credential set
// option, each claim set and each value is tried), and a query can come
// from any web page over the Digital Credentials API: without bounds, a
// 1 MB query kept a wallet busy for minutes. Each is far above what any
// real query needs. A claim_sets entry is bounded by
// MaxClaimsPerCredential too: it names each of its query's claims at
// most once (Validate refuses a repeat, which asks for nothing more).
//
// MaxMetaBytes bounds one credential query's meta as sent: a wallet
// reads a query's meta for every credential it holds of the query's
// format, and members it doesn't know, which it ignores, would
// otherwise make each read cost up to the whole request's size. A real
// meta names a type or a few: 64 vct_values of 60 bytes each fit.
const (
	MaxCredentialQueries      = 64   // credentials
	MaxCredentialSets         = 64   // credential_sets
	MaxCredentialSetOptions   = 64   // options in one credential set
	MaxClaimsPerCredential    = 256  // claims in one credential query
	MaxClaimSets              = 64   // claim_sets in one credential query
	MaxValuesPerClaim         = 64   // values in one claims query
	MaxPathLength             = 32   // components in one claims path
	MaxTrustedAuthorities     = 16   // trusted_authorities in one credential query
	MaxTrustedAuthorityValues = 64   // values in one trusted_authorities entry
	MaxVCTValues              = 64   // vct_values in one "dc+sd-jwt" credential query's meta
	MaxMetaBytes              = 4096 // bytes of one credential query's meta, as sent
)

// checkSize enforces the size bounds above.
func (q Query) checkSize() error {
	switch {
	case len(q.Credentials) > MaxCredentialQueries:
		return fmt.Errorf("dcql: query: %d credential queries, more than %d", len(q.Credentials), MaxCredentialQueries)
	case len(q.CredentialSets) > MaxCredentialSets:
		return fmt.Errorf("dcql: query: %d credential sets, more than %d", len(q.CredentialSets), MaxCredentialSets)
	}
	for i, cs := range q.CredentialSets {
		if len(cs.Options) > MaxCredentialSetOptions {
			return fmt.Errorf("dcql: query: credential_sets[%d]: %d options, more than %d", i, len(cs.Options), MaxCredentialSetOptions)
		}
	}
	for i, cq := range q.Credentials {
		switch {
		case len(cq.Claims) > MaxClaimsPerCredential:
			return fmt.Errorf("dcql: query: credentials[%d]: %d claims, more than %d", i, len(cq.Claims), MaxClaimsPerCredential)
		case len(cq.ClaimSets) > MaxClaimSets:
			return fmt.Errorf("dcql: query: credentials[%d]: %d claim sets, more than %d", i, len(cq.ClaimSets), MaxClaimSets)
		case len(cq.TrustedAuthorities) > MaxTrustedAuthorities:
			return fmt.Errorf("dcql: query: credentials[%d]: %d trusted authorities, more than %d", i, len(cq.TrustedAuthorities), MaxTrustedAuthorities)
		case len(cq.Meta) > MaxMetaBytes:
			return fmt.Errorf("dcql: query: credentials[%d]: a meta of %d bytes, more than %d", i, len(cq.Meta), MaxMetaBytes)
		}
		if err := cq.checkNestedSize(); err != nil {
			return fmt.Errorf("dcql: query: credentials[%d]%w", i, err)
		}
	}
	return nil
}

// checkNestedSize enforces the bounds on what one credential query's
// own entries hold, its error starting with the offending field's
// path within the credential query.
func (cq CredentialQuery) checkNestedSize() error {
	for j, set := range cq.ClaimSets {
		if len(set) > MaxClaimsPerCredential {
			return fmt.Errorf(".claim_sets[%d]: %d claims, more than %d", j, len(set), MaxClaimsPerCredential)
		}
	}
	for j, ta := range cq.TrustedAuthorities {
		if len(ta.Values) > MaxTrustedAuthorityValues {
			return fmt.Errorf(".trusted_authorities[%d]: %d values, more than %d", j, len(ta.Values), MaxTrustedAuthorityValues)
		}
	}
	for j, c := range cq.Claims {
		switch {
		case len(c.Values) > MaxValuesPerClaim:
			return fmt.Errorf(".claims[%d]: %d values, more than %d", j, len(c.Values), MaxValuesPerClaim)
		case len(c.Path) > MaxPathLength:
			return fmt.Errorf(".claims[%d]: a path of %d components, more than %d", j, len(c.Path), MaxPathLength)
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
	if err := c.validateMeta(); err != nil {
		return err
	}
	claimIDs, err := c.validateClaims()
	if err != nil {
		return err
	}
	if err := c.validateClaimSets(claimIDs); err != nil {
		return err
	}
	return c.validateTrustedAuthorities()
}

// validateMeta, validateClaims, validateClaimSets, and
// validateTrustedAuthorities are Validate's own per-field checks,
// split into methods purely to keep Validate under the linter's own
// cognitive complexity ceiling.
func (c CredentialQuery) validateMeta() error {
	if len(c.Meta) == 0 {
		return fmt.Errorf("dcql: credential query %q: meta is required", c.ID)
	}
	var probe any
	if err := strictjson.Unmarshal(c.Meta, &probe); err != nil {
		return fmt.Errorf("dcql: credential query %q: meta is not valid JSON: %w", c.ID, err)
	}
	if _, ok := probe.(map[string]any); !ok {
		return fmt.Errorf("dcql: credential query %q: meta must be a JSON object", c.ID)
	}
	// The format's type constraint is REQUIRED (Appendix B.3.5's
	// vct_values, B.2.3's doctype_value): without it the query accepts a
	// Credential of any type that has the claims.
	switch c.Format {
	case formatSDJWTVC:
		m, err := c.SDJWTVCMeta()
		if err != nil {
			return err
		}
		if err := m.validate(); err != nil {
			return fmt.Errorf("dcql: credential query %q: %w", c.ID, err)
		}
	case formatMdoc:
		m, err := c.MdocMeta()
		if err != nil {
			return err
		}
		if m.DoctypeValue == "" {
			return fmt.Errorf("dcql: credential query %q: meta.doctype_value is required", c.ID)
		}
	}
	return nil
}

// validateClaims returns the set of Claims[].ID values seen, for
// validateClaimSets's own reference check.
func (c CredentialQuery) validateClaims() (map[string]bool, error) {
	claimIDs := make(map[string]bool, len(c.Claims))
	seenPaths := make(map[string]bool, len(c.Claims))
	requireClaimID := len(c.ClaimSets) > 0
	if c.Claims != nil && len(c.Claims) == 0 {
		return nil, fmt.Errorf("dcql: credential query %q: claims must be non-empty when present", c.ID)
	}
	if c.ClaimSets != nil && len(c.ClaimSets) == 0 {
		return nil, fmt.Errorf("dcql: credential query %q: claim_sets must be non-empty when present", c.ID)
	}
	for i, cl := range c.Claims {
		if err := cl.Validate(requireClaimID); err != nil {
			return nil, fmt.Errorf("dcql: credential query %q: claims[%d]: %w", c.ID, i, err)
		}
		if err := c.validateClaimFormat(cl); err != nil {
			return nil, fmt.Errorf("dcql: credential query %q: claims[%d]: %w", c.ID, i, err)
		}
		if cl.ID != "" {
			if claimIDs[cl.ID] {
				return nil, fmt.Errorf("dcql: credential query %q: claims[%d]: duplicate id %q", c.ID, i, cl.ID)
			}
			claimIDs[cl.ID] = true
		}
		pathKey, err := json.Marshal(cl.Path)
		if err != nil {
			return nil, fmt.Errorf("dcql: credential query %q: claims[%d]: path: %w", c.ID, i, err)
		}
		if seenPaths[string(pathKey)] {
			return nil, fmt.Errorf("dcql: credential query %q: claims[%d]: path references the same claim as an earlier entry", c.ID, i)
		}
		seenPaths[string(pathKey)] = true
	}
	return claimIDs, nil
}

// validateClaimFormat checks cl against c's format: an "mso_mdoc"
// claims path is exactly a namespace and an element name (§7.2), and
// only an "mso_mdoc" claim has intent_to_retain (Appendix B.2.4).
func (c CredentialQuery) validateClaimFormat(cl ClaimsQuery) error {
	if c.Format != "mso_mdoc" {
		if cl.IntentToRetain != nil {
			return fmt.Errorf("intent_to_retain is only for an mso_mdoc claim")
		}
		return nil
	}
	if len(cl.Path) != 2 || !cl.Path[0].IsKey() || !cl.Path[1].IsKey() {
		return fmt.Errorf("an mso_mdoc claims path must be two strings, a namespace and an element name")
	}
	return nil
}

func (c CredentialQuery) validateClaimSets(claimIDs map[string]bool) error {
	for i, set := range c.ClaimSets {
		if len(set) == 0 {
			return fmt.Errorf("dcql: credential query %q: claim_sets[%d] must be non-empty", c.ID, i)
		}
		for j, ref := range set {
			if !claimIDs[ref] {
				return fmt.Errorf("dcql: credential query %q: claim_sets[%d] references unknown claim id %q", c.ID, i, ref)
			}
			if slices.Contains(set[:j], ref) {
				return fmt.Errorf("dcql: credential query %q: claim_sets[%d] lists claim id %q twice", c.ID, i, ref)
			}
		}
	}
	return nil
}

func (c CredentialQuery) validateTrustedAuthorities() error {
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
		for j, id := range opt {
			if !knownIDs[id] {
				return fmt.Errorf("dcql: credential set query: options[%d] references unknown credential id %q", i, id)
			}
			if slices.Contains(opt[:j], id) {
				return fmt.Errorf("dcql: credential set query: options[%d] lists credential id %q twice", i, id)
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

	// Values is OPTIONAL: an exact-match filter over the claim Path
	// selects (§6.3). Each element is a string, integer, or boolean.
	// SatisfiedBySDJWTVCClaims/SatisfiedByMdocClaims (and their
	// Selected* and Satisfied*Paths twins) require one selected value to
	// equal one of these: the Wallet's filter, and
	// verifier.VerifyResponse's check that what it received matches the
	// query. Under claim_sets, VerifyResponse keeps only the claims of
	// the options a presentation satisfies, so a claim it keeps has
	// passed its filter (unless AllowUnrequestedClaims). A query decoded from
	// JSON holds its integers as float64, exact only up to 2^53 in
	// magnitude: a larger value is rounded, so it can match a claim one
	// off it and miss its own. Keep a values filter's integers within
	// ±2^53.
	Values []any `json:"values,omitempty"`

	// IntentToRetain is OPTIONAL, for an "mso_mdoc" claim only: whether
	// the Verifier intends to keep the element (OID4VP Appendix B.2.4,
	// ISO/IEC 18013-5's IntentToRetain), for the Wallet to show the
	// holder.
	IntentToRetain *bool `json:"intent_to_retain,omitempty"`
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
	if c.Values != nil && len(c.Values) == 0 {
		return fmt.Errorf("dcql: claims query: values must be non-empty when present")
	}
	for i, v := range c.Values {
		if !isValuesElement(v) {
			return fmt.Errorf("dcql: claims query: values[%d] is not a string, integer or boolean", i)
		}
	}
	return nil
}

// isValuesElement reports whether v is a string, an integer or a
// boolean, as a values array's elements must be (§6.3). A JSON number
// decodes to float64, so a float64 without a fractional part counts as
// an integer.
func isValuesElement(v any) bool {
	switch n := v.(type) {
	case string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return n == math.Trunc(n) && !math.IsInf(n, 0)
	case float32:
		return float64(n) == math.Trunc(float64(n)) && !math.IsInf(float64(n), 0)
	case json.Number:
		_, err := n.Int64()
		return err == nil
	default:
		return false
	}
}
