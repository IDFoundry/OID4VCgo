package sdjwtvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// TypeMetadata is an SD-JWT VC Type Metadata document (draft-13 §6.2):
// what an Issuer publishes about a credential type, typically at the
// URL its vct names (§6.3.1). Build one, check it with Validate, and
// serve it as application/json.
type TypeMetadata struct {
	// VCT is the type this document describes. REQUIRED.
	VCT string `json:"vct"`

	// Name and Description are for developers reading the document;
	// Display carries what end users see. Both OPTIONAL.
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`

	// Extends is the URI of a type this one extends (§6.4), with its
	// optional integrity metadata (§7).
	Extends          string `json:"extends,omitempty"`
	ExtendsIntegrity string `json:"extends#integrity,omitempty"`

	// Display has an entry per supported locale (§8).
	Display []TypeDisplay `json:"display,omitempty"`

	// Claims describes individual claims (§9).
	Claims []ClaimMetadata `json:"claims,omitempty"`
}

// TypeDisplay is one locale's display information for the type (§8).
type TypeDisplay struct {
	Locale      string `json:"locale"` // REQUIRED: RFC 5646 language tag
	Name        string `json:"name"`   // REQUIRED: for end users
	Description string `json:"description,omitempty"`

	// Rendering maps a rendering method ("simple", "svg_templates") to
	// its parameters (§8.1), kept as JSON.
	Rendering map[string]json.RawMessage `json:"rendering,omitempty"`
}

// ClaimMetadata describes the claim or claims Path selects (§9).
type ClaimMetadata struct {
	// Path is REQUIRED: a non-empty array of strings (claim names), nil
	// (every array element) and non-negative integers (an array index)
	// — see ClaimPath for the common all-names case.
	Path    []any          `json:"path"`
	Display []ClaimDisplay `json:"display,omitempty"`
	// Mandatory, when true, means the Issuer MUST include the claim in
	// the credential (§9.3); it may still be selectively disclosable.
	Mandatory bool `json:"mandatory,omitempty"`
	// SD says whether the Issuer makes the claim selectively
	// disclosable; empty means SDAllowed (§9.4), though always or never
	// is RECOMMENDED.
	SD    ClaimSD `json:"sd,omitempty"`
	SvgID string  `json:"svg_id,omitempty"`
}

// ClaimDisplay is one locale's display information for a claim (§9.2).
type ClaimDisplay struct {
	Locale      string `json:"locale"` // REQUIRED
	Label       string `json:"label"`  // REQUIRED: for end users
	Description string `json:"description,omitempty"`
}

// ClaimSD is a claim's selective disclosure metadata (§9.4).
type ClaimSD string

// ClaimSD values.
const (
	SDAlways  ClaimSD = "always"  // the Issuer MUST make it selectively disclosable
	SDAllowed ClaimSD = "allowed" // the Issuer MAY
	SDNever   ClaimSD = "never"   // the Issuer MUST NOT
)

// ClaimPath is a claim path of names only, e.g. ClaimPath("address",
// "street_address").
func ClaimPath(names ...string) []any {
	path := make([]any, len(names))
	for i, n := range names {
		path[i] = n
	}
	return path
}

var svgIDPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate checks m against draft-13's MUSTs: vct is present; every
// display entry has locale and name; every claim has a valid path,
// display entries with locale and label, a known sd value, and a
// well-formed svg_id unique within the document.
func (m TypeMetadata) Validate() error {
	if m.VCT == "" {
		return errors.New("sdjwtvc: type metadata: vct is required")
	}
	for i, d := range m.Display {
		if d.Locale == "" || d.Name == "" {
			return fmt.Errorf("sdjwtvc: type metadata: display[%d]: locale and name are required", i)
		}
	}
	svgIDs := map[string]bool{}
	for i, c := range m.Claims {
		if err := c.validate(svgIDs); err != nil {
			return fmt.Errorf("sdjwtvc: type metadata: claims[%d]: %w", i, err)
		}
	}
	return nil
}

func (c ClaimMetadata) validate(svgIDs map[string]bool) error {
	if err := validateClaimPath(c.Path); err != nil {
		return err
	}
	for j, d := range c.Display {
		if d.Locale == "" || d.Label == "" {
			return fmt.Errorf("display[%d]: locale and label are required", j)
		}
	}
	switch c.SD {
	case "", SDAlways, SDAllowed, SDNever:
	default:
		return fmt.Errorf("sd %q is not always, allowed or never", c.SD)
	}
	return validateSvgID(c.SvgID, svgIDs)
}

// validateClaimPath checks a claim path is a non-empty array of
// strings, nulls and non-negative integers (§9.1).
func validateClaimPath(path []any) error {
	if len(path) == 0 {
		return errors.New("path must not be empty")
	}
	for j, el := range path {
		if !isClaimPathElement(el) {
			return fmt.Errorf("path[%d]: %v is neither a string, null nor a non-negative integer", j, el)
		}
	}
	return nil
}

func isClaimPathElement(el any) bool {
	switch v := el.(type) {
	case string, nil:
		return true
	case int:
		return v >= 0
	case float64: // a path decoded from JSON
		return v >= 0 && v == float64(int64(v))
	default:
		return false
	}
}

// validateSvgID checks an svg_id's form and that it's unique within
// the document, recording it in seen.
func validateSvgID(id string, seen map[string]bool) error {
	if id == "" {
		return nil
	}
	if !svgIDPattern.MatchString(id) {
		return fmt.Errorf("svg_id %q must be alphanumeric or underscores, not starting with a digit", id)
	}
	if seen[id] {
		return fmt.Errorf("svg_id %q is not unique", id)
	}
	seen[id] = true
	return nil
}
