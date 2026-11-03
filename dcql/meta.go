package dcql

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// The Credential Format Identifiers whose meta this package knows.
const (
	formatSDJWTVC = "dc+sd-jwt"
	formatMdoc    = "mso_mdoc"
)

// SDJWTVCMeta is the "dc+sd-jwt" Credential Format's own
// format-specific parameter inside a Credential Query's "meta"
// (Appendix B.3.5) — the format this repo's credential/sdjwtvc
// package issues.
type SDJWTVCMeta struct {
	// VCTValues is REQUIRED: a non-empty array of allowed "vct"
	// values for the requested Credential.
	VCTValues []string `json:"vct_values"`
}

// MdocMeta is the "mso_mdoc" Credential Format's own format-specific
// parameter inside a Credential Query's "meta" (Appendix B.2.3) — the
// format this repo's credential/mdoc package issues.
type MdocMeta struct {
	// DoctypeValue is REQUIRED: the allowed ISO/IEC 18013-5 doctype.
	DoctypeValue string `json:"doctype_value"`
}

// NewSDJWTVCMeta marshals meta for use as a CredentialQuery's own
// Meta field.
func NewSDJWTVCMeta(meta SDJWTVCMeta) (json.RawMessage, error) {
	if err := meta.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("dcql: marshal sd-jwt vc meta: %w", err)
	}
	return raw, nil
}

// NewMdocMeta marshals meta for use as a CredentialQuery's own Meta
// field.
func NewMdocMeta(meta MdocMeta) (json.RawMessage, error) {
	if meta.DoctypeValue == "" {
		return nil, fmt.Errorf("dcql: mdoc meta: doctype_value is required")
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("dcql: marshal mdoc meta: %w", err)
	}
	return raw, nil
}

// validate checks m names at least one vct, none of them empty: without
// one, the query would accept a Credential of any type. It names at most
// MaxVCTValues, a bound on a query's size like those Query.Validate
// enforces.
func (m SDJWTVCMeta) validate() error {
	switch {
	case len(m.VCTValues) == 0:
		return fmt.Errorf("dcql: sd-jwt vc meta: vct_values must be a non-empty array")
	case len(m.VCTValues) > MaxVCTValues:
		return fmt.Errorf("dcql: sd-jwt vc meta: %d vct_values, more than %d", len(m.VCTValues), MaxVCTValues)
	}
	for _, v := range m.VCTValues {
		if v == "" {
			return fmt.Errorf("dcql: sd-jwt vc meta: vct_values must not contain an empty string")
		}
	}
	return nil
}

// SDJWTVCMeta decodes c's own Meta as the "dc+sd-jwt" format's
// meta shape (Appendix B.3.5).
func (c CredentialQuery) SDJWTVCMeta() (SDJWTVCMeta, error) {
	var m SDJWTVCMeta
	if err := strictjson.Unmarshal(c.Meta, &m); err != nil {
		return SDJWTVCMeta{}, fmt.Errorf("dcql: credential query %q: sd-jwt vc meta: %w", c.ID, err)
	}
	return m, nil
}

// MdocMeta decodes c's own Meta as the "mso_mdoc" format's meta shape
// (Appendix B.2.3).
func (c CredentialQuery) MdocMeta() (MdocMeta, error) {
	var m MdocMeta
	if err := strictjson.Unmarshal(c.Meta, &m); err != nil {
		return MdocMeta{}, fmt.Errorf("dcql: credential query %q: mdoc meta: %w", c.ID, err)
	}
	return m, nil
}

// SatisfiedBySDJWTVCClaims reports whether claims — a "dc+sd-jwt"
// credential's own already-resolved claims (RFC 9901's "Processed
// SD-JWT Payload") — satisfies c's own "dc+sd-jwt"-specific
// constraints (§8.6 point 3): the credential's own "vct" must be
// among SDJWTVCMeta's own VCTValues, when declared, and c's own
// Claims/ClaimSets must be satisfied per §6.4.1 (see
// claimsSatisfiedBy). Returns a non-nil error naming the first unmet
// constraint otherwise.
//
// This is the Wallet's check, on a credential it holds whole: whether
// it can satisfy a Credential Query at all. A Verifier checking what a
// presentation discloses uses SatisfiedBySDJWTVCPresentation, which
// differs only in array indices.
func (c CredentialQuery) SatisfiedBySDJWTVCClaims(claims map[string]any) error {
	_, err := c.SelectedSDJWTVCClaimPaths(claims)
	return err
}

// SelectedSDJWTVCClaimPaths is SatisfiedBySDJWTVCClaims's own richer
// twin: on success, it also returns exactly which Claims entries'
// own Paths the winning combination resolved — the no-claim_sets
// case's own c.Claims (all of them), or the first satisfiable
// c.ClaimSets option's own Paths — §6.4.1's own "the Wallet MUST NOT
// send selectively disclosable claims that have not been selected"
// needs to know precisely this to build a minimally-disclosing
// Presentation (see wallet.PresentSDJWTVC's own doc comment for where
// this feeds in); SatisfiedBySDJWTVCClaims itself only needs the
// pass/fail outcome, so it discards the paths.
func (c CredentialQuery) SelectedSDJWTVCClaimPaths(claims map[string]any) ([]Path, error) {
	meta, err := c.SDJWTVCMeta()
	if err != nil {
		return nil, fmt.Errorf("meta: %w", err)
	}
	if len(meta.VCTValues) > 0 && !slices.ContainsFunc(credentialTypes(claims), func(t string) bool { return slices.Contains(meta.VCTValues, t) }) {
		vct, _ := claims["vct"].(string)
		return nil, fmt.Errorf("credential's own vct %q, and its aka_vcts, are not among the requested vct_values %v", vct, meta.VCTValues)
	}
	return c.selectedClaimPaths(func(p Path) ([]any, error) {
		return p.Select(claims)
	})
}

// SatisfiedBySDJWTVCPresentation is SatisfiedBySDJWTVCClaims for what a
// Verifier receives: claims is a presented SD-JWT VC's Processed SD-JWT
// Payload, holding only the disclosures the Wallet sent. An array index
// in a claims path counts the elements of the Holder's credential
// (§7.1), but a presentation drops the array elements it doesn't
// disclose (RFC 9901 §7.1) and can't say where the ones it does sat.
// So each index component is evaluated here as a Wildcard: the claim
// is present when any disclosed element is, and its Values match when
// any disclosed element's value does. A Verifier can't learn an
// element's position in the credential from a presentation, and must
// not rely on it.
func (c CredentialQuery) SatisfiedBySDJWTVCPresentation(claims map[string]any) error {
	meta, err := c.SDJWTVCMeta()
	if err != nil {
		return fmt.Errorf("meta: %w", err)
	}
	if len(meta.VCTValues) > 0 && !slices.ContainsFunc(credentialTypes(claims), func(t string) bool { return slices.Contains(meta.VCTValues, t) }) {
		vct, _ := claims["vct"].(string)
		return fmt.Errorf("credential's own vct %q, and its aka_vcts, are not among the requested vct_values %v", vct, meta.VCTValues)
	}
	_, err = c.selectedClaimPaths(func(p Path) ([]any, error) {
		return p.withIndicesWidened().Select(claims)
	})
	return err
}

// SatisfiedByMdocClaims reports whether docType/nameSpaces — an
// "mso_mdoc" credential's own document type and disclosed IssuerSigned
// namespaces (e.g. credential/mdoc.VerifiedMSO's own DocType/
// NameSpaces, from a prior credential/mdoc.Verify, or the equivalent
// derived from an unverified IssuerSigned a Wallet already holds)
// — satisfies c's own "mso_mdoc"-specific constraints (§8.6 point 3):
// docType must equal MdocMeta's own DoctypeValue, when declared, and
// c's own Claims/ClaimSets must be satisfied per §6.4.1 (see
// claimsSatisfiedBy) — each Claims entry an exactly-two-component
// mdoc-form Path (§7.2, see Path.MdocNamespaceAndElement). The same
// shared-check rationale as SatisfiedBySDJWTVCClaims applies.
func (c CredentialQuery) SatisfiedByMdocClaims(docType string, nameSpaces map[string]map[string]any) error {
	_, err := c.SelectedMdocClaimPaths(docType, nameSpaces)
	return err
}

// SelectedMdocClaimPaths is SatisfiedByMdocClaims's own richer twin —
// see SelectedSDJWTVCClaimPaths's own doc comment for exactly what it
// returns and why.
func (c CredentialQuery) SelectedMdocClaimPaths(docType string, nameSpaces map[string]map[string]any) ([]Path, error) {
	meta, err := c.MdocMeta()
	if err != nil {
		return nil, fmt.Errorf("meta: %w", err)
	}
	if meta.DoctypeValue != "" && docType != meta.DoctypeValue {
		return nil, fmt.Errorf("credential's own docType %q does not match the requested doctype_value %q", docType, meta.DoctypeValue)
	}
	return c.selectedClaimPaths(func(p Path) ([]any, error) {
		namespace, element, ok := p.MdocNamespaceAndElement()
		if !ok {
			return nil, fmt.Errorf("claims path %v is not a valid mdoc-format path (exactly two string components)", p)
		}
		elements, ok := nameSpaces[namespace]
		if !ok {
			return nil, fmt.Errorf("namespace %q is not present", namespace)
		}
		value, ok := elements[element]
		if !ok {
			return nil, fmt.Errorf("namespace %q element %q is not present", namespace, element)
		}
		return []any{value}, nil
	})
}

// selectedClaimPaths implements §6.4.1's own "Selecting Claims" rules,
// format-agnostically: present checks whether one Claims Query's own
// Path is actually present in the credential being matched. On
// success it returns exactly which Paths the winning combination
// resolved (§6.4.1's own "selected" claims — see
// SelectedSDJWTVCClaimPaths's own doc comment for why a caller needs
// this, not just the pass/fail outcome).
//
//   - If c.Claims is empty, there's nothing more to check (§6.4.1's
//     "claims is absent" case is a Presentation-construction concern —
//     which claims to disclose — not a matching one: a credential
//     already either has, or doesn't have, the format's own mandatory
//     claims regardless of what a Claims Query asks for) — an empty,
//     non-nil slice is returned, since nothing was selected.
//   - If c.Claims is set but c.ClaimSets is empty, every one of
//     c.Claims must resolve ("the Verifier requests all claims listed
//     in claims"), and every one of their own Paths is returned.
//   - If both are set, at least one c.ClaimSets option must resolve in
//     full — checked in the given order, since "the Wallet SHOULD
//     return the first option that it can satisfy" (most-preferred
//     first); this function reports satisfaction as soon as it finds
//     one, without checking whether a later option might also match,
//     and returns exactly that option's own Paths.
func (c CredentialQuery) selectedClaimPaths(present func(Path) ([]any, error)) ([]Path, error) {
	if len(c.ClaimSets) == 0 {
		paths := make([]Path, 0, len(c.Claims))
		for _, cl := range c.Claims {
			if err := presentAt(cl, present); err != nil {
				return nil, err
			}
			paths = append(paths, cl.Path)
		}
		return paths, nil
	}

	byID := make(map[string]ClaimsQuery, len(c.Claims))
	for _, cl := range c.Claims {
		byID[cl.ID] = cl
	}
	// Each claim is looked up once, however many options name it.
	checked := make(map[string]error, len(c.Claims))
	presentOnce := func(cl ClaimsQuery) error {
		err, ok := checked[cl.ID]
		if !ok {
			err = presentAt(cl, present)
			checked[cl.ID] = err
		}
		return err
	}
	var lastErr error
	for _, option := range c.ClaimSets {
		paths, err := claimSetOptionPaths(option, byID, presentOnce)
		if err != nil {
			lastErr = err
			continue
		}
		return paths, nil
	}
	return nil, fmt.Errorf("no claim_sets option is satisfied: %w", lastErr)
}

// claimSetOptionPaths checks one claim_sets option (a list of
// claims[].id values) with check, using byID to resolve each id
// to its own Path, returning those Paths on success.
func claimSetOptionPaths(option []string, byID map[string]ClaimsQuery, check func(ClaimsQuery) error) ([]Path, error) {
	paths := make([]Path, 0, len(option))
	for _, id := range option {
		cl, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("references unknown claim id %q", id)
		}
		if err := check(cl); err != nil {
			return nil, fmt.Errorf("claim %q: %w", id, err)
		}
		paths = append(paths, cl.Path)
	}
	return paths, nil
}

// presentAt is §6.4.1's atom of "is this claim actually there", shared
// by both selectedClaimPaths branches: cl's Path must select something,
// and when cl has Values, one of the selected values must equal one of
// them (§6.3). The Wallet applies Values as a filter; the Verifier
// applies the same check to what it received, so a Presentation whose
// claim has another value doesn't satisfy the query.
func presentAt(cl ClaimsQuery, present func(Path) ([]any, error)) error {
	selected, err := present(cl.Path)
	if err != nil {
		return fmt.Errorf("claim at path %v is not present: %w", cl.Path, err)
	}
	if len(cl.Values) > 0 && !anyValueMatches(selected, cl.Values) {
		return fmt.Errorf("claim at path %v has none of the requested values", cl.Path)
	}
	return nil
}

// credentialTypes are the types an SD-JWT VC is of: its vct, and each of
// its aka_vcts (SD-JWT VC draft-19 §2.2.2.2: "Holders and Verifiers can
// treat the SD-JWT VC as a credential of any of these types"), which is
// how a credential of a derived type answers a request for the general
// type it lists (OpenID4VP 1.0 §B.3.5). Matching a type isn't trusting
// the issuer for it: an Issuer's aka_vcts is no evidence it's authorized
// to issue that type (draft-19 §7.7).
func credentialTypes(claims map[string]any) []string {
	var types []string
	if vct, ok := claims["vct"].(string); ok && vct != "" {
		types = append(types, vct)
	}
	if aka, ok := claims["aka_vcts"].([]any); ok {
		for _, t := range aka {
			if s, ok := t.(string); ok && s != "" {
				types = append(types, s)
			}
		}
	}
	return types
}
