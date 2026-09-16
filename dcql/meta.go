package dcql

import (
	"encoding/json"
	"fmt"
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
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("dcql: marshal sd-jwt vc meta: %w", err)
	}
	return raw, nil
}

// NewMdocMeta marshals meta for use as a CredentialQuery's own Meta
// field.
func NewMdocMeta(meta MdocMeta) (json.RawMessage, error) {
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("dcql: marshal mdoc meta: %w", err)
	}
	return raw, nil
}

// SDJWTVCMeta decodes c's own Meta as the "dc+sd-jwt" format's
// meta shape (Appendix B.3.5).
func (c CredentialQuery) SDJWTVCMeta() (SDJWTVCMeta, error) {
	var m SDJWTVCMeta
	if err := json.Unmarshal(c.Meta, &m); err != nil {
		return SDJWTVCMeta{}, fmt.Errorf("dcql: credential query %q: sd-jwt vc meta: %w", c.ID, err)
	}
	return m, nil
}

// MdocMeta decodes c's own Meta as the "mso_mdoc" format's meta shape
// (Appendix B.2.3).
func (c CredentialQuery) MdocMeta() (MdocMeta, error) {
	var m MdocMeta
	if err := json.Unmarshal(c.Meta, &m); err != nil {
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
// This is the one piece of matching logic a Verifier (checking a
// returned Presentation actually carries what was asked for) and a
// Wallet (deciding which held credential can satisfy a Credential
// Query at all) need identically — c.Claims/c.Meta express the same
// constraint regardless of which side is asking, so this package
// holds the check once rather than each role package reimplementing
// it.
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
	if len(meta.VCTValues) > 0 {
		vct, _ := claims["vct"].(string)
		found := false
		for _, want := range meta.VCTValues {
			if vct == want {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("credential's own vct %q is not among the requested vct_values %v", vct, meta.VCTValues)
		}
	}
	return c.selectedClaimPaths(func(p Path) error {
		_, err := p.Select(claims)
		return err
	})
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
	return c.selectedClaimPaths(func(p Path) error {
		namespace, element, ok := p.MdocNamespaceAndElement()
		if !ok {
			return fmt.Errorf("claims path %v is not a valid mdoc-format path (exactly two string components)", p)
		}
		elements, ok := nameSpaces[namespace]
		if !ok {
			return fmt.Errorf("namespace %q is not present", namespace)
		}
		if _, ok := elements[element]; !ok {
			return fmt.Errorf("namespace %q element %q is not present", namespace, element)
		}
		return nil
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
func (c CredentialQuery) selectedClaimPaths(present func(Path) error) ([]Path, error) {
	if len(c.ClaimSets) == 0 {
		paths := make([]Path, 0, len(c.Claims))
		for _, cl := range c.Claims {
			if err := presentAt(cl.Path, present); err != nil {
				return nil, err
			}
			paths = append(paths, cl.Path)
		}
		return paths, nil
	}

	byID := make(map[string]Path, len(c.Claims))
	for _, cl := range c.Claims {
		byID[cl.ID] = cl.Path
	}
	var lastErr error
	for _, option := range c.ClaimSets {
		paths, err := claimSetOptionPaths(option, byID, present)
		if err != nil {
			lastErr = err
			continue
		}
		return paths, nil
	}
	return nil, fmt.Errorf("no claim_sets option is satisfied: %w", lastErr)
}

// claimSetOptionPaths checks one claim_sets option (a list of
// claims[].id values) against present, using byID to resolve each id
// to its own Path, returning those Paths on success.
func claimSetOptionPaths(option []string, byID map[string]Path, present func(Path) error) ([]Path, error) {
	paths := make([]Path, 0, len(option))
	for _, id := range option {
		path, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("references unknown claim id %q", id)
		}
		if err := presentAt(path, present); err != nil {
			return nil, fmt.Errorf("claim %q: %w", id, err)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// presentAt wraps a single Path.present check (§6.4.1's own atom of
// "is this claim actually there") with a uniform error, shared by
// both claimsSatisfiedBy branches — the no-claim_sets case and each
// claimSetOptionSatisfiedBy option resolve to exactly the same check.
func presentAt(p Path, present func(Path) error) error {
	if err := present(p); err != nil {
		return fmt.Errorf("claim at path %v is not present: %w", p, err)
	}
	return nil
}
