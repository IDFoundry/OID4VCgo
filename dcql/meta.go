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
