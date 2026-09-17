// Package conformanceconfig holds JSON-shape types shared between a
// conformance/*/scripts/*/config.go generator and the
// cmd/conformance-*/config.go binary that parses what it writes — both
// package main, so neither can import the other, the same constraint
// internal/conformancecert already exists to work around for key
// material. A type living here can be marshaled by the generator and
// unmarshaled by the binary from one definition, rather than two
// independently hand-copied mirrors that could drift out of sync.
package conformanceconfig

// MdocConfig is the mso_mdoc-format analog of a Credential Issuer's own
// VCT/Claims/Scope/CredentialConfigurationID fields (OID4VCI Appendix
// A.2.2) — cmd/conformance-issuer's own Config.Mdoc field, and
// run-fapi2sp-battery's own generated server config's "mdoc" object.
type MdocConfig struct {
	CredentialConfigurationID string `json:"credential_configuration_id"`

	// DocType is credential/mdoc.Claims.DocType — Appendix A.2.2's own
	// format-specific metadata parameter.
	DocType string `json:"doctype"`

	// Namespace is the one ISO 18013-5 namespace the fixed claim
	// content (Claims below) is issued under — real mdoc credentials
	// can span several namespaces, but a conformance issuer's own
	// static test data (no real user database) never needs more than
	// one.
	Namespace string `json:"namespace"`

	Claims map[string]string `json:"claims"`
	Scope  string            `json:"scope"`
}
