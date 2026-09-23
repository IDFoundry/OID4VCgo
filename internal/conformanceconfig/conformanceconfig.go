// Package conformanceconfig holds JSON-shape types shared between a
// conformance/*/scripts/*/config.go generator and the
// cmd/conformance-*/config.go binary that parses what it writes — both
// package main, so neither can import the other, the same constraint
// internal/conformancecert already exists to work around for key
// material. A type living here can be marshaled by the generator and
// unmarshaled by the binary from one definition, rather than two
// independently hand-copied mirrors that could drift out of sync.
package conformanceconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// KeyAttestationConfig, when set, additionally advertises the
// "attestation" proof type (OID4VCI Appendix F.3) alongside "jwt" on
// cmd/conformance-issuer's own "dc+sd-jwt" CredentialConfiguration —
// not a separate CredentialConfiguration, since
// issuer.RequestCredential dispatches by which proof type key an
// actual Credential Request's own "proofs" object contains, not a
// static single-choice config; advertising both leaves every existing
// "jwt"-proof flow completely unaffected.
type KeyAttestationConfig struct {
	// TrustedJWK is the one Key Attestation signer this issuer trusts —
	// a JSON-encoded public JWK (RFC 7517). Conformance-fixture-only: a
	// real deployment would resolve trust per Appendix D.1's own
	// kid/x5c/trust_chain header mechanisms instead of one fixed key
	// (see issuer.AttestationVerifier's own doc comment: "entirely this
	// issuer's own trust policy").
	TrustedJWK json.RawMessage `json:"trusted_jwk"`
}

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

	// Claims holds each data element's own value, JSON-typed (string,
	// number, bool, array, object — whatever encoding/json produces
	// unmarshaling into `any`). Most ISO/IEC 18013-5 Table 20 elements
	// are plain tstr and need no special handling; a handful need
	// namespace-specific reinterpretation only the consumer (this
	// config's own reader) knows how to do, keyed by identifier name —
	// see cmd/conformance-issuer/credential.go's own
	// mdocNameSpaceElementsFor: birth_date/issue_date/expiry_date need
	// wrapping in a cbor.Tag (full-date, tag 1004) instead of staying a
	// bare tstr, and portrait needs base64-decoding into raw bytes
	// (JSON has no native byte-string type, so it's written here as a
	// base64 string — encoding/json already does this automatically
	// for a []byte value on the writing side; only the read-back
	// direction needs an explicit decode, since unmarshaling into `any`
	// never infers "this string is really bytes" on its own).
	Claims map[string]any `json:"claims"`
	Scope  string         `json:"scope"`

	// SignerKeyPEM/CertificatePEM/TrustAnchorCertificatePEM, when all
	// three are set, are a dedicated mdoc Document Signer identity —
	// separate from the top-level Config's own
	// CredentialIssuerSigningKeyPEM/CredentialIssuerCertificatePEM the
	// "dc+sd-jwt" CredentialConfiguration uses. ISO/IEC 18013-5 Annex
	// B's own certificate profile (a ≤457-day leaf validity, an
	// mdlDS-only extended key usage, a digitalSignature-only key
	// usage — see internal/conformancecert.GenerateMdocDocumentSigner)
	// is specific to mdoc document signing and would be actively wrong
	// to impose on a general-purpose, multi-format issuer identity, so
	// mdoc gets its own. Optional: when empty, cmd/conformance-issuer
	// falls back to reusing the top-level issuer identity, matching
	// this config's own original (pre-Annex-B-compliance) behavior —
	// existing tests that never set these three fields keep working
	// unchanged.
	SignerKeyPEM              string `json:"signer_key_pem,omitempty"`
	CertificatePEM            string `json:"certificate_pem,omitempty"`
	TrustAnchorCertificatePEM string `json:"trust_anchor_certificate_pem,omitempty"`
}

// mdocFullDateTag is credential/mdoc's own documented convention for a
// full-date element (that package's own doc comment: "cbor.Tag for one
// of mdoc's date tags (0 for tdate, 1004 for full-date)") — this
// package has no opinion on namespace-specific data models, so the
// ISO/IEC 18013-5 org.iso.18013.5.1 namespace's own encoding choice
// (Table 20: "full-date" for birth_date, "tdate or full-date" for
// issue_date/expiry_date — full-date used for all three here, for one
// consistent encoding) is this package's own call to make, not the
// library's.
const mdocFullDateTag = 1004

// mdocDateElements names the Table 20 org.iso.18013.5.1 data elements
// whose JSON-config value needs wrapping in an mdocFullDateTag before
// use — see MdocConfig.Claims's own doc comment for why the raw JSON
// round-trip alone can't carry this. portrait needs its own
// reinterpretation too (base64 decode into raw bytes), handled inline
// in BuildMdocNameSpaceElements by name rather than via a second map —
// every other element is a plain tstr, needing no transform.
var mdocDateElements = map[string]bool{"birth_date": true, "issue_date": true, "expiry_date": true}

// BuildMdocNameSpaceElements transforms claims (JSON-typed values, as
// MdocConfig.Claims's own doc comment describes) into
// credential/mdoc.Claims.NameSpaces' own
// map[string]map[string]interface{} shape under namespace, applying
// ISO/IEC 18013-5 Table 20's own full-date and portrait
// reinterpretations — shared by every conformance binary that issues a
// real mdoc fixture credential (cmd/conformance-issuer,
// cmd/conformance-wallet-vp) so this transform lives in exactly one
// place rather than as two independently hand-copied mirrors that
// could drift out of sync, the same rationale this package's own doc
// comment already gives for its JSON-shape types.
func BuildMdocNameSpaceElements(namespace string, claims map[string]any) (map[string]map[string]interface{}, error) {
	elements := make(map[string]interface{}, len(claims))
	for name, value := range claims {
		switch {
		case mdocDateElements[name]:
			s, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("mdoc claim %q: want a date string, got %T", name, value)
			}
			elements[name] = cbor.Tag{Number: mdocFullDateTag, Content: s}
		case name == "portrait":
			s, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("mdoc claim %q: want a base64 string, got %T", name, value)
			}
			decoded, decErr := base64.StdEncoding.DecodeString(s)
			if decErr != nil {
				return nil, fmt.Errorf("mdoc claim %q: decode base64: %w", name, decErr)
			}
			elements[name] = decoded
		default:
			elements[name] = value
		}
	}
	return map[string]map[string]interface{}{namespace: elements}, nil
}
