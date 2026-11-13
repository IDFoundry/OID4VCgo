package verifier

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// WalletMetadataError is a request_uri POST (OpenID4VP 1.0 §5.10)
// refused for its wallet_metadata: the Wallet's metadata (§10) isn't a
// JSON object of the members it defines, or says the Wallet supports
// nothing this request could be made with. Reason is a fixed
// description, never the Wallet's own text.
type WalletMetadataError struct{ Reason string }

func (e *WalletMetadataError) Error() string {
	return "verifier: wallet_metadata refused: " + e.Reason
}

// clientIDPrefixX509Hash is the Client Identifier Prefix of every
// request this package signs (ClientIDForCertificate).
const clientIDPrefixX509Hash = "x509_hash"

// walletMetadata is the part of a Wallet's metadata (OpenID4VP 1.0 §10)
// that narrows what a request may be made with. Other members are
// ignored (§10.1: "The Verifier MUST ignore any unrecognized
// parameters"), and so is jwks, a key to encrypt the Request Object to,
// which §5.10.1 leaves the Verifier free not to do ("a signed,
// optionally encrypted, request object").
type walletMetadata struct {
	VPFormatsSupported                     map[string]map[string]json.RawMessage `json:"vp_formats_supported"`
	ClientIDPrefixesSupported              *[]string                             `json:"client_id_prefixes_supported"`
	RequestObjectSigningAlgValuesSupported *[]string                             `json:"request_object_signing_alg_values_supported"`
	AuthorizationEncryptionAlgValues       *[]string                             `json:"authorization_encryption_alg_values_supported"`
	AuthorizationEncryptionEncValues       *[]string                             `json:"authorization_encryption_enc_values_supported"`
}

// walletFit is a request's client_metadata narrowed to a Wallet's
// metadata: the encrypted_response_enc_values_supported and
// vp_formats_supported both it and the Verifier support.
type walletFit struct {
	encValues []jwe.Enc
	vpFormats map[string]any
}

// fitWalletMetadata checks raw, a request_uri POST's wallet_metadata
// (OpenID4VP 1.0 §5.10), against a request for query, and returns the
// client_metadata narrowed to it. It's refused (*WalletMetadataError)
// when it isn't a JSON object of the members §10 defines, or when the
// Wallet names, among what it supports:
//
//   - client_id_prefixes_supported (§10.1) without x509_hash, the
//     prefix of this Verifier's client_id. Absent, it isn't read as
//     "pre-registered" alone, §10.1's default: §5.10's own example
//     posts wallet_metadata without it and is answered with an
//     x509_san_dns request;
//   - request_object_signing_alg_values_supported (§5.10) without
//     Config.SigningAlg;
//   - authorization_encryption_alg_values_supported (§5.10) without
//     ECDH-ES, or authorization_encryption_enc_values_supported with
//     none of Config.EncValuesSupported;
//   - vp_formats_supported (§10.1) leaving the query no way to be
//     answered: a format the Wallet doesn't list, or whose
//     algorithms have none in common with the Verifier's, can't
//     answer a credential query — every credential query must be
//     answerable without credential_sets, one option of every required
//     set with them (§6.4.2).
//
// The client_metadata then lists only the formats and algorithms both
// support. An absent member narrows nothing.
func (v *Verifier) fitWalletMetadata(raw []byte, query dcql.Query) (*walletFit, error) {
	var m walletMetadata
	if err := strictjson.Unmarshal(raw, &m); err != nil || !bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), []byte("{")) {
		return nil, &WalletMetadataError{Reason: "wallet_metadata isn't a JSON object of the members OpenID4VP 1.0 §10 defines"}
	}
	if m.ClientIDPrefixesSupported != nil && !slices.Contains(*m.ClientIDPrefixesSupported, clientIDPrefixX509Hash) {
		return nil, &WalletMetadataError{Reason: "client_id_prefixes_supported doesn't include x509_hash, this Verifier's Client Identifier Prefix"}
	}
	if m.RequestObjectSigningAlgValuesSupported != nil && !slices.Contains(*m.RequestObjectSigningAlgValuesSupported, string(v.cfg.SigningAlg)) {
		return nil, &WalletMetadataError{Reason: "request_object_signing_alg_values_supported doesn't include the algorithm this Verifier signs with"}
	}
	if m.AuthorizationEncryptionAlgValues != nil && !slices.Contains(*m.AuthorizationEncryptionAlgValues, string(jwe.ECDHES)) {
		return nil, &WalletMetadataError{Reason: "authorization_encryption_alg_values_supported doesn't include ECDH-ES"}
	}
	fit := &walletFit{encValues: v.cfg.EncValuesSupported}
	if m.AuthorizationEncryptionEncValues != nil {
		fit.encValues = nil
		for _, enc := range v.cfg.EncValuesSupported {
			if slices.Contains(*m.AuthorizationEncryptionEncValues, string(enc)) {
				fit.encValues = append(fit.encValues, enc)
			}
		}
		if len(fit.encValues) == 0 {
			return nil, &WalletMetadataError{Reason: "authorization_encryption_enc_values_supported has none of the content encryption algorithms this Verifier decrypts"}
		}
	}
	vpFormats, err := v.fitVPFormats(m.VPFormatsSupported)
	if err != nil {
		return nil, err
	}
	fit.vpFormats = vpFormats
	if !answerable(query, vpFormats) {
		return nil, &WalletMetadataError{Reason: "vp_formats_supported leaves the request's credential queries no way to be answered"}
	}
	return fit, nil
}

// fitVPFormats is Config.VPFormatsSupported narrowed to wallet, a
// Wallet's vp_formats_supported: the formats both list, each member
// that is an array in both (a format's algorithms, such as dc+sd-jwt's
// sd-jwt_alg_values, or mso_mdoc's issuerauth_alg_values; OpenID4VP 1.0
// Appendix B) holding only the values both list. A format left with an
// empty array supports nothing, so it's dropped. A nil wallet narrows
// nothing.
func (v *Verifier) fitVPFormats(wallet map[string]map[string]json.RawMessage) (map[string]any, error) {
	if wallet == nil {
		return v.cfg.VPFormatsSupported, nil
	}
	fitted := map[string]any{}
	for format, ours := range v.cfg.VPFormatsSupported {
		theirs, ok := wallet[format]
		if !ok {
			continue
		}
		entry, keep, err := fitFormat(ours, theirs)
		if err != nil {
			return nil, err
		}
		if keep {
			fitted[format] = entry
		}
	}
	return fitted, nil
}

// fitFormat is ours, one format's vp_formats_supported entry, narrowed
// to theirs, the Wallet's, and whether the format is left supported.
func fitFormat(ours any, theirs map[string]json.RawMessage) (any, bool, error) {
	encoded, err := json.Marshal(ours)
	if err != nil {
		return nil, false, err
	}
	var members map[string]json.RawMessage
	if strictjson.Unmarshal(encoded, &members) != nil || members == nil {
		// Not an object: nothing in it to narrow.
		return ours, true, nil
	}
	fitted := make(map[string]json.RawMessage, len(members))
	for name, value := range members {
		fitted[name] = value
		var ourValues []json.RawMessage
		theirValue, ok := theirs[name]
		if !ok || strictjson.Unmarshal(value, &ourValues) != nil || ourValues == nil {
			continue
		}
		var theirValues []json.RawMessage
		if strictjson.Unmarshal(theirValue, &theirValues) != nil || theirValues == nil {
			return nil, false, &WalletMetadataError{Reason: "vp_formats_supported has a format parameter that isn't an array where this Verifier's is"}
		}
		common := intersectJSON(ourValues, theirValues)
		if len(common) == 0 {
			return nil, false, nil
		}
		if fitted[name], err = json.Marshal(common); err != nil {
			return nil, false, err
		}
	}
	return fitted, true, nil
}

// intersectJSON is the values of ours that theirs also has, compared
// as compact JSON (so "ES256" matches "ES256", and -7 matches -7).
func intersectJSON(ours, theirs []json.RawMessage) []json.RawMessage {
	have := make(map[string]bool, len(theirs))
	for _, t := range theirs {
		have[compactJSON(t)] = true
	}
	var common []json.RawMessage
	for _, o := range ours {
		if have[compactJSON(o)] {
			common = append(common, o)
		}
	}
	return common
}

func compactJSON(raw json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return string(raw)
	}
	return b.String()
}

// answerable reports whether query can be answered with the formats
// of vpFormats: every credential query without credential_sets, one
// option of each required set with them (OpenID4VP 1.0 §6.4.2).
func answerable(query dcql.Query, vpFormats map[string]any) bool {
	ok := map[string]bool{}
	for _, cq := range query.Credentials {
		_, ok[cq.ID] = vpFormats[cq.Format]
	}
	if len(query.CredentialSets) == 0 {
		for _, cq := range query.Credentials {
			if !ok[cq.ID] {
				return false
			}
		}
		return true
	}
	for _, cs := range query.CredentialSets {
		if !cs.IsRequired() {
			continue
		}
		if !anyOption(cs.Options, ok) {
			return false
		}
	}
	return true
}

// anyOption reports whether one of options has every ID in ok.
func anyOption(options [][]string, ok map[string]bool) bool {
	for _, option := range options {
		all := true
		for _, id := range option {
			all = all && ok[id]
		}
		if all {
			return true
		}
	}
	return false
}
