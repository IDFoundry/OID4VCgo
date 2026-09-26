package verifier

import "fmt"

// AssuranceLevel gates how strict this package's own validation is —
// the same mechanism issuer.AssuranceLevel and FAPIgo's own
// server.AssuranceLevel/client.AssuranceLevel use, mirrored here so a
// deployment has the same lever on the verifier side it already has on
// the issuer side.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development only — a loopback http:// ResponseURI, and issuer-key
	// resolvers that declare nothing about their own safety properties.
	AssuranceDevelopment

	// AssuranceProduction rejects:
	//
	//   - in New, a Config.ResponseURI with an http scheme — which, per
	//     fapi.ParseEndpointURL, can only happen if fapi.AllowLoopbackHTTP
	//     was passed when parsing it, an option that exists for local
	//     development only (the same check FAPIgo's own
	//     server.AssuranceProduction runs against its own endpoint URLs);
	//   - in VerifyResponse, a VerifyResponseRequest.IssuerKeys or
	//     MdocIssuerKeys that doesn't implement KeySourceAssurance and
	//     declare LiveFetchHardened — the same check FAPIgo's own
	//     client.AssuranceProduction runs against its own IssuerKeys, and
	//     issuer.AssuranceProduction against AttestationVerifier/
	//     ProofBindingKeys. Checked per call rather than in New because
	//     these resolvers are supplied per call.
	//
	// Declaring capabilities is not optional under this level: a
	// resolver that doesn't implement KeySourceAssurance at all is
	// rejected rather than assumed adequate. This does not verify any
	// declaration.
	AssuranceProduction
)

// KeySourceCapabilities is what an SDJWTVCIssuerKeyResolver or
// MdocIssuerKeyResolver implementation self-declares about its own
// safety properties — the same shape and rationale as
// issuer.KeySourceCapabilities and FAPIgo's own
// keys.KeySourceCapabilities.
type KeySourceCapabilities struct {
	// LiveFetchHardened is true iff every live network fetch this
	// resolver performs (DID resolution, VCT metadata lookup, an
	// OCSP/CRL check, ...) goes through fapihttp's own
	// SSRF/size-limit/redirect protections, or the implementation
	// performs no live fetch at all — X5CIssuerKeyResolver and
	// X5ChainIssuerKeyResolver both declare this unconditionally true,
	// since validating an already-presented certificate chain against
	// an in-memory CertPool never touches the network.
	LiveFetchHardened bool
}

// KeySourceAssurance is the optional interface an
// SDJWTVCIssuerKeyResolver or MdocIssuerKeyResolver implementation can
// declare its own KeySourceCapabilities through. There is no default:
// an implementation that doesn't implement this interface at all is
// rejected under AssuranceProduction.
type KeySourceAssurance interface {
	Capabilities() KeySourceCapabilities
}

// checkKeySourceAssurance requires source to implement
// KeySourceAssurance and declare LiveFetchHardened.
func checkKeySourceAssurance(name string, source any) error {
	asserter, ok := source.(KeySourceAssurance)
	if !ok {
		return fmt.Errorf("%s must implement verifier.KeySourceAssurance under AssuranceProduction", name)
	}
	if !asserter.Capabilities().LiveFetchHardened {
		return fmt.Errorf("%s must declare LiveFetchHardened capability under AssuranceProduction", name)
	}
	return nil
}

// checkProductionKeySources runs checkKeySourceAssurance against
// whichever of req's issuer-key resolvers is configured — called only
// once v's own Config.Assurance is known to be AssuranceProduction.
func checkProductionKeySources(req VerifyResponseRequest) error {
	if req.IssuerKeys != nil {
		if err := checkKeySourceAssurance("issuer_keys", req.IssuerKeys); err != nil {
			return err
		}
	}
	if req.MdocIssuerKeys != nil {
		if err := checkKeySourceAssurance("mdoc_issuer_keys", req.MdocIssuerKeys); err != nil {
			return err
		}
	}
	return nil
}
