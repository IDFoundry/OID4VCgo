package verifier

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

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
	//     these resolvers are supplied per call;
	//   - there too, an X5CIssuerKeyResolver or X5ChainIssuerKeyResolver
	//     whose Roots (or a RootsByDocType entry) is the system root pool
	//     (x509.SystemCertPool), which would accept any public CA's
	//     certificate as an issuer's. On Linux and the other Unix
	//     systems a pool built from it by adding certificates is refused
	//     too; on macOS and Windows, where the system pool defers to the
	//     platform verifier, only an unmodified copy is detected, so
	//     build issuer roots from the issuers' own CAs, not from it.
	//
	// Declaring capabilities is not optional under this level: a
	// resolver that doesn't implement KeySourceAssurance at all is
	// rejected rather than assumed adequate. This does not verify any
	// declaration.
	//
	// Revocation is decided outside Accept, which this package can't
	// see into: TransactionsConfig, VerifyResponseRequest and
	// mdocdcapi.VerifyParams each require a Status (a StatusPolicy) or
	// an explicit NoStatusCheck, and a proximity reader under
	// proximity.WithAssurance(AssuranceProduction) requires
	// proximity.WithStatus or proximity.WithNoStatusCheck
	// (CheckStatusDecision, for all of them). A StatusPolicy is refused
	// unless its Checker's Fetcher is HardenedForProduction and its
	// Options.Revocation is set. A status check run inside an Accept
	// instead — RequireValidStatus beside NoStatusCheck — isn't
	// checked: its statuslist.Checker is the caller's to harden.
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
		// Without the chain, ISO/IEC 18013-5's document signer checks
		// (the IACA's country, the DS validity) don't run, and status
		// binding can't tell the DS's CA.
		if _, ok := mdocChainResolver(req.MdocIssuerKeys); !ok {
			return errors.New("mdoc_issuer_keys must verify issuer chains (verifier.MdocIssuerChainResolver, or Unwrap to one) under AssuranceProduction")
		}
	}
	if anchoredBySystemPool(req.IssuerKeys) {
		return errors.New("issuer_keys: Roots is the system root pool under AssuranceProduction: it anchors every public CA's certificates, a TLS server's among them; trust the credential issuers' own CAs")
	}
	for resolver, i := MdocIssuerKeyResolver(req.MdocIssuerKeys), 0; resolver != nil && i < 16; i++ {
		if anchoredBySystemPool(resolver) {
			return errors.New("mdoc_issuer_keys: Roots or RootsByDocType holds the system root pool under AssuranceProduction: it anchors every public CA's certificates; trust the IACAs")
		}
		wrapper, ok := resolver.(MdocIssuerKeyResolverWrapper)
		if !ok {
			break
		}
		resolver = wrapper.Unwrap()
	}
	return nil
}

// anchoredBySystemPool reports whether resolver is one of this
// package's x5c resolvers with a system root pool as a trust anchor
// set (certchain.IsSystemPool).
func anchoredBySystemPool(resolver any) bool {
	var pools []*x509.CertPool
	switch r := resolver.(type) {
	case X5CIssuerKeyResolver:
		pools = []*x509.CertPool{r.Roots}
	case *X5CIssuerKeyResolver:
		if r != nil {
			pools = []*x509.CertPool{r.Roots}
		}
	case X5ChainIssuerKeyResolver:
		pools = r.anchorPools()
	case *X5ChainIssuerKeyResolver:
		if r != nil {
			pools = r.anchorPools()
		}
	}
	return slices.ContainsFunc(pools, certchain.IsSystemPool)
}
