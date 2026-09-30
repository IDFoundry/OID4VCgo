package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	fapires "github.com/idfoundry/fapigo/resource"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
)

// issuedCredentialLifetime bounds an issued credential's own "exp"
// claim — HAIP/SD-JWT VC §11.2.3's own RECOMMENDED (not required) way
// to limit a credential's validity, confirmed live as something the
// OIDF conformance suite's own log flags as a WARNING when absent. See
// sdjwtvc.RoundedExp's own doc comment for why the actual exp value is
// day-rounded, not this value added to the raw issuance instant.
const issuedCredentialLifetime = 365 * 24 * time.Hour

// nonceHandler serves the OID4VCI Nonce Endpoint (§7) — not a
// protected resource (issuer.RequestNonce's own doc comment), so no
// resource.Verifier check here.
func nonceHandler(iss *issuer.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := iss.RequestNonce(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result.WriteJSON(w)
	}
}

// mdocClaimsForRequest builds this request's own *mdoc.Claims from
// nameSpaces (cfg.Mdoc.Claims, precomputed once by credentialHandler —
// nil when cfg.Mdoc is unset, in which case this returns nil too) and
// docType, with a Signed/ValidFrom/ValidUntil validity window spanning
// lifetime from the start of today's own UTC day, not the raw issuance
// instant — the same RFC 9901 §10.1 anti-linkability reasoning
// sdjwtvc.RoundedExp's own doc comment explains for SD-JWT VC's "exp",
// applying equally here (confirmed live: the OIDF suite's own
// VCIEnsureCredentialTimeClaimsNotLinkable check flags mdoc's MSO
// validityInfo signed/validFrom/validUntil the same way it flags
// SD-JWT VC's iat/exp/nbf). Day-granularity rounding means every
// credential issued on the same calendar day carries identical
// Signed/ValidFrom values, closing that channel.
func mdocClaimsForRequest(docType string, nameSpaces map[string]map[string]interface{}, lifetime time.Duration) *mdoc.Claims {
	if nameSpaces == nil {
		return nil
	}
	dayStart := time.Now().UTC().Truncate(24 * time.Hour)
	return &mdoc.Claims{
		DocType: docType, NameSpaces: nameSpaces,
		Signed: dayStart, ValidFrom: dayStart, ValidUntil: dayStart.Add(lifetime),
	}
}

// credentialHandler serves the Credential Endpoint (§8) with
// issuer.CredentialHandler, checking access tokens with
// resourceVerifier through issuer/fapiresource. What it issues is fixed
// by cfg — issuer.Issuer has no user database of its own
// (CredentialRequest.SDJWTClaims' own doc comment), so this binary's
// own static test data stands in for one. No credential_identifier-based
// requests yet — see README's own "Status".
func credentialHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, credentialURL *url.URL, cfg Config) (http.Handler, error) {
	content, err := credentialContentFor(cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := fapiresource.New(resourceVerifier)
	if err != nil {
		return nil, err
	}
	return iss.CredentialHandler(issuer.CredentialHandlerConfig{
		URL: credentialURL, Tokens: tokens,
		Prepare: func(_ context.Context, _ issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			if cfg.Deferred {
				req.Defer = &issuer.Deferral{}
				return nil, nil
			}
			req.SDJWTClaims, req.MdocClaims = content()
			return nil, nil
		},
	})
}

// credentialContentFor returns what this binary issues, fixed by cfg:
// both SDJWTClaims and MdocClaims (the latter nil when cfg.Mdoc is
// unset) — the issuer uses whichever the requested configuration's
// format needs.
func credentialContentFor(cfg Config) (func() (*sdjwtvc.Claims, *mdoc.Claims), error) {
	additional := sdjwtAdditionalClaims(cfg.Claims)
	mdocNameSpaceElements, mdocDocType, err := mdocNameSpaceElementsFor(cfg.Mdoc)
	if err != nil {
		return nil, fmt.Errorf("mdoc claims: %w", err)
	}
	return func() (*sdjwtvc.Claims, *mdoc.Claims) {
		exp := sdjwtvc.RoundedExp(time.Now(), issuedCredentialLifetime)
		return &sdjwtvc.Claims{VCT: cfg.VCT, Exp: &exp, Additional: additional},
			mdocClaimsForRequest(mdocDocType, mdocNameSpaceElements, issuedCredentialLifetime)
	}, nil
}

// deferredPath is the Deferred Credential Endpoint's path
// under the Credential Issuer's identifier.
const deferredPath = "/deferred_credential"

// deferredCredentialHandler serves the Deferred Credential Endpoint
// (§9) with issuer.DeferredCredentialHandler, issuing a pending
// transaction on the Wallet's first poll: this binary has no business
// process to wait for, and the OIDF suite polls only once.
func deferredCredentialHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, cfg Config) (http.Handler, error) {
	endpoint, err := url.Parse(cfg.Issuer + deferredPath)
	if err != nil {
		return nil, fmt.Errorf("deferred credential endpoint URL: %w", err)
	}
	content, err := credentialContentFor(cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := fapiresource.New(resourceVerifier)
	if err != nil {
		return nil, err
	}
	return iss.DeferredCredentialHandler(issuer.DeferredCredentialHandlerConfig{
		ProtectedEndpointConfig: issuer.ProtectedEndpointConfig{URL: endpoint, Tokens: tokens},
		Resolve: func(ctx context.Context, _ issuer.Grant, transactionID string, _ issuer.DeferredTransactionRecord) error {
			sdjwtClaims, mdocClaims := content()
			return iss.IssueDeferredCredential(ctx, transactionID, issuer.DeferredIssuance{SDJWTClaims: sdjwtClaims, MdocClaims: mdocClaims})
		},
	})
}

// notificationPath is the Notification Endpoint's path under the
// Credential Issuer's identifier.
const notificationPath = "/notification"

// notificationHandler serves the Notification Endpoint (§11) with
// issuer.NotificationEndpointHandler, checking access tokens with
// resourceVerifier the same way credentialHandler does.
func notificationHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, cfg Config) (http.Handler, error) {
	endpoint, err := url.Parse(cfg.Issuer + notificationPath)
	if err != nil {
		return nil, fmt.Errorf("notification endpoint URL: %w", err)
	}
	tokens, err := fapiresource.New(resourceVerifier)
	if err != nil {
		return nil, err
	}
	return iss.NotificationEndpointHandler(issuer.ProtectedEndpointConfig{URL: endpoint, Tokens: tokens})
}

// sdjwtAdditionalClaims builds credentialHandler's own precomputed
// SD-JWT "Additional" claim map (every entry selectively disclosable)
// from claims — extracted out of credentialHandler itself purely to
// keep that function's own cognitive complexity low.
func sdjwtAdditionalClaims(claims map[string]string) map[string]any {
	additional := make(map[string]any, len(claims))
	for name, value := range claims {
		additional[name] = sdjwtvc.SD(value)
	}
	return additional
}

// mdocNameSpaceElementsFor builds credentialHandler's own precomputed
// mso_mdoc namespace/data-element map from cfg (nil when cfg is unset,
// in which case serveCredentialRequest's own mdocClaimsForRequest call
// always returns a nil *mdoc.Claims too) — extracted out of
// credentialHandler itself purely to keep that function's own
// cognitive complexity low. The actual Table 20 full-date/portrait
// transform lives in conformanceconfig.BuildMdocNameSpaceElements,
// shared with cmd/conformance-wallet-vp's own identical need to build
// a real mdoc fixture credential.
func mdocNameSpaceElementsFor(cfg *conformanceconfig.MdocConfig) (nameSpaces map[string]map[string]interface{}, docType string, err error) {
	if cfg == nil {
		return nil, "", nil
	}
	nameSpaces, err = conformanceconfig.BuildMdocNameSpaceElements(cfg.Namespace, cfg.Claims)
	if err != nil {
		return nil, "", err
	}
	return nameSpaces, cfg.DocType, nil
}
